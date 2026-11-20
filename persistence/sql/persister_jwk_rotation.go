// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package sql

import (
	"context"
	"encoding/json"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/gofrs/uuid"
	"github.com/pkg/errors"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/ory/hydra/v2/aead"
	"github.com/ory/hydra/v2/jwk"
	"github.com/ory/hydra/v2/x"
	"github.com/ory/pop/v6"
	"github.com/ory/x/otelx"
	"github.com/ory/x/sqlcon"
)

var _ jwk.RotationManager = (*JWKPersister)(nil)

// storageClock reads the database transaction's clock. Every instance compares
// against this single time source so cleanup decisions never depend on a local
// wall clock beyond the explicit skew tolerance.
func (p *JWKPersister) storageClock(ctx context.Context, c *pop.Connection) (time.Time, error) {
	var raw string
	query := "SELECT CURRENT_TIMESTAMP"
	switch c.Dialect.Name() {
	case "mysql":
		query = "SELECT CURRENT_TIMESTAMP(6)"
	case "cockroach":
		query = "SELECT clock_timestamp()"
	}
	if err := c.RawQuery(query).First(&raw); err != nil {
		return time.Time{}, sqlcon.HandleError(err)
	}
	return parseStorageClock(raw)
}

// parseStorageClock normalizes the timestamp representations the supported
// dialects return. SQLite emits "2006-01-02 15:04:05" in UTC, the network
// databases emit RFC3339Nano with a zone.
func parseStorageClock(raw string) (time.Time, error) {
	layouts := []string{time.RFC3339Nano, "2006-01-02 15:04:05.999999999-07:00", "2006-01-02 15:04:05"}
	var lastErr error
	for _, layout := range layouts {
		if t, err := time.Parse(layout, raw); err == nil {
			return t.UTC(), nil
		} else {
			lastErr = err
		}
	}
	return time.Time{}, errors.Wrapf(lastErr, "could not parse storage clock %q", raw)
}

// checkClockSkew compares the instance clock against the storage clock and
// refuses automatic cleanup when the deviation exceeds the tolerance.
func (p *JWKPersister) checkClockSkew(storageNow time.Time, skew time.Duration) error {
	local := time.Now().UTC()
	delta := local.Sub(storageNow)
	if delta < 0 {
		delta = -delta
	}
	if delta > skew {
		return errors.WithStack(errors.Wrapf(jwk.ErrClockSkew, "observed skew %s exceeds tolerance %s", delta, skew))
	}
	return nil
}

func (p *JWKPersister) loadRotationRows(ctx context.Context, c *pop.Connection, set string) (jwk.RotationSQLDataRows, error) {
	var rows jwk.RotationSQLDataRows
	q := c.WithContext(ctx).Where("nid = ?", p.D.BasePersister().NetworkID(ctx)).Where("sid = ?", set)
	if err := q.Order("generation ASC, kid ASC").All(&rows); err != nil {
		return nil, sqlcon.HandleError(err)
	}
	return rows, nil
}

func (p *JWKPersister) replaceRotationRows(ctx context.Context, c *pop.Connection, nid uuid.UUID, set string, planned []jwk.KeyLifecycle, now time.Time) error {
	if err := c.RawQuery("DELETE FROM hydra_jwk_rotation WHERE nid = ? AND sid = ?", nid, set).Exec(); err != nil {
		return sqlcon.HandleError(err)
	}
	for _, l := range planned {
		row := jwk.NewRotationSQLData(nid, l, now)
		if err := c.Create(&row); err != nil {
			return sqlcon.HandleError(err)
		}
	}
	return nil
}

// getKeySetInTx reads a key set on the caller's transaction connection.
func (p *JWKPersister) getKeySetInTx(ctx context.Context, c *pop.Connection, set string) (*jose.JSONWebKeySet, error) {
	var js jwk.SQLDataRows
	if err := c.WithContext(ctx).
		Where("nid = ?", p.D.BasePersister().NetworkID(ctx)).
		Where("sid = ?", set).
		Order("created_at DESC").
		All(&js); err != nil {
		return nil, sqlcon.HandleError(err)
	}
	return js.ToJWK(ctx, aead.NewAESGCM(p.D.Config()))
}

// addKeyInTx writes one JWK inside the caller's transaction.
func (p *JWKPersister) addKeyInTx(ctx context.Context, c *pop.Connection, set string, key *jose.JSONWebKey) error {
	out, err := json.Marshal(key)
	if err != nil {
		return errors.WithStack(err)
	}
	encrypted, err := aead.NewAESGCM(p.D.Config()).Encrypt(ctx, out, nil)
	if err != nil {
		return errors.WithStack(err)
	}
	return sqlcon.HandleError(c.WithContext(ctx).Create(&jwk.SQLData{
		NID:     p.D.BasePersister().NetworkID(ctx),
		Set:     set,
		KID:     key.KeyID,
		Version: 0,
		Key:     encrypted,
	}))
}

// addKeySetInTx writes a whole key set inside the caller's transaction.
func (p *JWKPersister) addKeySetInTx(ctx context.Context, c *pop.Connection, set string, keys *jose.JSONWebKeySet) error {
	for i := range keys.Keys {
		if err := p.addKeyInTx(ctx, c, set, &keys.Keys[i]); err != nil {
			return err
		}
	}
	return nil
}

// deleteKeyInTx removes a key's material inside the caller's transaction. A
// missing row is not an error so repeated cleanup stays idempotent.
func (p *JWKPersister) deleteKeyInTx(ctx context.Context, c *pop.Connection, set, kid string) error {
	err := c.WithContext(ctx).
		Where("nid = ?", p.D.BasePersister().NetworkID(ctx)).
		Where("sid = ? AND kid = ?", set, kid).
		Delete(&jwk.SQLData{})
	return sqlcon.HandleError(err)
}

// ensureInTx creates the first active generation when none exists. It runs on
// the transaction handed in by the caller and returns the resulting metadata.
func (p *JWKPersister) ensureInTx(ctx context.Context, c *pop.Connection, set, alg, use string, now time.Time) ([]jwk.KeyLifecycle, error) {
	nid := p.D.BasePersister().NetworkID(ctx)

	existing, getErr := p.getKeySetInTx(ctx, c, set)
	switch {
	case getErr == nil:
		// Legacy set: adopt the existing private key as generation 1 rather
		// than minting a replacement, preserving single-instance behavior.
		if priv, findErr := jwk.FindPrivateKey(existing); findErr == nil {
			lifecycle := jwk.KeyLifecycle{
				Set: set, Kid: priv.KeyID, State: jwk.KeyStateActive,
				Generation: 1, ActivatedAt: now, UpdatedAt: now,
			}
			row := jwk.NewRotationSQLData(nid, lifecycle, now)
			if err := c.Create(&row); err != nil {
				return nil, sqlcon.HandleError(err)
			}
			return []jwk.KeyLifecycle{lifecycle}, nil
		}
	case !isNotFound(getErr):
		return nil, getErr
	}

	keys, err := jwk.GenerateJWK(jose.SignatureAlgorithm(alg), "", use)
	if err != nil {
		return nil, errors.Wrapf(jwk.ErrKeyGeneration, "%s", err)
	}
	if err := p.addKeySetInTx(ctx, c, set, keys); err != nil {
		if errors.Is(sqlcon.HandleError(err), sqlcon.ErrUniqueViolation()) {
			return nil, sqlcon.ErrConcurrentUpdate()
		}
		return nil, errors.Wrapf(jwk.ErrKeyGeneration, "%s", err)
	}
	kid := keys.Keys[0].KeyID
	lifecycle := jwk.KeyLifecycle{
		Set: set, Kid: kid, State: jwk.KeyStateActive,
		Generation: 1, ActivatedAt: now, UpdatedAt: now,
	}
	row := jwk.NewRotationSQLData(nid, lifecycle, now)
	if err := c.Create(&row); err != nil {
		return nil, sqlcon.HandleError(err)
	}
	return []jwk.KeyLifecycle{lifecycle}, nil
}

func withSet(deltas []jwk.RotationDelta, set string) []jwk.RotationDelta {
	for i := range deltas {
		deltas[i].Set = set
	}
	return deltas
}

// isNotFound unifies the two not-found shapes in this codebase: sqlcon's
// sql.ErrNoRows wrapper and x.ErrNotFound produced when decoding an empty row
// set into a JWK set.
func isNotFound(err error) bool {
	return errors.Is(err, sqlcon.ErrNoRows()) || errors.Is(err, x.ErrNotFound)
}

func containsString(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}

// adoptLegacyKeys reconciles key material added through the legacy
// GenerateAndPersistKeySet/AddKeySet endpoints (which predate rotation
// metadata) into the lifecycle. The newest private key without metadata is
// promoted to the next active generation and the previously active key is
// retired, preserving the historic rule that the most recently created key
// signs. Keys already carrying metadata are left untouched.
func (p *JWKPersister) adoptLegacyKeys(ctx context.Context, c *pop.Connection, set string, meta []jwk.KeyLifecycle, now time.Time) ([]jwk.KeyLifecycle, []jwk.RotationDelta, error) {
	existing, err := p.getKeySetInTx(ctx, c, set)
	if err != nil {
		if isNotFound(err) {
			return meta, nil, nil
		}
		return nil, nil, err
	}

	known := map[string]struct{}{}
	for _, m := range meta {
		known[m.Kid] = struct{}{}
	}

	var newest *jose.JSONWebKey
	for i := range existing.Keys {
		k := &existing.Keys[i]
		if k.IsPublic() {
			continue
		}
		if _, ok := known[k.KeyID]; ok {
			continue
		}
		if newest == nil {
			newest = k
		}
	}
	if newest == nil {
		return meta, nil, nil
	}

	nid := p.D.BasePersister().NetworkID(ctx)
	generation := jwk.NextGeneration(meta)
	var deltas []jwk.RotationDelta
	for i := range meta {
		if meta[i].State == jwk.KeyStateActive {
			from := meta[i].State
			meta[i].State = jwk.KeyStateRetired
			meta[i].RetiredAt = now
			meta[i].UpdatedAt = now
			deltas = append(deltas, jwk.RotationDelta{
				Set: set, Kid: meta[i].Kid, From: from, To: jwk.KeyStateRetired,
				ChangedAt: now, Generation: generation,
			})
		}
	}
	lifecycle := jwk.KeyLifecycle{
		Set: set, Kid: newest.KeyID, State: jwk.KeyStateActive,
		Generation: generation, ActivatedAt: now, UpdatedAt: now,
	}
	meta = append(meta, lifecycle)
	deltas = append(deltas, jwk.RotationDelta{
		Set: set, Kid: newest.KeyID, From: jwk.KeyStatePending, To: jwk.KeyStateActive,
		ChangedAt: now, Generation: generation,
	})
	if err := p.replaceRotationRows(ctx, c, nid, set, meta, now); err != nil {
		return nil, nil, err
	}
	return meta, deltas, nil
}

// EnsureSigningKey implements jwk.RotationManager.
func (p *JWKPersister) EnsureSigningKey(ctx context.Context, set, alg, use string) (_ *jwk.RotationResult, err error) {
	ctx, span := p.D.Tracer(ctx).Tracer().Start(ctx, "persistence.sql.EnsureSigningKey",
		trace.WithAttributes(attribute.String("set", set)))
	defer otelx.End(span, &err)

	var result *jwk.RotationResult
	err = p.D.BasePersister().Transaction(ctx, func(ctx context.Context, c *pop.Connection) error {
		now, err := p.storageClock(ctx, c)
		if err != nil {
			return err
		}

		rows, err := p.loadRotationRows(ctx, c, set)
		if err != nil {
			return err
		}
		meta := rows.ToLifecycleView()

		// Reconcile key material created through the legacy admin endpoints
		// before deciding which key signs, so an externally added key becomes
		// the active generation exactly as the pre-rotation behavior did.
		var adoptedDeltas []jwk.RotationDelta
		if jwk.FindActive(meta) != nil {
			meta, adoptedDeltas, err = p.adoptLegacyKeys(ctx, c, set, meta, now)
			if err != nil {
				return err
			}
		}

		// Fast path: an active key already exists, every instance reuses it.
		if jwk.FindActive(meta) != nil {
			view := jwk.BuildView(set, meta)
			result = &jwk.RotationResult{Set: set, View: view, Delta: adoptedDeltas}
			return nil
		}

		meta, err = p.ensureInTx(ctx, c, set, alg, use, now)
		if err != nil {
			return err
		}
		view := jwk.BuildView(set, meta)
		result = &jwk.RotationResult{
			Set:  set,
			View: view,
			Delta: []jwk.RotationDelta{{
				Set: set, Kid: view.SigningKID, From: jwk.KeyStatePending, To: jwk.KeyStateActive,
				ChangedAt: now, Generation: 1,
			}},
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// Rotate implements jwk.RotationManager.
func (p *JWKPersister) Rotate(ctx context.Context, set, alg, use string, maxTokenTTL, clockSkew time.Duration) (_ *jwk.RotationResult, err error) {
	ctx, span := p.D.Tracer(ctx).Tracer().Start(ctx, "persistence.sql.Rotate",
		trace.WithAttributes(attribute.String("set", set), attribute.String("alg", alg)))
	defer otelx.End(span, &err)

	var result *jwk.RotationResult
	err = p.D.BasePersister().Transaction(ctx, func(ctx context.Context, c *pop.Connection) error {
		now, err := p.storageClock(ctx, c)
		if err != nil {
			return err
		}
		nid := p.D.BasePersister().NetworkID(ctx)

		rows, err := p.loadRotationRows(ctx, c, set)
		if err != nil {
			return err
		}
		meta := rows.ToLifecycleView()

		// A rotation on a set that has never gone through the lifecycle
		// machinery first ensures an active generation exists, so callers can
		// rotate legacy and fresh sets through one entry point.
		if jwk.FindActive(meta) == nil {
			meta, err = p.ensureInTx(ctx, c, set, alg, use, now)
			if err != nil {
				return err
			}
		}

		// Generate fresh material before mutating anything: generation failure
		// rolls the whole transaction back and the old key keeps signing.
		keys, err := jwk.GenerateJWK(jose.SignatureAlgorithm(alg), "", use)
		if err != nil {
			return errors.Wrapf(jwk.ErrKeyGeneration, "%s", err)
		}
		kid := keys.Keys[0].KeyID

		generation := jwk.NextGeneration(meta)
		planned, deltas, _ := jwk.PlanRotation(meta, kid, now, maxTokenTTL, clockSkew, generation)
		for i := range planned {
			planned[i].Set = set
		}
		deltas = withSet(deltas, set)

		// The post-rotation verification set must contain the retired key(s)
		// plus the new active key; refuse anything that would publish empty.
		if len(jwk.PublicKIDs(planned)) == 0 {
			return errors.WithStack(jwk.ErrEmptyVerificationSet)
		}

		if err := p.addKeySetInTx(ctx, c, set, keys); err != nil {
			if errors.Is(sqlcon.HandleError(err), sqlcon.ErrUniqueViolation()) {
				return sqlcon.ErrConcurrentUpdate()
			}
			return errors.Wrapf(jwk.ErrKeyGeneration, "%s", err)
		}
		if err := p.replaceRotationRows(ctx, c, nid, set, planned, now); err != nil {
			return err
		}

		result = &jwk.RotationResult{Set: set, View: jwk.BuildView(set, planned), Delta: deltas}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// GetLifecycle implements jwk.RotationManager.
func (p *JWKPersister) GetLifecycle(ctx context.Context, set string) (_ *jwk.LifecycleView, err error) {
	ctx, span := p.D.Tracer(ctx).Tracer().Start(ctx, "persistence.sql.GetLifecycle",
		trace.WithAttributes(attribute.String("set", set)))
	defer otelx.End(span, &err)

	var view *jwk.LifecycleView
	err = p.D.BasePersister().Transaction(ctx, func(ctx context.Context, c *pop.Connection) error {
		rows, err := p.loadRotationRows(ctx, c, set)
		if err != nil {
			return err
		}
		if len(rows) == 0 {
			return x.ErrNotFound
		}
		v := jwk.BuildView(set, rows.ToLifecycleView())
		view = &v
		return nil
	})
	if err != nil {
		return nil, err
	}
	return view, nil
}

// Cleanup implements jwk.RotationManager.
func (p *JWKPersister) Cleanup(ctx context.Context, set string, now time.Time, clockSkew time.Duration) (_ []string, err error) {
	ctx, span := p.D.Tracer(ctx).Tracer().Start(ctx, "persistence.sql.Cleanup",
		trace.WithAttributes(attribute.String("set", set)))
	defer otelx.End(span, &err)

	var tombstoned []string
	err = p.D.BasePersister().Transaction(ctx, func(ctx context.Context, c *pop.Connection) error {
		storageNow, err := p.storageClock(ctx, c)
		if err != nil {
			return err
		}
		if err := p.checkClockSkew(storageNow, clockSkew); err != nil {
			return err
		}
		if now.IsZero() {
			now = storageNow
		}

		rows, err := p.loadRotationRows(ctx, c, set)
		if err != nil {
			return err
		}
		meta := rows.ToLifecycleView()
		candidates := jwk.CleanupCandidates(meta, now)
		if len(candidates) == 0 {
			return nil
		}

		nid := p.D.BasePersister().NetworkID(ctx)
		changed := false
		for i := range meta {
			if !containsString(candidates, meta[i].Kid) {
				continue
			}
			// Re-check state inside the transaction: a concurrent rotation can
			// have promoted this kid. Only a still-retired key may be removed.
			if meta[i].State != jwk.KeyStateRetired {
				continue
			}
			meta[i].State = jwk.KeyStateTombstoned
			meta[i].TombstonedAt = storageNow
			meta[i].UpdatedAt = storageNow

			if err := p.deleteKeyInTx(ctx, c, set, meta[i].Kid); err != nil {
				return err
			}
			tombstoned = append(tombstoned, meta[i].Kid)
			changed = true
		}
		if changed {
			return p.replaceRotationRows(ctx, c, nid, set, meta, storageNow)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return tombstoned, nil
}

// ExportLifecycle implements jwk.RotationManager.
func (p *JWKPersister) ExportLifecycle(ctx context.Context, set string) (_ *jwk.LifecycleExport, err error) {
	ctx, span := p.D.Tracer(ctx).Tracer().Start(ctx, "persistence.sql.ExportLifecycle",
		trace.WithAttributes(attribute.String("set", set)))
	defer otelx.End(span, &err)

	var out *jwk.LifecycleExport
	err = p.D.BasePersister().Transaction(ctx, func(ctx context.Context, c *pop.Connection) error {
		rows, err := p.loadRotationRows(ctx, c, set)
		if err != nil {
			return err
		}
		if len(rows) == 0 {
			return x.ErrNotFound
		}
		keySet, err := p.getKeySetInTx(ctx, c, set)
		if err != nil {
			return err
		}
		// Only public material ever leaves the process.
		public := jwk.ExcludePrivateKeys(keySet)
		visible := jwk.PublicKIDs(rows.ToLifecycleView())
		filtered := &jose.JSONWebKeySet{}
		for _, kid := range visible {
			filtered.Keys = append(filtered.Keys, public.Key(kid)...)
		}
		out = &jwk.LifecycleExport{
			Version: 1,
			Set:     set,
			Keys:    filtered.Keys,
			Meta:    rows.ToLifecycleView(),
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ImportLifecycle implements jwk.RotationManager.
func (p *JWKPersister) ImportLifecycle(ctx context.Context, set string, in *jwk.LifecycleExport) (_ *jwk.LifecycleView, err error) {
	ctx, span := p.D.Tracer(ctx).Tracer().Start(ctx, "persistence.sql.ImportLifecycle",
		trace.WithAttributes(attribute.String("set", set)))
	defer otelx.End(span, &err)

	var view *jwk.LifecycleView
	err = p.D.BasePersister().Transaction(ctx, func(ctx context.Context, c *pop.Connection) error {
		now, err := p.storageClock(ctx, c)
		if err != nil {
			return err
		}
		nid := p.D.BasePersister().NetworkID(ctx)

		// Defense in depth: never persist a private key arriving in an export.
		for i := range in.Keys {
			if !in.Keys[i].IsPublic() {
				return errors.New("lifecycle import must contain public keys only")
			}
		}
		if len(in.Keys) == 0 {
			return errors.WithStack(jwk.ErrEmptyVerificationSet)
		}

		existing, getErr := p.getKeySetInTx(ctx, c, set)
		switch {
		case getErr == nil:
			if err := jwk.VerifyNoKeyIDConflict(existing, &jose.JSONWebKeySet{Keys: in.Keys}); err != nil {
				return err
			}
			// Merge in kids that are not already stored; identical kids with
			// identical thumbprints are left untouched (idempotent re-import).
			for i := range in.Keys {
				if len(existing.Key(in.Keys[i].KeyID)) == 0 {
					if err := p.addKeyInTx(ctx, c, set, &in.Keys[i]); err != nil {
						return err
					}
				}
			}
		case isNotFound(getErr):
			if err := p.addKeySetInTx(ctx, c, set, &jose.JSONWebKeySet{Keys: in.Keys}); err != nil {
				return err
			}
		default:
			return getErr
		}

		for i := range in.Meta {
			in.Meta[i].Set = set
		}

		// Replace metadata wholesale inside the same transaction so the import
		// either restores the exact state or changes nothing on rollback.
		if err := c.RawQuery("DELETE FROM hydra_jwk_rotation WHERE nid = ? AND sid = ?", nid, set).Exec(); err != nil {
			return sqlcon.HandleError(err)
		}
		for _, l := range in.Meta {
			row := jwk.NewRotationSQLData(nid, l, now)
			if err := c.Create(&row); err != nil {
				return sqlcon.HandleError(err)
			}
		}

		v := jwk.BuildView(set, in.Meta)
		view = &v
		return nil
	})
	if err != nil {
		return nil, err
	}
	return view, nil
}
