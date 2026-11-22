// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package sql

import (
	"context"
	"database/sql"
	"time"

	"github.com/gofrs/uuid"
	"github.com/pkg/errors"

	"github.com/ory/hydra/v2/oauth2/lockout"
	"github.com/ory/x/dbal"
	"github.com/ory/x/otelx"
	"github.com/ory/x/sqlcon"
)

var _ lockout.Store = (*Persister)(nil)

type lockoutRow struct {
	NID             uuid.UUID  `db:"nid"`
	ClientID        string     `db:"client_id"`
	SourceHash      string     `db:"source_hash"`
	FailureCount    int64      `db:"failure_count"`
	WindowStartedAt time.Time  `db:"window_started_at"`
	LockedUntil     *time.Time `db:"locked_until"`
	LockoutRound    int64      `db:"lockout_round"`
}

func (lockoutRow) TableName() string { return "hydra_client_lockout" }

func (r *lockoutRow) toEntry() *lockout.Entry {
	return &lockout.Entry{
		Key: lockout.Key{
			ClientID: r.ClientID,
			Source:   r.SourceHash,
		},
		FailureCount:    r.FailureCount,
		WindowStartedAt: r.WindowStartedAt,
		LockedUntil:     r.LockedUntil,
		LockoutRound:    r.LockoutRound,
	}
}

// IncrementFailure implements lockout.Store. The increment, the sliding
// window reset and the suppression of counts during an active lock all happen
// inside a single atomic upsert, so concurrent instances can neither lose nor
// double-count failures.
func (p *Persister) IncrementFailure(ctx context.Context, key lockout.Key, window time.Duration, now time.Time) (_ *lockout.Entry, err error) {
	ctx, span := p.r.Tracer(ctx).Tracer().Start(ctx, "persistence.sql.IncrementFailure")
	defer otelx.End(span, &err)

	now = now.UTC()
	cutoff := now.Add(-window)
	nid := p.NetworkID(ctx)
	c := p.Connection(ctx)

	if c.Dialect.Name() == dbal.DriverMySQL {
		// MySQL does not support RETURNING, so we upsert and read back in a
		// second statement. The upsert itself is atomic, which is what the
		// counting guarantees rely on.
		if err := c.RawQuery(`
INSERT INTO hydra_client_lockout
  (nid, client_id, source_hash, failure_count, window_started_at, lockout_round, created_at, updated_at)
VALUES (?, ?, ?, 1, ?, 0, ?, ?)
ON DUPLICATE KEY UPDATE
  failure_count = IF(locked_until IS NOT NULL AND locked_until > ?, failure_count,
                     IF(window_started_at <= ? OR window_started_at > ?, 1, failure_count + 1)),
  window_started_at = IF(locked_until IS NOT NULL AND locked_until > ?, window_started_at,
                         IF(window_started_at <= ? OR window_started_at > ?, ?, window_started_at)),
  updated_at = ?`,
			nid, key.ClientID, key.Source, now, now, now,
			now, cutoff, now, now, cutoff, now, now, now,
		).Exec(); err != nil {
			return nil, sqlcon.HandleError(err)
		}
		entry, err := p.GetEntry(ctx, key)
		if err != nil {
			return nil, err
		}
		if entry == nil {
			return nil, errors.WithStack(sqlcon.ErrNoRows())
		}
		return entry, nil
	}

	var row lockoutRow
	if err := c.RawQuery(`
INSERT INTO hydra_client_lockout
  (nid, client_id, source_hash, failure_count, window_started_at, lockout_round, created_at, updated_at)
VALUES (?, ?, ?, 1, ?, 0, ?, ?)
ON CONFLICT (nid, client_id, source_hash) DO UPDATE SET
  failure_count = CASE
    WHEN hydra_client_lockout.locked_until IS NOT NULL AND hydra_client_lockout.locked_until > ? THEN hydra_client_lockout.failure_count
    WHEN hydra_client_lockout.window_started_at <= ? OR hydra_client_lockout.window_started_at > ? THEN 1
    ELSE hydra_client_lockout.failure_count + 1
  END,
  window_started_at = CASE
    WHEN hydra_client_lockout.locked_until IS NOT NULL AND hydra_client_lockout.locked_until > ? THEN hydra_client_lockout.window_started_at
    WHEN hydra_client_lockout.window_started_at <= ? OR hydra_client_lockout.window_started_at > ? THEN ?
    ELSE hydra_client_lockout.window_started_at
  END,
  updated_at = ?
RETURNING failure_count, window_started_at, locked_until, lockout_round`,
		nid, key.ClientID, key.Source, now, now, now,
		now, cutoff, now, now, cutoff, now, now, now,
	).First(&row); err != nil {
		return nil, sqlcon.HandleError(err)
	}
	row.ClientID = key.ClientID
	row.SourceHash = key.Source
	return row.toEntry(), nil
}

// TriggerLock implements lockout.Store.
func (p *Persister) TriggerLock(ctx context.Context, key lockout.Key, expectedRound int64, lockedUntil, now time.Time) (_ bool, err error) {
	ctx, span := p.r.Tracer(ctx).Tracer().Start(ctx, "persistence.sql.TriggerLock")
	defer otelx.End(span, &err)

	now = now.UTC()
	count, err := p.Connection(ctx).RawQuery(`
UPDATE hydra_client_lockout
SET lockout_round = lockout_round + 1,
    locked_until = ?,
    failure_count = 0,
    window_started_at = ?,
    updated_at = ?
WHERE nid = ? AND client_id = ? AND source_hash = ?
  AND lockout_round = ?
  AND (locked_until IS NULL OR locked_until <= ?)`,
		lockedUntil.UTC(), now, now,
		p.NetworkID(ctx), key.ClientID, key.Source,
		expectedRound, now,
	).ExecWithCount()
	if err != nil {
		return false, sqlcon.HandleError(err)
	}
	return count > 0, nil
}

// ResetFailures implements lockout.Store.
func (p *Persister) ResetFailures(ctx context.Context, key lockout.Key, now time.Time) (err error) {
	ctx, span := p.r.Tracer(ctx).Tracer().Start(ctx, "persistence.sql.ResetFailures")
	defer otelx.End(span, &err)

	// A successful authentication clears the counter and the backoff state
	// for the key, but never an active lock.
	return sqlcon.HandleError(p.Connection(ctx).RawQuery(`
DELETE FROM hydra_client_lockout
WHERE nid = ? AND client_id = ? AND source_hash = ?
  AND (locked_until IS NULL OR locked_until <= ?)`,
		p.NetworkID(ctx), key.ClientID, key.Source, now.UTC(),
	).Exec())
}

// GetEntry implements lockout.Store.
func (p *Persister) GetEntry(ctx context.Context, key lockout.Key) (_ *lockout.Entry, err error) {
	ctx, span := p.r.Tracer(ctx).Tracer().Start(ctx, "persistence.sql.GetEntry")
	defer otelx.End(span, &err)

	var row lockoutRow
	if err := p.Connection(ctx).
		Where("nid = ? AND client_id = ? AND source_hash = ?", p.NetworkID(ctx), key.ClientID, key.Source).
		First(&row); errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	} else if err != nil {
		return nil, sqlcon.HandleError(err)
	}
	return row.toEntry(), nil
}

// ListEntries implements lockout.Store.
func (p *Persister) ListEntries(ctx context.Context, clientID string) (_ []lockout.Entry, err error) {
	ctx, span := p.r.Tracer(ctx).Tracer().Start(ctx, "persistence.sql.ListEntries")
	defer otelx.End(span, &err)

	var rows []lockoutRow
	if err := p.Connection(ctx).
		Where("nid = ? AND client_id = ?", p.NetworkID(ctx), clientID).
		Order("source_hash ASC").
		All(&rows); err != nil {
		return nil, sqlcon.HandleError(err)
	}
	entries := make([]lockout.Entry, 0, len(rows))
	for i := range rows {
		entries = append(entries, *rows[i].toEntry())
	}
	return entries, nil
}

// Clear implements lockout.Store.
func (p *Persister) Clear(ctx context.Context, clientID string) (_ int64, err error) {
	ctx, span := p.r.Tracer(ctx).Tracer().Start(ctx, "persistence.sql.Clear")
	defer otelx.End(span, &err)

	count, err := p.Connection(ctx).RawQuery(`
DELETE FROM hydra_client_lockout
WHERE nid = ? AND client_id = ?`,
		p.NetworkID(ctx), clientID,
	).ExecWithCount()
	if err != nil {
		return 0, sqlcon.HandleError(err)
	}
	return int64(count), nil
}

// ClampLockedUntil implements lockout.Store.
func (p *Persister) ClampLockedUntil(ctx context.Context, key lockout.Key, lockedUntil time.Time) (err error) {
	ctx, span := p.r.Tracer(ctx).Tracer().Start(ctx, "persistence.sql.ClampLockedUntil")
	defer otelx.End(span, &err)

	return sqlcon.HandleError(p.Connection(ctx).RawQuery(`
UPDATE hydra_client_lockout
SET locked_until = ?, updated_at = ?
WHERE nid = ? AND client_id = ? AND source_hash = ?
  AND locked_until IS NOT NULL AND locked_until > ?`,
		lockedUntil.UTC(), time.Now().UTC(),
		p.NetworkID(ctx), key.ClientID, key.Source,
		lockedUntil.UTC(),
	).Exec())
}

// InsertAudit implements lockout.Store.
func (p *Persister) InsertAudit(ctx context.Context, entry lockout.AuditEntry) (err error) {
	ctx, span := p.r.Tracer(ctx).Tracer().Start(ctx, "persistence.sql.InsertAudit")
	defer otelx.End(span, &err)

	return sqlcon.HandleError(p.Connection(ctx).RawQuery(`
INSERT INTO hydra_client_lockout_audit (id, nid, client_id, action, actor, created_at)
VALUES (?, ?, ?, ?, ?, ?)`,
		uuid.Must(uuid.NewV4()).String(), p.NetworkID(ctx),
		entry.ClientID, entry.Action, entry.Actor, entry.At.UTC(),
	).Exec())
}
