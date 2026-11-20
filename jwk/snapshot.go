// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package jwk

import (
	"context"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/pkg/errors"

	"github.com/ory/hydra/v2/x"
)

// DefaultVerificationSnapshotMaxAge bounds how long verification may run on a
// stale snapshot while storage is unavailable. Past this age the snapshot is
// discarded and the storage error is surfaced instead of a potentially wrong
// verification decision.
const DefaultVerificationSnapshotMaxAge = 30 * time.Second

// verificationSnapshot is one cached read of a set's public verification keys
// together with the lifecycle metadata needed for kid-less fallback selection.
type verificationSnapshot struct {
	keys jose.JSONWebKeySet
	meta []KeyLifecycle
	at   time.Time
}

// VerificationKeyResolver serves verification keys from storage, retaining the
// last successful read as a bounded-age fallback for storage outages. Cross
// instance consistency still comes from storage: the cache only bridges short
// unavailability windows, never acts as a source of truth, and is refreshed on
// the first successful read after an outage.
type VerificationKeyResolver struct {
	r       InternalRegistry
	maxAge  time.Duration
	mu      sync.Mutex
	snaps   map[string]verificationSnapshot
	nowFunc func() time.Time
}

// NewVerificationKeyResolver builds a resolver with the default snapshot age.
func NewVerificationKeyResolver(r InternalRegistry) *VerificationKeyResolver {
	return &VerificationKeyResolver{
		r:       r,
		maxAge:  DefaultVerificationSnapshotMaxAge,
		snaps:   map[string]verificationSnapshot{},
		nowFunc: time.Now,
	}
}

// WithMaxAge overrides the stale-snapshot limit. Mainly used by tests.
func (v *VerificationKeyResolver) WithMaxAge(d time.Duration) *VerificationKeyResolver {
	v.maxAge = d
	return v
}

// load reads the freshest set state from storage. A successful read replaces
// any cached snapshot immediately, so recovery from an outage takes effect on
// the very next call.
func (v *VerificationKeyResolver) load(ctx context.Context, set string) (verificationSnapshot, error) {
	keys, err := v.r.KeyManager().GetKeySet(ctx, set)
	if err != nil {
		return verificationSnapshot{}, err
	}
	var meta []KeyLifecycle
	if rm, ok := v.r.KeyManager().(RotationManager); ok {
		if view, err := rm.GetLifecycle(ctx, set); err == nil {
			meta = view.Keys
		} else if !errors.Is(err, x.ErrNotFound) && !errors.Is(err, ErrRotationUnsupported) {
			return verificationSnapshot{}, err
		}
	}
	return verificationSnapshot{keys: *ExcludePrivateKeys(keys), meta: meta, at: v.nowFunc()}, nil
}

// Resolve returns the verification key for a token. kid selects by exact ID;
// when empty, selection falls back by algorithm and use in the stable order
// defined by SelectVerificationKey.
//
// On a storage failure the last successful snapshot is reused only while it is
// younger than maxAge. An older snapshot or no snapshot returns the storage
// error rather than guessing.
func (v *VerificationKeyResolver) Resolve(ctx context.Context, set, kid, alg, use string) (*jose.JSONWebKey, error) {
	snap, freshErr := v.load(ctx, set)
	if freshErr == nil {
		v.mu.Lock()
		v.snaps[set] = snap
		v.mu.Unlock()
	} else {
		v.mu.Lock()
		cached, ok := v.snaps[set]
		v.mu.Unlock()
		if !ok {
			return nil, freshErr
		}
		if v.nowFunc().Sub(cached.at) > v.maxAge {
			return nil, errors.Wrapf(freshErr, "verification key snapshot for set %q is stale beyond %s", set, v.maxAge)
		}
		v.r.Logger().WithError(freshErr).Warnf(
			"Storage unavailable while resolving verification key for set %q; using snapshot aged %s", set, v.nowFunc().Sub(cached.at))
		snap = cached
	}
	return SelectVerificationKey(&snap.keys, snap.meta, kid, alg, use)
}

// Invalidate drops the cached snapshot for a set. Rotation and cleanup call
// this after committing so subsequent verification never serves a pre-change
// snapshot for longer than necessary.
func (v *VerificationKeyResolver) Invalidate(set string) {
	v.mu.Lock()
	delete(v.snaps, set)
	v.mu.Unlock()
}
