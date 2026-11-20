// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package jwk

import (
	"bytes"
	"crypto"
	"sort"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/pkg/errors"
)

// assertTransition returns an error when from -> to is not a legal forward
// lifecycle transition. Reaching the same state is allowed so that retried
// operations and repeated cleanup of an already tombstoned key stay idempotent.
func assertTransition(from, to KeyState) error {
	if from == to {
		return nil
	}
	want, ok := lifecycleOrder[from]
	if !ok || want != to {
		return errors.Errorf("illegal signing key lifecycle transition %q -> %q", from, to)
	}
	return nil
}

// FindActive returns the active lifecycle record, or nil when the set has no
// active key. At most one record may be active; that invariant is enforced by
// the persister inside the rotation transaction.
func FindActive(meta []KeyLifecycle) *KeyLifecycle {
	for i := range meta {
		if meta[i].State == KeyStateActive {
			return &meta[i]
		}
	}
	return nil
}

// signingKey picks the private JWK used to sign new tokens: the active key's
// kid is located in the key set by exact ID. Selection is deterministic: when
// metadata is missing (legacy sets without rotation records), the first
// private key in storage order is used, preserving the historic behavior of
// FindPrivateKey.
func signingKey(meta []KeyLifecycle, set *jose.JSONWebKeySet) (*jose.JSONWebKey, error) {
	if active := FindActive(meta); active != nil {
		if keys := set.Key(active.Kid); len(keys) > 0 {
			for i := range keys {
				if !keys[i].IsPublic() {
					return &keys[i], nil
				}
			}
		}
		return nil, errors.Errorf("active signing key %q is missing its private key material", active.Kid)
	}
	return FindPrivateKey(set)
}

// PlanRotation computes the metadata changes for one rotation without touching
// storage. now is the unified storage clock; the caller is responsible for
// checking clock skew before invoking it.
//
// The previously active key (if any) is retired with a cleanup boundary of
// now + maxTokenTTL + clockSkew. The new key starts in pending state and is
// immediately promoted to active within the same transaction, so a failure
// leaves the old key untouched.
func PlanRotation(meta []KeyLifecycle, kid string, now time.Time, maxTokenTTL, clockSkew time.Duration, generation int64) (planned []KeyLifecycle, deltas []RotationDelta, setName string) {
	planned = make([]KeyLifecycle, 0, len(meta)+1)
	planned = append(planned, meta...)

	for i := range planned {
		if planned[i].State == KeyStateActive {
			from := planned[i].State
			planned[i].State = KeyStateRetired
			planned[i].RetiredAt = now
			planned[i].CleanupAfter = now.Add(maxTokenTTL).Add(clockSkew)
			planned[i].UpdatedAt = now
			deltas = append(deltas, RotationDelta{
				Set: planned[i].Set, Kid: planned[i].Kid,
				From: from, To: KeyStateRetired, ChangedAt: now, Generation: generation,
			})
			setName = planned[i].Set
		}
	}

	planned = append(planned, KeyLifecycle{
		Kid:         kid,
		State:       KeyStateActive,
		Generation:  generation,
		ActivatedAt: now,
		UpdatedAt:   now,
	})
	deltas = append(deltas, RotationDelta{
		Kid: kid, From: KeyStatePending, To: KeyStateActive, ChangedAt: now, Generation: generation,
	})
	if setName == "" && len(meta) > 0 {
		setName = meta[0].Set
	}
	return planned, deltas, setName
}

// NextGeneration returns one plus the largest generation present, starting at 1
// for a fresh set.
func NextGeneration(meta []KeyLifecycle) int64 {
	var max int64
	for _, m := range meta {
		if m.Generation > max {
			max = m.Generation
		}
	}
	return max + 1
}

// CleanupCandidates returns the kids whose cleanup boundary has passed. A key
// is eligible only when it is still retired: a key that was promoted back to
// active (or never retired) is never returned, even if an old boundary exists.
//
// The boundary is inclusive: now >= CleanupAfter means eligible, so callers
// testing one second before and one second after the boundary observe the
// reject/accept pair deterministically.
func CleanupCandidates(meta []KeyLifecycle, now time.Time) []string {
	var out []string
	for _, m := range meta {
		if m.State == KeyStateRetired && !now.Before(m.CleanupAfter) {
			out = append(out, m.Kid)
		}
	}
	sort.Strings(out)
	return out
}

// BuildView assembles the externally visible rotation progress.
func BuildView(set string, meta []KeyLifecycle) LifecycleView {
	view := LifecycleView{Set: set, Keys: append([]KeyLifecycle(nil), meta...)}
	sort.SliceStable(view.Keys, func(i, j int) bool {
		if view.Keys[i].Generation != view.Keys[j].Generation {
			return view.Keys[i].Generation < view.Keys[j].Generation
		}
		return view.Keys[i].Kid < view.Keys[j].Kid
	})
	var next time.Time
	for _, k := range view.Keys {
		if k.State == KeyStateRetired {
			if next.IsZero() || k.CleanupAfter.Before(next) {
				next = k.CleanupAfter
			}
		}
		if k.State == KeyStateActive && view.SigningKID == "" {
			view.SigningKID = k.Kid
		}
	}
	view.NextCleanupAt = next
	return view
}

// PublicKIDs returns the key IDs that must remain visible externally, in
// stable generation order.
func PublicKIDs(meta []KeyLifecycle) []string {
	view := BuildView("", meta)
	out := make([]string, 0, len(view.Keys))
	for _, k := range view.Keys {
		if k.IsPubliclyVisible() {
			out = append(out, k.Kid)
		}
	}
	return out
}

// samePublicKey compares the cryptographic identity of two public JWKs by their
// thumbprints. It is used to reject the same kid being written with two
// different public keys while accepting byte-identical rewrites.
func samePublicKey(a, b jose.JSONWebKey) bool {
	pa, pb := a.Public(), b.Public()
	ta, errA := pa.Thumbprint(crypto.SHA256)
	tb, errB := pb.Thumbprint(crypto.SHA256)
	if errA != nil || errB != nil {
		return false
	}
	return bytes.Equal(ta, tb)
}

// VerifyNoKeyIDConflict returns ErrKeyIDConflict when incoming contains a kid
// that already exists with a different public key. Identical rewrites are
// allowed so that import retries stay idempotent.
func VerifyNoKeyIDConflict(existing, incoming *jose.JSONWebKeySet) error {
	for i := range incoming.Keys {
		inc := &incoming.Keys[i]
		for _, got := range existing.Key(inc.KeyID) {
			if !samePublicKey(got, *inc) {
				return errors.WithStack(errors.Wrapf(ErrKeyIDConflict, "key ID %q", inc.KeyID))
			}
		}
	}
	return nil
}

// SelectVerificationKey implements verification-side key selection:
//
//  1. When the token header carries a kid, the matching key is chosen by exact
//     ID. An unknown kid is an error rather than a guess.
//  2. Without a kid, selection falls back by algorithm then use. The fallback
//     order is fixed: active first, then pending, then retired, each group in
//     ascending generation order, so every instance resolves identically.
func SelectVerificationKey(set *jose.JSONWebKeySet, meta []KeyLifecycle, kid, alg, use string) (*jose.JSONWebKey, error) {
	if kid != "" {
		matches := set.Key(kid)
		if len(matches) == 0 {
			return nil, errors.Errorf("no verification key found for kid %q", kid)
		}
		for i := range matches {
			k := &matches[i]
			if (alg == "" || k.Algorithm == alg) && (use == "" || k.Use == use) {
				return k, nil
			}
		}
		return &matches[0], nil
	}

	rank := map[KeyState]int{KeyStateActive: 0, KeyStatePending: 1, KeyStateRetired: 2}
	type candidate struct {
		key  jose.JSONWebKey
		rank int
		gen  int64
		idx  int
	}
	var candidates []candidate
	stateByKid := map[string]KeyLifecycle{}
	for _, m := range meta {
		stateByKid[m.Kid] = m
	}
	for idx := range set.Keys {
		k := set.Keys[idx]
		if alg != "" && k.Algorithm != alg {
			continue
		}
		if use != "" && k.Use != use {
			continue
		}
		r, gen := 3, int64(0)
		if m, ok := stateByKid[k.KeyID]; ok {
			r = rank[m.State]
			gen = m.Generation
		}
		candidates = append(candidates, candidate{key: k, rank: r, gen: gen, idx: idx})
	}
	if len(candidates) == 0 {
		return nil, errors.Errorf("no verification key found for alg=%q use=%q", alg, use)
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].rank != candidates[j].rank {
			return candidates[i].rank < candidates[j].rank
		}
		if candidates[i].gen != candidates[j].gen {
			return candidates[i].gen < candidates[j].gen
		}
		return candidates[i].idx < candidates[j].idx
	})
	return &candidates[0].key, nil
}
