// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package jwk_test

import (
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/hydra/v2/fosite/token/jwt"
	"github.com/ory/hydra/v2/internal/testhelpers"
	"github.com/ory/hydra/v2/jwk"
	"github.com/ory/hydra/v2/x"
)

// TestRotationEnsureFirstSigningKey covers first-time signing: exactly one
// active key is created and repeated/concurrent calls converge on it.
func TestRotationEnsureFirstSigningKey(t *testing.T) {
	reg := testhelpers.NewRegistryMemory(t)
	rm := reg.KeyManager().(jwk.RotationManager)
	ctx := t.Context()
	const set = "set-first"

	res, err := rm.EnsureSigningKey(ctx, set, "RS256", "sig")
	require.NoError(t, err)
	require.NotEmpty(t, res.View.SigningKID)
	firstKID := res.View.SigningKID

	// Idempotent: the second call returns the same active key.
	res2, err := rm.EnsureSigningKey(ctx, set, "RS256", "sig")
	require.NoError(t, err)
	assert.Equal(t, firstKID, res2.View.SigningKID)

	// Exactly one active key in storage.
	var activeCount int
	for _, k := range res2.View.Keys {
		if k.State == jwk.KeyStateActive {
			activeCount++
		}
	}
	assert.Equal(t, 1, activeCount)
}

func TestRotationConcurrentFirstAndRotateSingleActive(t *testing.T) {
	reg := testhelpers.NewRegistryMemory(t)
	rm := reg.KeyManager().(jwk.RotationManager)
	ctx := t.Context()
	const set = "set-concurrent"

	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstErrs []error
	results := make(chan string, 16)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := rm.EnsureSigningKey(ctx, set, "RS256", "sig")
			if err != nil {
				mu.Lock()
				firstErrs = append(firstErrs, err)
				mu.Unlock()
				return
			}
			results <- r.View.SigningKID
		}()
	}
	wg.Wait()
	close(results)
	for _, err := range firstErrs {
		require.NoError(t, err)
	}
	firstKID := <-results
	for kid := range results {
		assert.Equal(t, firstKID, kid, "all instances must converge on one signing key")
	}

	// Concurrent rotations also converge on exactly one active key.
	var wg2 sync.WaitGroup
	var rotateErrs []error
	for range 6 {
		wg2.Add(1)
		go func() {
			defer wg2.Done()
			if _, err := rm.Rotate(ctx, set, "RS256", "sig", time.Hour, time.Minute); err != nil {
				mu.Lock()
				rotateErrs = append(rotateErrs, err)
				mu.Unlock()
			}
		}()
	}
	wg2.Wait()
	for _, err := range rotateErrs {
		require.NoError(t, err)
	}

	view, err := rm.GetLifecycle(ctx, set)
	require.NoError(t, err)
	var active int
	for _, k := range view.Keys {
		if k.State == jwk.KeyStateActive {
			active++
		}
	}
	assert.Equal(t, 1, active, "after concurrent rotations exactly one key may sign")
}

// TestRotationOldTokenStillVerifies covers acceptance 1 & 3: after rotation
// both keys are published and the old key verifies a token signed before the
// rotation, for the whole window until its cleanup boundary.
func TestRotationOldTokenStillVerifies(t *testing.T) {
	reg := testhelpers.NewRegistryMemory(t)
	rm := reg.KeyManager().(jwk.RotationManager)
	ctx := t.Context()
	const set = "set-verify"

	first, err := rm.EnsureSigningKey(ctx, set, "RS256", "sig")
	require.NoError(t, err)
	oldKID := first.View.SigningKID

	// Sign a token with the first key.
	_, err = jwk.GetOrGenerateKeys(ctx, reg, set, "RS256")
	require.NoError(t, err)
	signer := jwk.NewDefaultJWTSigner(reg, set)
	token, _, err := signer.Generate(ctx, jwt.MapClaims{"sub": "alice"}, &jwt.Headers{})
	require.NoError(t, err)

	// Rotate: the old key becomes retired but must remain verifiable.
	_, err = rm.Rotate(ctx, set, "RS256", "sig", time.Hour, time.Minute)
	require.NoError(t, err)

	view, err := rm.GetLifecycle(ctx, set)
	require.NoError(t, err)
	states := map[string]jwk.KeyState{}
	for _, k := range view.Keys {
		states[k.Kid] = k.State
	}
	assert.Equal(t, jwk.KeyStateRetired, states[oldKID])

	// The public verification set contains both keys and is non-empty.
	pub, err := reg.KeyManager().GetKeySet(ctx, set)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(pub.Key(oldKID)), 1)

	// The verification side selects the old key by the token's kid and the
	// token signed before rotation still verifies against the retired key.
	require.NoError(t, verifyWithKeySet(t, token, pub, oldKID))

	// The same token must fail against the new active key.
	view2, err := rm.GetLifecycle(ctx, set)
	require.NoError(t, err)
	require.Error(t, verifyWithKeySet(t, token, pub, view2.SigningKID))
}

// verifyWithKeySet performs JWS verification using the public key identified
// by kid, mirroring how a resource server resolves keys from the JWKS.
func verifyWithKeySet(t *testing.T, token string, set *jose.JSONWebKeySet, kid string) error {
	t.Helper()
	object, err := jose.ParseSigned(token)
	require.NoError(t, err)
	matches := set.Key(kid)
	require.NotEmpty(t, matches, "kid %s missing from verification set", kid)
	_, err = object.Verify(matches[0].Public().Key)
	return err
}

// TestRotationVerificationSetNeverEmpty asserts that throughout a rotation the
// old identifier remains present in the public verification set.
func TestRotationVerificationSetNeverEmpty(t *testing.T) {
	reg := testhelpers.NewRegistryMemory(t)
	rm := reg.KeyManager().(jwk.RotationManager)
	ctx := t.Context()
	const set = x.OpenIDConnectKeyName

	first, err := rm.EnsureSigningKey(ctx, set, "RS256", "sig")
	require.NoError(t, err)
	oldKID := first.View.SigningKID

	for range 3 {
		_, err := rm.Rotate(ctx, set, "RS256", "sig", time.Hour, time.Minute)
		require.NoError(t, err)

		pub, err := reg.KeyManager().GetKeySet(ctx, set)
		require.NoError(t, err)
		require.NotEmpty(t, pub.Keys, "verification set must never be empty during rotation")
		// The original key remains available for verification until cleanup.
		require.GreaterOrEqual(t, len(pub.Key(oldKID)), 1)
	}
}

// TestRotationCleanupBoundaryAndSurvivingToken covers acceptance 4: after an
// expired key is cleaned up, a still-valid token signed by a surviving key
// continues to verify; repeated cleanup is idempotent.
func TestRotationCleanupBoundaryAndSurvivingToken(t *testing.T) {
	reg := testhelpers.NewRegistryMemory(t)
	rm := reg.KeyManager().(jwk.RotationManager)
	ctx := t.Context()
	const set = "set-cleanup"
	skew := time.Minute
	ttl := time.Hour

	_, err := rm.EnsureSigningKey(ctx, set, "RS256", "sig")
	require.NoError(t, err)
	// First rotation: generation 1 retires with a short cleanup boundary.
	_, err = rm.Rotate(ctx, set, "RS256", "sig", ttl, skew)
	require.NoError(t, err)
	// Sign the surviving token AFTER rotation, with the then-active key (gen 2).
	signer := jwk.NewDefaultJWTSigner(reg, set)
	token, _, err := signer.Generate(ctx, jwt.MapClaims{"sub": "bob"}, &jwt.Headers{})
	require.NoError(t, err)

	// Second rotation with a much longer token lifetime: the token's signing
	// key (gen 2) retires with a boundary far in the future, so it must survive
	// the cleanup that removes the oldest generation.
	longTTL := 24 * time.Hour
	_, err = rm.Rotate(ctx, set, "RS256", "sig", longTTL, skew)
	require.NoError(t, err)
	view, err := rm.GetLifecycle(ctx, set)
	require.NoError(t, err)
	parsed, err := jose.ParseSigned(token)
	require.NoError(t, err)
	tokenKID := parsed.Signatures[0].Header.KeyID
	// Boundary of the oldest retired generation (the short-TTL one).
	var boundary time.Time
	for _, k := range view.Keys {
		if k.State == jwk.KeyStateRetired && (boundary.IsZero() || k.CleanupAfter.Before(boundary)) {
			boundary = k.CleanupAfter
		}
	}
	require.False(t, boundary.IsZero())
	// The token's key has a strictly later boundary, so it cannot be eligible
	// at the same instant.
	var tokenBoundary time.Time
	for _, k := range view.Keys {
		if k.Kid == tokenKID {
			tokenBoundary = k.CleanupAfter
		}
	}
	require.True(t, tokenBoundary.After(boundary))

	// Before the boundary cleanup removes nothing.
	got, err := rm.Cleanup(ctx, set, boundary.Add(-time.Second), skew)
	require.NoError(t, err)
	assert.Empty(t, got)

	// At/after the boundary the retired key material is tombstoned.
	got, err = rm.Cleanup(ctx, set, boundary.Add(time.Second), skew)
	require.NoError(t, err)
	require.NotEmpty(t, got)

	// Repeated cleanup is a no-op without error.
	again, err := rm.Cleanup(ctx, set, boundary.Add(time.Hour), skew)
	require.NoError(t, err)
	assert.Empty(t, again)

	// The surviving token, signed by a key whose material was NOT cleaned up
	// (its boundary is later than the earliest retired generation), continues
	// to verify after the oldest retired key material has been deleted.
	pub, err := reg.KeyManager().GetKeySet(ctx, set)
	require.NoError(t, err)
	require.NoError(t, verifyWithKeySet(t, token, pub, tokenKID))

	// The cleaned-up retired key is no longer published.
	finalView, err := rm.GetLifecycle(ctx, set)
	require.NoError(t, err)
	for _, k := range finalView.Keys {
		if contains(got, k.Kid) {
			assert.Equal(t, jwk.KeyStateTombstoned, k.State)
		}
	}
}

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}

// TestRotationExportImportRoundTrip covers acceptance 9: export then import
// reproduces the identical rotation state, with no private material leaking.
func TestRotationExportImportRoundTrip(t *testing.T) {
	reg := testhelpers.NewRegistryMemory(t)
	rm := reg.KeyManager().(jwk.RotationManager)
	ctx := t.Context()
	const set = "set-export"

	_, err := rm.EnsureSigningKey(ctx, set, "RS256", "sig")
	require.NoError(t, err)
	_, err = rm.Rotate(ctx, set, "RS256", "sig", time.Hour, time.Minute)
	require.NoError(t, err)

	exported, err := rm.ExportLifecycle(ctx, set)
	require.NoError(t, err)
	for _, k := range exported.Keys {
		assert.True(t, k.IsPublic(), "export must never contain private keys")
	}

	target := testhelpers.NewRegistryMemory(t)
	targetRM := target.KeyManager().(jwk.RotationManager)
	view, err := targetRM.ImportLifecycle(ctx, set, exported)
	require.NoError(t, err)

	// Re-importing the identical export is idempotent.
	_, err = targetRM.ImportLifecycle(ctx, set, exported)
	require.NoError(t, err)

	sourceView, err := rm.GetLifecycle(ctx, set)
	require.NoError(t, err)
	require.Len(t, view.Keys, len(sourceView.Keys))
	for i := range sourceView.Keys {
		assert.Equal(t, sourceView.Keys[i].Kid, view.Keys[i].Kid)
		assert.Equal(t, sourceView.Keys[i].State, view.Keys[i].State)
		assert.Equal(t, sourceView.Keys[i].Generation, view.Keys[i].Generation)
		assert.True(t, view.Keys[i].CleanupAfter.Equal(sourceView.Keys[i].CleanupAfter))
	}
	assert.Equal(t, sourceView.SigningKID, view.SigningKID)
}

// TestRotationImportRejectsConflictingKid covers acceptance 6: the same kid
// with two different public keys is rejected at write time.
func TestRotationImportRejectsConflictingKid(t *testing.T) {
	reg := testhelpers.NewRegistryMemory(t)
	rm := reg.KeyManager().(jwk.RotationManager)
	ctx := t.Context()
	const set = "set-conflict"

	base, err := rm.EnsureSigningKey(ctx, set, "RS256", "sig")
	require.NoError(t, err)
	exported, err := rm.ExportLifecycle(ctx, set)
	require.NoError(t, err)

	// Forge a different key under an already-used kid.
	other, err := jwk.GenerateJWK(jose.RS256, base.View.SigningKID, "sig")
	require.NoError(t, err)
	exported.Keys = append(exported.Keys, other.Keys[0].Public())

	_, err = rm.ImportLifecycle(ctx, set, exported)
	require.Error(t, err)
}

// TestRotationFullStateLifecycle asserts the complete chain a key travels
// through: it is generated via pending (recorded in the delta), becomes active,
// then retired on rotation, and finally tombstoned once its boundary passes.
func TestRotationFullStateLifecycle(t *testing.T) {
	reg := testhelpers.NewRegistryMemory(t)
	rm := reg.KeyManager().(jwk.RotationManager)
	ctx := t.Context()
	const set = "set-lifecycle"
	skew := time.Minute
	ttl := time.Hour

	first, err := rm.EnsureSigningKey(ctx, set, "RS256", "sig")
	require.NoError(t, err)
	require.Equal(t, jwk.KeyStatePending, first.Delta[0].From)
	require.Equal(t, jwk.KeyStateActive, first.Delta[0].To)
	firstKID := first.View.SigningKID

	rot, err := rm.Rotate(ctx, set, "RS256", "sig", ttl, skew)
	require.NoError(t, err)
	var retiredDelta *jwk.RotationDelta
	for i := range rot.Delta {
		if rot.Delta[i].Kid == firstKID {
			retiredDelta = &rot.Delta[i]
		}
	}
	require.NotNil(t, retiredDelta)
	assert.Equal(t, jwk.KeyStateActive, retiredDelta.From)
	assert.Equal(t, jwk.KeyStateRetired, retiredDelta.To)

	view, err := rm.GetLifecycle(ctx, set)
	require.NoError(t, err)
	var boundary time.Time
	for _, k := range view.Keys {
		if k.Kid == firstKID {
			assert.Equal(t, jwk.KeyStateRetired, k.State)
			boundary = k.CleanupAfter
		}
	}
	require.False(t, boundary.IsZero())

	tombstoned, err := rm.Cleanup(ctx, set, boundary.Add(time.Second), skew)
	require.NoError(t, err)
	assert.Equal(t, []string{firstKID}, tombstoned)

	view, err = rm.GetLifecycle(ctx, set)
	require.NoError(t, err)
	for _, k := range view.Keys {
		if k.Kid == firstKID {
			assert.Equal(t, jwk.KeyStateTombstoned, k.State)
			assert.False(t, k.TombstonedAt.IsZero())
		}
	}
}

func TestRotationClockSkewRefused(t *testing.T) {
	reg := testhelpers.NewRegistryMemory(t)
	rm := reg.KeyManager().(jwk.RotationManager)
	ctx := t.Context()
	const set = "set-skew"

	_, err := rm.EnsureSigningKey(ctx, set, "RS256", "sig")
	require.NoError(t, err)
	_, err = rm.Rotate(ctx, set, "RS256", "sig", time.Millisecond, time.Second)
	require.NoError(t, err)

	// A zero tolerance means any measurable instance-vs-storage clock
	// difference is out of bounds. The storage read and the local comparison
	// cannot happen at the exact same instant, so cleanup must be refused with
	// the clock-skew error instead of deleting keys on an untrusted clock.
	_, err = rm.Cleanup(ctx, set, time.Time{}, 0)
	require.ErrorIs(t, err, jwk.ErrClockSkew)
}
