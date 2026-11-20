// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package jwk_test

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ory/hydra/v2/internal/testhelpers"
	"github.com/ory/hydra/v2/jwk"
)

// TestVerificationSnapshotFallback verifies that storage outages are bridged
// by the last successful snapshot only while it is within its age limit.
func TestVerificationSnapshotFallback(t *testing.T) {
	reg := testhelpers.NewRegistryMemory(t)
	rm := reg.KeyManager().(jwk.RotationManager)
	ctx := t.Context()
	const set = "set-snapshot"

	res, err := rm.EnsureSigningKey(ctx, set, "RS256", "sig")
	require.NoError(t, err)
	kid := res.View.SigningKID

	resolver := jwk.NewVerificationKeyResolver(reg).WithMaxAge(50 * time.Millisecond)

	// First read populates the snapshot from storage.
	got, err := resolver.Resolve(ctx, set, kid, "RS256", "sig")
	require.NoError(t, err)
	require.Equal(t, kid, got.KeyID)

	// Simulate storage becoming unavailable by closing the connection. The
	// fresh snapshot must still serve verification.
	require.NoError(t, reg.Persister().Connection(ctx).Close())
	got, err = resolver.Resolve(ctx, set, kid, "RS256", "sig")
	require.NoError(t, err, "a snapshot within its age limit must survive a storage outage")
	require.Equal(t, kid, got.KeyID)

	// Once the snapshot ages past the limit, the storage error must surface
	// instead of serving a potentially wrong key.
	time.Sleep(70 * time.Millisecond)
	_, err = resolver.Resolve(ctx, set, kid, "RS256", "sig")
	require.Error(t, err)
	require.False(t, errors.Is(err, jwk.ErrRotationUnsupported))
}

// TestVerificationResolverUnknownKidFails ensures exact kid selection never
// silently falls back to a different key.
func TestVerificationResolverUnknownKidFails(t *testing.T) {
	reg := testhelpers.NewRegistryMemory(t)
	rm := reg.KeyManager().(jwk.RotationManager)
	ctx := t.Context()
	const set = "set-unknown-kid"
	_, err := rm.EnsureSigningKey(ctx, set, "RS256", "sig")
	require.NoError(t, err)

	resolver := jwk.NewVerificationKeyResolver(reg)
	_, err = resolver.Resolve(ctx, set, "does-not-exist", "", "")
	require.Error(t, err)
}
