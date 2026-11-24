// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package clientauth

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/hydra/v2/fosite"
)

type testMethod struct {
	d Descriptor
}

func (m testMethod) Descriptor() Descriptor { return m.d }
func (m testMethod) Authenticate(context.Context, *AuthenticationInput) (fosite.Client, error) {
	return nil, nil
}

func TestRegistryRegistrationErrors(t *testing.T) {
	r := NewRegistry()
	require.NoError(t, RegisterBuiltins(r))

	err := r.Register(nil)
	require.Error(t, err)

	err = r.Register(testMethod{d: Descriptor{CredentialType: CredentialCustom}})
	var regErr *RegistrationError
	require.ErrorAs(t, err, &regErr)
	assert.Equal(t, "descriptor.id", regErr.Field)

	err = r.Register(testMethod{d: Descriptor{ID: MethodNone, CredentialType: CredentialNone}})
	require.ErrorAs(t, err, &regErr)
	assert.Contains(t, err.Error(), "already registered")

	err = r.Register(testMethod{d: Descriptor{ID: "bad-kind", CredentialType: "nope"}})
	require.ErrorAs(t, err, &regErr)
	assert.Equal(t, "descriptor.credential_type", regErr.Field)
}

func TestSnapshotDefaultSortedDedupedAndDerived(t *testing.T) {
	r := NewRegistry()
	require.NoError(t, RegisterBuiltins(r))
	require.NoError(t, r.Register(testMethod{d: Descriptor{
		ID:             "custom_b",
		CredentialType: CredentialCustom,
		Discoverable:   true,
	}}))
	require.NoError(t, r.Register(testMethod{d: Descriptor{
		ID:             "custom_a",
		CredentialType: CredentialCustom,
	}}))

	snap := r.Snapshot(context.Background())
	assert.Equal(t, []string{
		MethodClientSecretBasic,
		MethodClientSecretPost,
		"custom_a",
		"custom_b",
		MethodNone,
		MethodPrivateKeyJWT,
	}, snap.IDs())
	assert.Equal(t, []string{
		MethodClientSecretBasic,
		MethodClientSecretPost,
		"custom_b",
		MethodNone,
		MethodPrivateKeyJWT,
	}, snap.DiscoveryIDs())
	assert.True(t, snap.RotationEligible(MethodClientSecretBasic))
	assert.True(t, snap.RotationEligible(MethodClientSecretPost))
	assert.False(t, snap.RotationEligible(MethodPrivateKeyJWT))
	assert.False(t, snap.RotationEligible(MethodNone))
	assert.False(t, snap.RotationEligible("custom_a"))
}

func TestSnapshotConfigErrorsAndEmptySet(t *testing.T) {
	ctx := context.Background()

	t.Run("empty explicit set is locatable but usable", func(t *testing.T) {
		r := NewRegistry(WithConfigSource(func(context.Context) ([]string, bool, error) {
			return []string{}, true, nil
		}))
		require.NoError(t, RegisterBuiltins(r))
		snap := r.Snapshot(ctx)
		require.Error(t, snap.ConfigError())
		assert.Empty(t, snap.IDs())
		assert.Empty(t, snap.DiscoveryIDs())
		assert.False(t, snap.Has(MethodNone))
	})

	t.Run("duplicate identifier", func(t *testing.T) {
		r := NewRegistry(WithConfigSource(func(context.Context) ([]string, bool, error) {
			return []string{MethodNone, MethodNone}, true, nil
		}))
		require.NoError(t, RegisterBuiltins(r))
		snap := r.Snapshot(ctx)
		require.Error(t, snap.ConfigError())
		assert.Contains(t, snap.ConfigError().Error(), "more than once")
		assert.Empty(t, snap.IDs())
	})

	t.Run("unregistered identifier", func(t *testing.T) {
		r := NewRegistry(WithConfigSource(func(context.Context) ([]string, bool, error) {
			return []string{"ghost"}, true, nil
		}))
		require.NoError(t, RegisterBuiltins(r))
		snap := r.Snapshot(ctx)
		require.Error(t, snap.ConfigError())
		assert.Contains(t, snap.ConfigError().Error(), "not registered")
	})
}

func TestSnapshotContextIsRequestScoped(t *testing.T) {
	r := NewRegistry()
	require.NoError(t, RegisterBuiltins(r))

	first := r.Snapshot(context.Background())
	ctx := WithSnapshot(context.Background(), first)
	assert.Same(t, first, r.Snapshot(ctx))
}
