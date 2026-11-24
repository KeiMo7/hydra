// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package clientauth

import (
	"context"
	"sync"

	"github.com/ory/hydra/v2/fosite"
)

var (
	fallbackOnce     sync.Once
	fallbackRegistry *Registry
)

// BuiltinFallbackRegistry returns a process-wide registry containing only
// built-in declarations. Production wiring uses the driver-owned registry;
// this fallback keeps lightweight standalone validators compatible.
func BuiltinFallbackRegistry() *Registry {
	fallbackOnce.Do(func() {
		fallbackRegistry = NewRegistry()
		_ = RegisterBuiltins(fallbackRegistry)
	})
	return fallbackRegistry
}

// BuiltinDescriptors returns the declaration shared by Hydra's built-in
// authentication methods. Built-in and external methods use the same
// Descriptor shape.
func BuiltinDescriptors() []Descriptor {
	return []Descriptor{
		{
			ID:             MethodClientSecretBasic,
			CredentialType: CredentialSharedSecret,
			Discoverable:   true,
			Rotatable:      true,
			Materials:      []string{"client_id", "client_secret", "authorization_header"},
		},
		{
			ID:             MethodClientSecretPost,
			CredentialType: CredentialSharedSecret,
			Discoverable:   true,
			Rotatable:      true,
			Materials:      []string{"client_id", "client_secret"},
		},
		{
			ID:             MethodPrivateKeyJWT,
			CredentialType: CredentialPublicKey,
			Discoverable:   true,
			Rotatable:      false,
			Materials:      []string{"client_assertion", "jwks|jwks_uri"},
		},
		{
			ID:             MethodNone,
			CredentialType: CredentialNone,
			Discoverable:   true,
			Rotatable:      false,
			Materials:      nil,
		},
	}
}

type builtinMethod struct {
	d Descriptor
}

// RegisterBuiltins registers all built-in declarations. Actual verification is
// delegated to the existing Fosite strategy via Registry.SetLegacyAuthenticator.
func RegisterBuiltins(registry *Registry) error {
	for _, d := range BuiltinDescriptors() {
		if err := registry.Register(builtinMethod{d: d}); err != nil {
			return err
		}
	}
	return nil
}

func (m builtinMethod) Descriptor() Descriptor { return m.d }

// Authenticate is dispatched through the registry's legacy adapter, which
// preserves Fosite's exact built-in behavior. It is implemented here only to
// satisfy the Method interface.
func (m builtinMethod) Authenticate(_ context.Context, _ *AuthenticationInput) (fosite.Client, error) {
	return nil, fosite.ErrInvalidClient
}
