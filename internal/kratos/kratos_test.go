// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package kratos_test

import (
	"context"
	"encoding/json"
	stderr "errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/hydra/v2/driver"
	"github.com/ory/hydra/v2/driver/config"
	"github.com/ory/hydra/v2/fosite"
	"github.com/ory/hydra/v2/internal/testhelpers"
	"github.com/ory/hydra/v2/x/loginstats"
	"github.com/ory/x/configx"
)

// loginFlow is a minimal valid Kratos native login flow payload. The generated
// SDK validates required fields, so the stub must provide them all.
func loginFlow() map[string]any {
	return map[string]any{
		"id":          "flow-id",
		"type":        "api",
		"state":       "show_form",
		"issued_at":   "2099-01-01T00:00:00Z",
		"expires_at":  "2099-01-01T00:00:00Z",
		"request_url": "/self-service/login/api?flow=flow-id",
		"ui":          map[string]any{"action": "/self-service/login?flow=flow-id", "method": "POST", "nodes": []any{}},
	}
}

// newStubKratos serves a Kratos-like API. updateStatus chooses the update
// outcome; 0 means success.
func newStubKratos(t *testing.T, updateStatus int, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/self-service/login/api" {
			_ = json.NewEncoder(w).Encode(loginFlow())
			return
		}
		if handler != nil {
			handler(w, r)
			return
		}
		if updateStatus == 0 {
			// A successful native login update returns a SuccessfulNativeLogin
			// carrying the active session.
			_ = json.NewEncoder(w).Encode(map[string]any{
				"session_token": "st",
				"session": map[string]any{"id": "sess-1", "identity": map[string]any{
					"id":         "ident-1",
					"schema_id":  "default",
					"schema_url": "/schemas/default",
					"traits":     map[string]any{"email": "someone@example.com"},
				}},
			})
			return
		}
		w.WriteHeader(updateStatus)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": updateStatus}})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestAuthenticate_SuccessStillWorks(t *testing.T) {
	t.Parallel()

	srv := newStubKratos(t, 0, nil)
	reg := testhelpers.NewRegistryMemory(t,
		driver.WithConfigOptions(configx.WithValue(config.KeyIdentityProviderPublicURL, srv.URL)),
	)
	session, err := reg.Kratos().Authenticate(context.Background(), "someone", "secret")
	require.NoError(t, err)
	require.NotNil(t, session)
	assert.Equal(t, "ident-1", session.Identity.Id)
}

func TestAuthenticate_Backend500IsNotCredential(t *testing.T) {
	t.Parallel()

	srv := newStubKratos(t, http.StatusInternalServerError, nil)
	reg := testhelpers.NewRegistryMemory(t,
		driver.WithConfigOptions(configx.WithValue(config.KeyIdentityProviderPublicURL, srv.URL)),
	)
	_, err := reg.Kratos().Authenticate(context.Background(), "someone", "secret")
	require.Error(t, err)

	// External shape is unchanged: the ROPC grant still turns this into ErrNotFound.
	assert.True(t, stderr.Is(err, fosite.ErrNotFound))
	// But internally it is an outage, which the classifier must keep separate
	// from a bad password.
	assert.True(t, stderr.Is(err, loginstats.ErrBackendUnavailable))
	assert.Equal(t, loginstats.ReasonBackendUnavailable, loginstats.Classify(err, loginstats.Hint{}))
}

func TestAuthenticate_NetworkFailureIsBackendNotCredential(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	// The update call closes the connection immediately; flow creation still
	// succeeds so we exercise the credential-adjudication call specifically.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/self-service/login/api" {
			_ = json.NewEncoder(w).Encode(loginFlow())
			return
		}
		hj, ok := w.(http.Hijacker)
		require.True(t, ok)
		conn, _, err := hj.Hijack()
		require.NoError(t, err)
		_ = conn.Close()
	}))
	t.Cleanup(srv.Close)

	reg := testhelpers.NewRegistryMemory(t,
		driver.WithConfigOptions(configx.WithValue(config.KeyIdentityProviderPublicURL, srv.URL)),
	)
	_, err := reg.Kratos().Authenticate(ctx, "someone", "secret")
	require.Error(t, err)
	assert.True(t, stderr.Is(err, fosite.ErrNotFound))
	assert.True(t, stderr.Is(err, loginstats.ErrBackendUnavailable),
		"a connection failure must never classify as a bad password: %v", err)
}
