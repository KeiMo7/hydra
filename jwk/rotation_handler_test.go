// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package jwk_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/hydra/v2/driver"
	"github.com/ory/hydra/v2/internal/testhelpers"
	"github.com/ory/hydra/v2/jwk"
	"github.com/ory/x/httprouterx"
)

func newRotationServer(t *testing.T) (*httptest.Server, *driver.RegistrySQL) {
	t.Helper()
	reg := testhelpers.NewRegistryMemory(t)
	router := httprouterx.NewRouterAdminWithPrefix()
	jwk.NewRotationHandler(reg).SetAdminRoutes(router)
	return httptest.NewServer(router), reg
}

func doJSON(t *testing.T, method, url string, body any) (int, []byte) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		require.NoError(t, err)
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, url, reader)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer res.Body.Close()
	raw, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	return res.StatusCode, raw
}

func TestRotationHandlerEndToEnd(t *testing.T) {
	srv, reg := newRotationServer(t)
	defer srv.Close()
	rm := reg.KeyManager().(jwk.RotationManager)
	const set = "http-set"

	// Rotate on an empty set creates the first generation.
	status, raw := doJSON(t, http.MethodPost, srv.URL+"/admin/key-rotation/"+set+"/rotate", map[string]string{"alg": "RS256"})
	require.Equal(t, http.StatusOK, status, string(raw))
	var result jwk.RotationResult
	require.NoError(t, json.Unmarshal(raw, &result))
	firstKID := result.View.SigningKID
	require.NotEmpty(t, firstKID)

	// Status endpoint reports one active key.
	status, raw = doJSON(t, http.MethodGet, srv.URL+"/admin/key-rotation/"+set, nil)
	require.Equal(t, http.StatusOK, status)
	var view jwk.LifecycleView
	require.NoError(t, json.Unmarshal(raw, &view))
	assert.Equal(t, firstKID, view.SigningKID)

	// A second rotation retires the first key.
	status, raw = doJSON(t, http.MethodPost, srv.URL+"/admin/key-rotation/"+set+"/rotate",
		map[string]string{"max_token_ttl": "1h", "clock_skew": "1m"})
	require.Equal(t, http.StatusOK, status, string(raw))
	require.NoError(t, json.Unmarshal(raw, &result))
	assert.NotEqual(t, firstKID, result.View.SigningKID)

	// Export contains public keys only and lifecycle metadata.
	status, raw = doJSON(t, http.MethodGet, srv.URL+"/admin/key-rotation/"+set+"/export", nil)
	require.Equal(t, http.StatusOK, status)
	var exported jwk.LifecycleExport
	require.NoError(t, json.Unmarshal(raw, &exported))
	for _, k := range exported.Keys {
		assert.True(t, k.IsPublic())
	}
	require.NotEmpty(t, exported.Meta)

	// Import into a different set on the same registry reproduces state.
	const target = "http-set-imported"
	status, raw = doJSON(t, http.MethodPut, srv.URL+"/admin/key-rotation/"+target+"/import", exported)
	require.Equal(t, http.StatusOK, status, string(raw))
	targetView, err := rm.GetLifecycle(t.Context(), target)
	require.NoError(t, err)
	assert.Equal(t, exported.Meta[len(exported.Meta)-1].Kid, targetView.SigningKID)

	// Cleanup before any boundary removes nothing.
	status, raw = doJSON(t, http.MethodPost, srv.URL+"/admin/key-rotation/"+set+"/cleanup", map[string]string{"clock_skew": "1m"})
	require.Equal(t, http.StatusOK, status)
	var cleanup map[string]any
	require.NoError(t, json.Unmarshal(raw, &cleanup))
	assert.Empty(t, cleanup["tombstoned"])
}

func TestRotationHandlerRejectsBadDuration(t *testing.T) {
	srv, _ := newRotationServer(t)
	defer srv.Close()

	status, raw := doJSON(t, http.MethodPost, srv.URL+"/admin/key-rotation/x/rotate", map[string]string{"clock_skew": "not-a-duration"})
	require.Equal(t, http.StatusBadRequest, status, string(raw))
}

func TestRotationHandlerStatusUnknownSet(t *testing.T) {
	srv, _ := newRotationServer(t)
	defer srv.Close()

	status, _ := doJSON(t, http.MethodGet, srv.URL+"/admin/key-rotation/missing", nil)
	require.Equal(t, http.StatusNotFound, status)
}

// TestRotationHandlerCleanupClockSkew exercises the HTTP path of the
// clock-skew refusal with an impossible zero tolerance.
func TestRotationHandlerCleanupClockSkew(t *testing.T) {
	srv, reg := newRotationServer(t)
	defer srv.Close()
	rm := reg.KeyManager().(jwk.RotationManager)
	const set = "http-skew"
	_, err := rm.EnsureSigningKey(t.Context(), set, "RS256", "sig")
	require.NoError(t, err)
	_, err = rm.Rotate(t.Context(), set, "RS256", "sig", time.Millisecond, time.Second)
	require.NoError(t, err)

	status, raw := doJSON(t, http.MethodPost, srv.URL+"/admin/key-rotation/"+set+"/cleanup", map[string]string{"clock_skew": "0s"})
	require.Equal(t, http.StatusServiceUnavailable, status, string(raw))
}
