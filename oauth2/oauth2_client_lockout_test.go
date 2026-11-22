// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"

	hc "github.com/ory/hydra/v2/client"
	"github.com/ory/hydra/v2/driver"
	"github.com/ory/hydra/v2/driver/config"
	"github.com/ory/hydra/v2/internal/testhelpers"
	hydraoauth2 "github.com/ory/hydra/v2/oauth2"
	"github.com/ory/x/configx"
)

func lockoutTokenRequest(t *testing.T, c *http.Client, tokenURL, clientID, clientSecret string) (int, gjson.Result) {
	t.Helper()
	form := url.Values{"grant_type": {"client_credentials"}}
	req, err := http.NewRequest("POST", tokenURL, strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(clientID), url.QueryEscape(clientSecret))
	res, err := c.Do(req)
	require.NoError(t, err)
	defer func() { _ = res.Body.Close() }()
	body, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	return res.StatusCode, gjson.ParseBytes(body)
}

func lockoutStatus(t *testing.T, c *http.Client, adminURL, clientID string) (int, gjson.Result) {
	t.Helper()
	res, err := c.Get(fmt.Sprintf("%s/clients/%s/lockout", adminURL, clientID))
	require.NoError(t, err)
	defer func() { _ = res.Body.Close() }()
	body, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	return res.StatusCode, gjson.ParseBytes(body)
}

func TestClientCredentialsLockout(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	newLockedRegistry := func(t *testing.T, extra ...configx.OptionModifier) *driver.RegistrySQL {
		opts := []configx.OptionModifier{
			configx.WithValue(config.KeyClientLockoutThreshold, 3),
			configx.WithValue(config.KeyClientLockoutWindow, "10m"),
			configx.WithValue(config.KeyClientLockoutDuration, "5m"),
		}
		return testhelpers.NewRegistryMemory(t, driver.WithConfigOptions(append(opts, extra...)...))
	}

	createClient := func(t *testing.T, reg *driver.RegistrySQL, secret string) *hc.Client {
		c := &hc.Client{
			ID:            uuid.Must(uuid.NewV4()).String(),
			Secret:        secret,
			GrantTypes:    []string{"client_credentials"},
			ResponseTypes: []string{"token"},
			Scope:         "foobar",
		}
		require.NoError(t, reg.ClientManager().CreateClient(ctx, c))
		return c
	}

	t.Run("locked client is rejected even with correct credentials until unlocked", func(t *testing.T) {
		t.Parallel()
		reg := newLockedRegistry(t)
		public, admin := testhelpers.NewOAuth2Server(ctx, t, reg)
		tokenURL := public.URL + hydraoauth2.TokenPath
		cl := createClient(t, reg, "the-correct-secret")

		// Three failures engage the lockout (threshold = 3).
		for i := 0; i < 3; i++ {
			code, body := lockoutTokenRequest(t, public.Client(), tokenURL, cl.ID, "wrong-secret")
			require.Equal(t, http.StatusUnauthorized, code, body.Raw)
			assert.Equal(t, "invalid_client", body.Get("error").String())
			assert.NotContains(t, body.Get("error_description").String(), "locked out")
		}

		// The correct secret is rejected while locked, with a distinguishable reason.
		code, body := lockoutTokenRequest(t, public.Client(), tokenURL, cl.ID, "the-correct-secret")
		require.Equal(t, http.StatusUnauthorized, code, body.Raw)
		assert.Equal(t, "invalid_client", body.Get("error").String())
		assert.Contains(t, body.Get("error_description").String(), "locked out")

		// Operators can inspect the state.
		code, status := lockoutStatus(t, admin.Client(), admin.URL, cl.ID)
		require.Equal(t, http.StatusOK, code, status.Raw)
		assert.True(t, status.Get("locked").Bool())
		assert.EqualValues(t, 1, status.Get("lockout_round").Int())

		// Manual unlock restores access immediately.
		req, err := http.NewRequest("DELETE", fmt.Sprintf("%s/clients/%s/lockout", admin.URL, cl.ID), nil)
		require.NoError(t, err)
		res, err := admin.Client().Do(req)
		require.NoError(t, err)
		_ = res.Body.Close()
		require.Equal(t, http.StatusNoContent, res.StatusCode)

		code, body = lockoutTokenRequest(t, public.Client(), tokenURL, cl.ID, "the-correct-secret")
		require.Equal(t, http.StatusOK, code, body.Raw)
		assert.NotEmpty(t, body.Get("access_token").String())

		// The unlock left an audit trail entry.
		var auditCount int64
		require.NoError(t, reg.Persister().Connection(ctx).RawQuery(
			`SELECT COUNT(*) FROM hydra_client_lockout_audit WHERE client_id = ? AND action = 'unlock'`, cl.ID,
		).First(&auditCount))
		assert.EqualValues(t, 1, auditCount)
	})

	t.Run("concurrent failures are counted exactly", func(t *testing.T) {
		t.Parallel()
		reg := newLockedRegistry(t, configx.WithValue(config.KeyClientLockoutThreshold, 10000))
		public, admin := testhelpers.NewOAuth2Server(ctx, t, reg)
		tokenURL := public.URL + hydraoauth2.TokenPath
		cl := createClient(t, reg, "secret")

		const n = 30
		var wg sync.WaitGroup
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				code, _ := lockoutTokenRequest(t, public.Client(), tokenURL, cl.ID, "wrong-secret")
				assert.Equal(t, http.StatusUnauthorized, code)
			}()
		}
		wg.Wait()

		code, status := lockoutStatus(t, admin.Client(), admin.URL, cl.ID)
		require.Equal(t, http.StatusOK, code, status.Raw)
		assert.EqualValues(t, n, status.Get("failure_count").Int(),
			"N concurrent failed requests must result in exactly N counted failures")
	})

	t.Run("unknown clients are counted and locked like known clients", func(t *testing.T) {
		t.Parallel()
		reg := newLockedRegistry(t)
		public, _ := testhelpers.NewOAuth2Server(ctx, t, reg)
		tokenURL := public.URL + hydraoauth2.TokenPath
		unknownID := uuid.Must(uuid.NewV4()).String()

		var firstKnown, firstUnknown gjson.Result
		cl := createClient(t, reg, "secret")
		codeKnown, firstKnown := lockoutTokenRequest(t, public.Client(), tokenURL, cl.ID, "wrong")
		codeUnknown, firstUnknown := lockoutTokenRequest(t, public.Client(), tokenURL, unknownID, "wrong")
		require.Equal(t, codeKnown, codeUnknown)
		assert.Equal(t, firstKnown.Get("error").String(), firstUnknown.Get("error").String(),
			"unknown clients must be indistinguishable from wrong secrets")

		for i := 0; i < 2; i++ {
			lockoutTokenRequest(t, public.Client(), tokenURL, unknownID, "wrong")
		}
		// The unknown client identifier is now locked as well.
		_, body := lockoutTokenRequest(t, public.Client(), tokenURL, unknownID, "wrong")
		assert.Contains(t, body.Get("error_description").String(), "locked out")
	})

	t.Run("public clients are unaffected", func(t *testing.T) {
		t.Parallel()
		reg := newLockedRegistry(t)
		public, admin := testhelpers.NewOAuth2Server(ctx, t, reg)
		cl := &hc.Client{
			ID:                      uuid.Must(uuid.NewV4()).String(),
			TokenEndpointAuthMethod: "none",
			GrantTypes:              []string{"client_credentials"},
			ResponseTypes:           []string{"token"},
			Scope:                   "foobar",
		}
		require.NoError(t, reg.ClientManager().CreateClient(ctx, cl))

		// Public clients authenticate without a secret and must never be
		// counted or locked.
		for i := 0; i < 5; i++ {
			form := url.Values{"grant_type": {"client_credentials"}, "client_id": {cl.ID}}
			res, err := public.Client().PostForm(public.URL+hydraoauth2.TokenPath, form)
			require.NoError(t, err)
			_ = res.Body.Close()
		}
		code, status := lockoutStatus(t, admin.Client(), admin.URL, cl.ID)
		require.Equal(t, http.StatusOK, code, status.Raw)
		assert.EqualValues(t, 0, status.Get("failure_count").Int())
		assert.False(t, status.Get("locked").Bool())
	})

	t.Run("disabled lockout keeps previous behavior", func(t *testing.T) {
		t.Parallel()
		reg := newLockedRegistry(t, configx.WithValue(config.KeyClientLockoutEnabled, false))
		public, admin := testhelpers.NewOAuth2Server(ctx, t, reg)
		tokenURL := public.URL + hydraoauth2.TokenPath
		cl := createClient(t, reg, "secret")

		for i := 0; i < 10; i++ {
			code, body := lockoutTokenRequest(t, public.Client(), tokenURL, cl.ID, "wrong-secret")
			require.Equal(t, http.StatusUnauthorized, code, body.Raw)
			assert.NotContains(t, body.Get("error_description").String(), "locked out")
		}
		code, status := lockoutStatus(t, admin.Client(), admin.URL, cl.ID)
		require.Equal(t, http.StatusOK, code, status.Raw)
		assert.EqualValues(t, 0, status.Get("failure_count").Int(), "disabled lockout must not record anything")

		// And the correct secret still works.
		code, body := lockoutTokenRequest(t, public.Client(), tokenURL, cl.ID, "secret")
		require.Equal(t, http.StatusOK, code, body.Raw)
	})
}
