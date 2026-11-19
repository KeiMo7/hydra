// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	hydra "github.com/ory/hydra/v2/client"
	"github.com/ory/hydra/v2/driver"
	"github.com/ory/hydra/v2/driver/config"
	"github.com/ory/hydra/v2/fosite/compose"
	"github.com/ory/hydra/v2/internal/kratos"
	"github.com/ory/hydra/v2/internal/testhelpers"
	"github.com/ory/hydra/v2/x/loginstats"
	"github.com/ory/x/configx"
)

// TestLoginAttemptStats_PasswordGrant verifies the ROPC path records one
// success and one failure with bounded, plaintext-free account labels.
func TestLoginAttemptStats_PasswordGrant(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	fakeKratos := kratos.NewFake()
	reg := testhelpers.NewRegistryMemory(t,
		driver.WithKratosClient(fakeKratos),
		driver.WithExtraFositeFactories(compose.OAuth2ResourceOwnerPasswordCredentialsFactory),
		driver.WithConfigOptions(
			configx.WithValue(config.KeyLoginAttemptStatsEnabled, true),
			configx.WithValue(config.KeyLoginAttemptStatsAccountCardinality, 64),
		),
	)
	publicTS, _ := testhelpers.NewOAuth2Server(t.Context(), t, reg)
	shim := loginstats.NewRecorderShim(reg.LoginAttemptRecorder())

	secret := uuid.Must(uuid.NewV4()).String()
	c := &hydra.Client{
		Secret:     secret,
		GrantTypes: []string{"password", "refresh_token"},
		Scope:      "offline",
	}
	require.NoError(t, reg.ClientManager().CreateClient(ctx, c))

	cfg := &oauth2.Config{
		ClientID:     c.GetID(),
		ClientSecret: secret,
		Endpoint: oauth2.Endpoint{
			TokenURL:  reg.Config().OAuth2TokenURL(ctx).String(),
			AuthStyle: oauth2.AuthStyleInHeader,
		},
		Scopes: []string{"offline"},
	}
	_ = publicTS

	t.Run("success and failure are each counted once with bounded labels", func(t *testing.T) {
		before := shim.Total()

		// Success.
		tok, err := cfg.PasswordCredentialsToken(ctx, kratos.FakeUsername, kratos.FakePassword)
		require.NoError(t, err)
		require.NotEmpty(t, tok.AccessToken)

		// Failure: bad password, externally invalid_grant.
		_, err = cfg.PasswordCredentialsToken(ctx, kratos.FakeUsername, "wrong-password")
		require.Error(t, err)

		after := shim.Total()
		assert.Equal(t, before+2, after, "one success and one failure must each be recorded")

		rows := shim.ByReason()
		assert.Equal(t, int64(1), rows[string(loginstats.ReasonSuccess)])
		assert.Equal(t, int64(1), rows[string(loginstats.ReasonGrantExpiredOrRevoked)],
			"the fake kratos surfaces a bare not-found, which the protocol layer maps to invalid_grant")

		// No plaintext account anywhere in the bounded label set.
		for _, label := range shim.AccountLabels() {
			assert.NotContains(t, label, kratos.FakeUsername)
			assert.NotEqual(t, kratos.FakeUsername, label)
		}
	})
}

func TestLoginAttemptStats_AuthorizeRedirectFailure(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	reg := testhelpers.NewRegistryMemory(t,
		driver.WithConfigOptions(configx.WithValue(config.KeyLoginAttemptStatsEnabled, true)),
	)
	publicTS, _ := testhelpers.NewOAuth2Server(t.Context(), t, reg)
	shim := loginstats.NewRecorderShim(reg.LoginAttemptRecorder())

	secret := uuid.Must(uuid.NewV4()).String()
	c := &hydra.Client{
		Secret:        secret,
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
		Scope:         "offline",
		RedirectURIs:  []string{publicTS.URL + "/callback"},
	}
	require.NoError(t, reg.ClientManager().CreateClient(ctx, c))

	// An authorize request with an unsupported response type is returned as a
	// redirect (3xx) when a valid redirect URI is registered. It must still be
	// counted as a failure, not a success.
	u, err := url.Parse(reg.Config().OAuth2AuthURL(ctx).String())
	require.NoError(t, err)
	q := u.Query()
	q.Set("client_id", c.GetID())
	q.Set("response_type", "code")
	q.Set("redirect_uri", publicTS.URL+"/callback")
	q.Set("scope", "offline")
	q.Set("state", "xyz")
	u.RawQuery = q.Encode()

	clientNoRedirect := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := clientNoRedirect.Get(u.String())
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusSeeOther, resp.StatusCode, "the failure is delivered as a redirect")
	loc, err := resp.Location()
	require.NoError(t, err)
	assert.NotEmpty(t, loc.Query().Get("error"))

	rows := shim.ByOutcome()
	assert.Equal(t, int64(1), rows[string(loginstats.OutcomeFailure)],
		"a redirect-based authorization failure must not be counted as success")
	assert.Equal(t, int64(0), rows[string(loginstats.OutcomeSuccess)])
}

func TestLoginAttemptStats_LabelsBoundedUnderHighCardinality(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	reg := testhelpers.NewRegistryMemory(t,
		driver.WithConfigOptions(
			configx.WithValue(config.KeyLoginAttemptStatsEnabled, true),
			configx.WithValue(config.KeyLoginAttemptStatsAccountCardinality, 5),
			configx.WithValue(config.KeyLoginAttemptStatsSourceCardinality, 5),
		),
	)
	testhelpers.NewOAuth2Server(t.Context(), t, reg)
	rec := reg.LoginAttemptRecorder()

	// Fire many attempts with distinct oversized accounts and malformed/unique
	// sources.
	for i := 0; i < 200; i++ {
		rec.Record(ctx, loginstats.Attempt{
			EntryPoint: loginstats.EntryPointToken,
			Account:    repeat("a", 2000) + string(rune('A'+i%26)) + string(rune('0'+i%10)),
			Remote:     "10." + string(rune('0'+i/100)) + "." + string(rune('0'+(i/10)%10)) + "." + string(rune('0'+i%10)),
			GrantType:  loginstats.GrantPassword,
			Err:        nil,
		})
	}
	shim := loginstats.NewRecorderShim(rec)
	labels := shim.AccountLabels()
	assert.LessOrEqual(t, len(labels), 5+3, "account labels must be bounded by cap plus fixed buckets")
	assert.Contains(t, labels, loginstats.LabelOverflow)
}

func repeat(s string, n int) string {
	out := make([]byte, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, s[0])
	}
	return string(out)
}

// TestLoginAttemptStats_DeviceEndpoint covers the device authorization
// endpoint's success and failure with the same-source aggregate.
func TestLoginAttemptStats_DeviceEndpoint(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	reg := testhelpers.NewRegistryMemory(t,
		driver.WithConfigOptions(configx.WithValue(config.KeyLoginAttemptStatsEnabled, true)),
	)
	publicTS, _ := testhelpers.NewOAuth2Server(t.Context(), t, reg)
	shim := loginstats.NewRecorderShim(reg.LoginAttemptRecorder())

	secret := uuid.Must(uuid.NewV4()).String()
	c := &hydra.Client{
		ID:                      "device-stats-client",
		Secret:                  secret,
		GrantTypes:              []string{"urn:ietf:params:oauth:grant-type:device_code"},
		Scope:                   "offline",
		TokenEndpointAuthMethod: "client_secret_post",
	}
	require.NoError(t, reg.ClientManager().CreateClient(ctx, c))

	deviceURL := reg.Config().OAuth2DeviceAuthorisationURL(ctx).String()
	_ = publicTS

	t.Run("successful device authorization is counted", func(t *testing.T) {
		before := shim.Total()
		form := url.Values{
			"client_id":     {c.GetID()},
			"client_secret": {secret},
			"scope":         {"offline"},
		}
		resp, err := http.PostForm(deviceURL, form)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		assert.Equal(t, before+1, shim.Total())
		rows := shim.ByReason()
		assert.Equal(t, int64(1), rows[string(loginstats.ReasonSuccess)])
	})

	t.Run("device failure is classified, not counted as success", func(t *testing.T) {
		beforeFail := shim.ByOutcome()[string(loginstats.OutcomeFailure)]
		form := url.Values{
			"client_id":     {"does-not-exist"},
			"client_secret": {"wrong"},
			"scope":         {"offline"},
		}
		resp, err := http.PostForm(deviceURL, form)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.NotEqual(t, http.StatusOK, resp.StatusCode)

		outcomes := shim.ByOutcome()
		assert.Equal(t, beforeFail+1, outcomes[string(loginstats.OutcomeFailure)])
		assert.GreaterOrEqual(t, outcomes[string(loginstats.OutcomeFailure)], int64(1))
	})
}
