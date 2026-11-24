// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package clientauth_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/hydra/v2/client"
	"github.com/ory/hydra/v2/clientauth"
	"github.com/ory/hydra/v2/driver"
	"github.com/ory/hydra/v2/driver/config"
	"github.com/ory/hydra/v2/fosite"
	"github.com/ory/hydra/v2/internal/testhelpers"
	"github.com/ory/x/configx"
)

const (
	customMethodID = "test_credential"
	panicMethodID  = "test_panicky"
	customFormKey  = "x_test_credential"
)

type acceptanceMethod struct {
	id         string
	kind       clientauth.CredentialKind
	discover   bool
	rotatable  bool
	hasher     fosite.Hasher
	panicValue bool
}

func (m *acceptanceMethod) Descriptor() clientauth.Descriptor {
	return clientauth.Descriptor{
		ID:             m.id,
		CredentialType: m.kind,
		Discoverable:   m.discover,
		Rotatable:      m.rotatable,
		Materials:      []string{customFormKey},
	}
}

func (m *acceptanceMethod) MatchRequest(r *http.Request, form url.Values) (string, bool) {
	return form.Get("client_id"), form.Get(customFormKey) != ""
}

func (m *acceptanceMethod) Authenticate(ctx context.Context, in *clientauth.AuthenticationInput) (fosite.Client, error) {
	if m.panicValue {
		panic("intentional method crash")
	}

	cl := in.Client
	if cl == nil {
		id := in.Form.Get("client_id")
		var err error
		cl, err = in.Clients.GetClient(ctx, id)
		if err != nil {
			return nil, &clientauth.AuthFailure{Category: clientauth.CategoryClientNotFound}
		}
	}

	secret := in.Form.Get(customFormKey)
	if secret == "" {
		return nil, &clientauth.AuthFailure{Category: clientauth.CategoryNoCredentials}
	}
	if err := m.hasher.Compare(ctx, cl.GetHashedSecret(), []byte(secret)); err != nil {
		return nil, &clientauth.AuthFailure{Category: clientauth.CategoryInvalidSecret}
	}
	return cl, nil
}

type acceptanceEnv struct {
	reg     *driver.RegistrySQL
	capture *clientauth.CaptureExporter
	logHook *test.Hook
	public  *httptest.Server
	admin   *httptest.Server
}

func setupAcceptance(t *testing.T) acceptanceEnv {
	t.Helper()
	ctx := context.Background()
	reg := testhelpers.NewRegistryMemory(t, driver.WithConfigOptions(configx.WithValues(map[string]any{
		config.KeyLogLevel:              "info",
		"log.leak_sensitive_values":     false,
		config.KeyDefaultClientScope:    []string{"openid"},
		config.KeySubjectTypesSupported: []string{"public"},
		config.KeyBCryptCost:            4,
	})))

	capture := clientauth.NewCaptureExporter()
	reg.ClientAuthRegistry().AddExporter(capture)

	logHook := &test.Hook{}
	reg.Logger().Logrus().AddHook(logHook)

	require.NoError(t, reg.ClientAuthRegistry().Register(&acceptanceMethod{
		id:       customMethodID,
		kind:     clientauth.CredentialCustom,
		discover: true,
		hasher:   reg.ClientHasher(),
	}))
	require.NoError(t, reg.ClientAuthRegistry().Register(&acceptanceMethod{
		id:         panicMethodID,
		kind:       clientauth.CredentialCustom,
		hasher:     reg.ClientHasher(),
		panicValue: true,
	}))

	public, admin := testhelpers.NewOAuth2Server(ctx, t, reg)
	return acceptanceEnv{reg: reg, capture: capture, logHook: logHook, public: public, admin: admin}
}

func (e acceptanceEnv) tokenURL() string  { return e.public.URL + "/oauth2/token" }
func (e acceptanceEnv) revokeURL() string { return e.public.URL + "/oauth2/revoke" }
func (e acceptanceEnv) deviceURL() string { return e.public.URL + "/oauth2/device/auth" }

func doForm(t *testing.T, endpoint string, form url.Values, headers http.Header) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, vs := range headers {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}

	res, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	return res.StatusCode, string(body)
}

func createAdminClient(t *testing.T, admin *httptest.Server, payload map[string]any) (int, map[string]any, string) {
	t.Helper()
	raw, err := json.Marshal(payload)
	require.NoError(t, err)
	res, err := http.Post(admin.URL+"/admin/clients", "application/json", bytes.NewReader(raw)) //nolint:gosec
	require.NoError(t, err)
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	var decoded map[string]any
	_ = json.Unmarshal(body, &decoded)
	return res.StatusCode, decoded, string(body)
}

func discoveryMethods(t *testing.T, public *httptest.Server) []string {
	t.Helper()
	res, err := http.Get(public.URL + "/.well-known/openid-configuration") //nolint:gosec
	require.NoError(t, err)
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, res.StatusCode, string(body))
	var doc struct {
		Methods []string `json:"token_endpoint_auth_methods_supported"`
	}
	require.NoError(t, json.Unmarshal(body, &doc))
	return doc.Methods
}

func eventsFor(events []clientauth.Event, clientID, method string) []clientauth.Event {
	var out []clientauth.Event
	for _, e := range events {
		if e.ClientID == clientID && (method == "" || e.Method == method) {
			out = append(out, e)
		}
	}
	return out
}

func lastCategory(t *testing.T, capture *clientauth.CaptureExporter, clientID, method string) clientauth.FailureCategory {
	t.Helper()
	require.Eventually(t, func() bool {
		return len(eventsFor(capture.Events(), clientID, method)) > 0
	}, time.Second, 10*time.Millisecond)
	events := eventsFor(capture.Events(), clientID, method)
	return events[len(events)-1].Category
}

func TestClientAuthFrameworkFullChain(t *testing.T) {
	ctx := context.Background()
	env := setupAcceptance(t)

	methods := discoveryMethods(t, env.public)
	assert.Contains(t, methods, customMethodID)
	assert.Contains(t, methods, clientauth.MethodClientSecretBasic)
	assert.Equal(t, methods, append([]string(nil), methods...), "discovery list should be stable")
	assert.Equal(t, methods, sortedCopy(methods), "discovery list should be sorted")

	// Unknown methods and public-key metadata remain 400 metadata errors.
	status, _, body := createAdminClient(t, env.admin, map[string]any{
		"client_id":                  "reject-unknown-method",
		"token_endpoint_auth_method": "not_registered",
	})
	assert.Equal(t, http.StatusBadRequest, status, body)
	assert.Contains(t, body, "invalid_client_metadata")

	status, _, body = createAdminClient(t, env.admin, map[string]any{
		"client_id":                  "reject-missing-jwk",
		"token_endpoint_auth_method": clientauth.MethodPrivateKeyJWT,
	})
	assert.Equal(t, http.StatusBadRequest, status, body)
	assert.Contains(t, body, "invalid_client_metadata")
	assert.Contains(t, body, "either jwks or jwks_uri must be set")

	// The test-only method goes through creation with the same validation path.
	customSecret := "unit-test-custom-secret"
	customClientID := "custom-full-chain"
	status, created, body := createAdminClient(t, env.admin, map[string]any{
		"client_id":                  customClientID,
		"client_secret":              customSecret,
		"token_endpoint_auth_method": customMethodID,
		"grant_types":                []string{"client_credentials"},
		"scope":                      "openid",
	})
	require.Equal(t, http.StatusCreated, status, body)
	require.Equal(t, customClientID, created["client_id"])

	form := url.Values{
		"grant_type":  {"client_credentials"},
		"client_id":   {customClientID},
		customFormKey: {customSecret},
	}
	status, body = doForm(t, env.tokenURL(), form, nil)
	require.Equal(t, http.StatusOK, status, body)
	assert.Contains(t, body, "access_token")
	assert.Equal(t, clientauth.CategorySuccess, lastCategory(t, env.capture, customClientID, customMethodID))

	// Bad custom credentials have the stable external invalid_client mapping.
	errorBodies := []string{}
	wrong := url.Values{
		"grant_type":  {"client_credentials"},
		"client_id":   {customClientID},
		customFormKey: {"wrong-custom-secret"},
	}
	status, body = doForm(t, env.tokenURL(), wrong, nil)
	assert.Equal(t, http.StatusUnauthorized, status, body)
	assert.Contains(t, body, `"error":"invalid_client"`)
	errorBodies = append(errorBodies, body)
	assert.Equal(t, clientauth.CategoryInvalidSecret, lastCategory(t, env.capture, customClientID, customMethodID))

	// Token, revocation and device authorization use the same decision/mapping.
	for _, tc := range []struct {
		name          string
		endpoint      string
		extra         url.Values
		endpointAudit string
	}{
		{name: "token", endpoint: env.tokenURL(), extra: url.Values{"grant_type": {"client_credentials"}}, endpointAudit: "token"},
		{name: "revoke", endpoint: env.revokeURL(), extra: url.Values{"token": {"some-token"}}, endpointAudit: "revocation"},
		{name: "device", endpoint: env.deviceURL(), extra: nil, endpointAudit: "device_authorization"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := url.Values{"client_id": {customClientID}, customFormKey: {"wrong-custom-secret"}}
			for k, vs := range tc.extra {
				v[k] = vs
			}
			status, body := doForm(t, tc.endpoint, v, nil)
			assert.Equalf(t, http.StatusUnauthorized, status, body)
			assert.Contains(t, body, "invalid_client")
			errorBodies = append(errorBodies, body)

			var matched *clientauth.Event
			for _, e := range env.capture.Events() {
				if e.ClientID == customClientID && e.Endpoint == tc.endpointAudit && !e.Success {
					matched = &e
				}
			}
			require.NotNil(t, matched, "expected %s audit event", tc.endpointAudit)
			assert.Equal(t, clientauth.CategoryInvalidSecret, matched.Category)
		})
	}

	// A panicking external method is isolated to that method's failure.
	panicClientID := "panic-client"
	status, _, body = createAdminClient(t, env.admin, map[string]any{
		"client_id":                  panicClientID,
		"client_secret":              "panic-client-secret",
		"token_endpoint_auth_method": panicMethodID,
		"grant_types":                []string{"client_credentials"},
	})
	require.Equal(t, http.StatusCreated, status, body)
	status, body = doForm(t, env.tokenURL(), url.Values{
		"grant_type": {"client_credentials"},
		"client_id":  {panicClientID},
	}, nil)
	assert.Equal(t, http.StatusUnauthorized, status, body)
	assert.Contains(t, body, `"error":"invalid_client"`)
	assert.NotContains(t, body, "intentional method crash")
	assert.NotContains(t, body, "goroutine")
	assert.Equal(t, clientauth.CategoryMethodPanic, lastCategory(t, env.capture, panicClientID, panicMethodID))

	// The process and other methods remain usable after the panic.
	status, body = doForm(t, env.tokenURL(), form, nil)
	assert.Equal(t, http.StatusOK, status, body)

	// Header secret + body JWT assertion is invalid_request, never one-of.
	basicID := "ambiguity-client"
	basicSecret := "ambiguity-secret-123"
	status, _, body = createAdminClient(t, env.admin, map[string]any{
		"client_id":                  basicID,
		"client_secret":              basicSecret,
		"token_endpoint_auth_method": clientauth.MethodClientSecretBasic,
		"grant_types":                []string{"client_credentials"},
	})
	require.Equal(t, http.StatusCreated, status, body)
	assertion := "SENSITIVE_CLIENT_ASSERTION_HEADER.PAYLOAD.SIGNATURE"
	ambiguousForm := url.Values{
		"grant_type":            {"client_credentials"},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {assertion},
	}
	headers := http.Header{}
	headers.Set("Authorization", "Basic "+basicAuthHeader(basicID, basicSecret))
	status, body = doForm(t, env.tokenURL(), ambiguousForm, headers)
	assert.Equal(t, http.StatusBadRequest, status, body)
	assert.Contains(t, body, `"error":"invalid_request"`)
	errorBodies = append(errorBodies, body)
	assert.Equal(t, clientauth.CategoryAmbiguousCredential, lastCategory(t, env.capture, basicID, ""))

	// Stock data with an unsupported method fails closed without 500.
	unsupportedID := "stock-unsupported-method"
	unsupportedSecret := "stock-unsupported-secret"
	require.NoError(t, env.reg.ClientManager().CreateClient(ctx, &client.Client{
		ID:                      unsupportedID,
		Secret:                  unsupportedSecret,
		TokenEndpointAuthMethod: "ancient_removed_method",
		GrantTypes:              []string{"client_credentials"},
	}))
	status, body = doForm(t, env.tokenURL(), url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {unsupportedID},
		"client_secret": {unsupportedSecret},
	}, nil)
	assert.Equal(t, http.StatusUnauthorized, status, body)
	assert.Contains(t, body, `"error":"invalid_client"`)
	assert.NotContains(t, body, "ancient_removed_method")
	errorBodies = append(errorBodies, body)
	assert.Equal(t, clientauth.CategoryUnknownMethod, lastCategory(t, env.capture, unsupportedID, "ancient_removed_method"))

	// Rotation eligibility is declaration-derived.
	req, err := http.NewRequest(http.MethodPost, env.admin.URL+"/admin/clients/"+customClientID+"/secrets/rotate", nil)
	require.NoError(t, err)
	res, err := http.DefaultClient.Do(req) //nolint:gosec
	require.NoError(t, err)
	defer res.Body.Close()
	rotationBody, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, res.StatusCode, string(rotationBody))
	assert.Contains(t, string(rotationBody), "does not support client secret rotation")
	assert.Contains(t, string(rotationBody), customMethodID)

	// Negative audit/log/response leakage assertions.
	auditRaw, err := json.Marshal(env.capture.Events())
	require.NoError(t, err)
	logs := fmt.Sprint(env.logHook.AllEntries())
	basicHeader := "Basic " + basicAuthHeader(basicID, basicSecret)
	sensitive := []string{customSecret, "wrong-custom-secret", basicSecret, unsupportedSecret, assertion, basicHeader}
	for _, secret := range sensitive {
		assert.NotContains(t, string(auditRaw), secret, "audit event leaked sensitive material")
		assert.NotContains(t, logs, secret, "logs leaked sensitive material")
		for _, responseBody := range errorBodies {
			assert.NotContains(t, responseBody, secret, "error response leaked sensitive material")
		}
	}
}

func TestClientAuthFrameworkDisableAndReenableBuiltin(t *testing.T) {
	ctx := context.Background()
	env := setupAcceptance(t)

	id := "disable-basic-client"
	secret := "disable-basic-secret"
	status, _, body := createAdminClient(t, env.admin, map[string]any{
		"client_id":                  id,
		"client_secret":              secret,
		"token_endpoint_auth_method": clientauth.MethodClientSecretBasic,
		"grant_types":                []string{"client_credentials"},
	})
	require.Equal(t, http.StatusCreated, status, body)

	headers := http.Header{}
	headers.Set("Authorization", "Basic "+basicAuthHeader(id, secret))
	tokenForm := url.Values{"grant_type": {"client_credentials"}}
	status, body = doForm(t, env.tokenURL(), tokenForm, headers)
	require.Equal(t, http.StatusOK, status, body)

	env.reg.Config().MustSet(ctx, config.KeyOAuth2ClientAuthenticationEnabledMethods, []string{
		clientauth.MethodClientSecretPost,
		clientauth.MethodPrivateKeyJWT,
		clientauth.MethodNone,
	})

	methods := discoveryMethods(t, env.public)
	assert.NotContains(t, methods, clientauth.MethodClientSecretBasic)
	assert.Equal(t, []string{clientauth.MethodClientSecretPost, clientauth.MethodNone, clientauth.MethodPrivateKeyJWT}, methods)

	status, _, body = createAdminClient(t, env.admin, map[string]any{
		"client_id":                  "basic-now-disabled",
		"token_endpoint_auth_method": clientauth.MethodClientSecretBasic,
	})
	assert.Equal(t, http.StatusBadRequest, status, body)
	assert.Contains(t, body, "invalid_client_metadata")

	updateRaw, err := json.Marshal(map[string]any{"token_endpoint_auth_method": clientauth.MethodClientSecretBasic})
	require.NoError(t, err)
	updateReq, err := http.NewRequest(http.MethodPut, env.admin.URL+"/admin/clients/"+id, bytes.NewReader(updateRaw))
	require.NoError(t, err)
	updateReq.Header.Set("Content-Type", "application/json")
	updateRes, err := http.DefaultClient.Do(updateReq) //nolint:gosec
	require.NoError(t, err)
	updateBody, err := io.ReadAll(updateRes.Body)
	updateRes.Body.Close()
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, updateRes.StatusCode, string(updateBody))
	assert.Contains(t, string(updateBody), "invalid_client_metadata")

	status, body = doForm(t, env.tokenURL(), tokenForm, headers)
	assert.Equal(t, http.StatusUnauthorized, status, body)
	assert.Contains(t, body, `"error":"invalid_client"`)
	assert.Equal(t, clientauth.CategoryMethodDisabled, lastCategory(t, env.capture, id, clientauth.MethodClientSecretBasic))

	// Configuration changes take effect on the next request.
	env.reg.Config().Delete(ctx, config.KeyOAuth2ClientAuthenticationEnabledMethods)
	status, body = doForm(t, env.tokenURL(), tokenForm, headers)
	assert.Equal(t, http.StatusOK, status, body)
}

func TestClientAuthFrameworkEmptySet(t *testing.T) {
	ctx := context.Background()
	env := setupAcceptance(t)

	id := "empty-set-client"
	secret := "empty-set-secret"
	status, _, body := createAdminClient(t, env.admin, map[string]any{
		"client_id":                  id,
		"client_secret":              secret,
		"token_endpoint_auth_method": clientauth.MethodClientSecretBasic,
		"grant_types":                []string{"client_credentials"},
	})
	require.Equal(t, http.StatusCreated, status, body)

	env.reg.Config().MustSet(ctx, config.KeyOAuth2ClientAuthenticationEnabledMethods, []string{})
	assert.Empty(t, discoveryMethods(t, env.public))

	status, _, body = createAdminClient(t, env.admin, map[string]any{
		"client_id":                  "empty-set-new-client",
		"token_endpoint_auth_method": clientauth.MethodClientSecretBasic,
	})
	assert.Equal(t, http.StatusBadRequest, status, body)
	assert.Contains(t, body, "invalid_client_metadata")

	headers := http.Header{}
	headers.Set("Authorization", "Basic "+basicAuthHeader(id, secret))
	status, body = doForm(t, env.tokenURL(), url.Values{"grant_type": {"client_credentials"}}, headers)
	assert.Equal(t, http.StatusUnauthorized, status, body)
	assert.Contains(t, body, `"error":"invalid_client"`)
	assert.Equal(t, clientauth.CategoryConfigurationError, lastCategory(t, env.capture, id, clientauth.MethodClientSecretBasic))
}

func basicAuthHeader(id, secret string) string {
	return base64.StdEncoding.EncodeToString([]byte(id + ":" + secret))
}

func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}
