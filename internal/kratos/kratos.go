// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package kratos

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/pkg/errors"
	"go.opentelemetry.io/otel/attribute"

	"github.com/ory/x/logrusx"

	"github.com/ory/hydra/v2/driver/config"
	"github.com/ory/hydra/v2/fosite"
	"github.com/ory/hydra/v2/x/loginstats"
	client "github.com/ory/kratos-client-go"
	"github.com/ory/x/httpx"
	"github.com/ory/x/otelx"
)

type (
	dependencies interface {
		config.Provider
		httpx.ClientProvider
		otelx.Provider
		logrusx.Provider
	}
	Provider interface {
		Kratos() Client
	}
	Client interface {
		DisableSession(ctx context.Context, identityProviderSessionID string) error
		Authenticate(ctx context.Context, name, secret string) (*client.Session, error)
	}
	Default struct {
		dependencies
	}
)

func New(d dependencies) Client {
	return &Default{dependencies: d}
}

func (k *Default) Authenticate(ctx context.Context, name, secret string) (session *client.Session, err error) {
	ctx, span := k.Tracer(ctx).Tracer().Start(ctx, "kratos.Authenticate")
	defer otelx.End(span, &err)

	publicURL, ok := k.Config().KratosPublicURL(ctx)
	span.SetAttributes(attribute.String("public_url", fmt.Sprintf("%+v", publicURL)))
	if !ok {
		span.SetAttributes(attribute.Bool("skipped", true))
		span.SetAttributes(attribute.String("reason", "kratos public url not set"))

		return nil, errors.New("kratos public url not set")
	}

	kratos := k.newKratosClient(ctx, publicURL)

	flow, _, err := kratos.FrontendAPI.CreateNativeLoginFlow(ctx).Execute()
	if err != nil {
		return nil, err
	}

	res, _, err := kratos.FrontendAPI.UpdateLoginFlow(ctx).Flow(flow.Id).UpdateLoginFlowBody(client.UpdateLoginFlowBody{
		UpdateLoginFlowWithPasswordMethod: &client.UpdateLoginFlowWithPasswordMethod{
			Method:     "password",
			Identifier: name,
			Password:   secret,
		},
	}).Execute()
	if err != nil {
		// The outward contract is unchanged: every credential failure keeps
		// surfacing as fosite.ErrNotFound, which the ROPC grant turns into the
		// same invalid_grant response for both unknown accounts and bad
		// passwords. The internal cause is attached to the error chain so the
		// login-attempt classifier can keep operational granularity (and tell a
		// dependency outage apart from a genuine rejection) without opening an
		// account-enumeration channel on the HTTP response.
		return nil, fosite.ErrNotFound.WithWrap(classifyLoginError(err))
	}

	return &res.Session, nil
}

// classifyLoginError translates a Kratos native-login API failure into an
// internal sentinel while preserving the original error as the wrapped cause.
// It never changes what the caller eventually returns to the OAuth2 client.
func classifyLoginError(err error) error {
	var apiErr client.GenericOpenAPIError
	if !errors.As(err, &apiErr) {
		// No HTTP response (DNS, connection refused, timeout, ...): an
		// infrastructure condition, not a credential problem.
		return joinError{outer: loginstats.ErrBackendUnavailable, inner: err}
	}

	status := effectiveStatus(apiErr)

	// A 5xx response means the identity backend could not adjudicate the
	// credentials. It must not be counted as a wrong password.
	if status >= 500 {
		return joinError{outer: loginstats.ErrBackendUnavailable, inner: err}
	}

	// 4xx responses are adjudicated credential failures. The structured error
	// id, when the body is parseable, separates an unknown identifier from a
	// bad password internally; otherwise the conservative credential default
	// applies.
	switch loginReasonFromBody(apiErr.Body()) {
	case "identifier_unknown", "account_not_found":
		return joinError{outer: loginstats.ErrCredentialAccountUnknown, inner: err}
	case "credentials_invalid", "password_violation", "error_validation":
		return joinError{outer: loginstats.ErrCredentialPasswordBad, inner: err}
	default:
		// Conservative default: any other 4xx is still a credential rejection,
		// never an outage.
		return joinError{outer: loginstats.ErrCredentialPasswordBad, inner: err}
	}
}

// effectiveStatus resolves the HTTP status code even when the SDK could not
// decode the body. It prefers the structured code in the JSON payload and
// falls back to the status text the SDK stores in GenericOpenAPIError.Error().
func effectiveStatus(apiErr client.GenericOpenAPIError) int {
	if code := httpStatusFromBody(apiErr.Body()); code > 0 {
		return code
	}
	return statusFromText(apiErr.Error())
}

// statusFromText extracts a leading three-digit HTTP code from strings like
// "400 Bad Request". It returns 0 when no code is present.
func statusFromText(status string) int {
	if len(status) < 3 {
		return 0
	}
	code := 0
	for i := 0; i < 3; i++ {
		d := status[i] - '0'
		if d > 9 {
			return 0
		}
		code = code*10 + int(d)
	}
	return code
}

// joinError keeps both the internal classification sentinel and the original
// SDK error in a single chain, so errors.Is can find either.
type joinError struct {
	outer, inner error
}

func (e joinError) Error() string   { return e.outer.Error() + ": " + e.inner.Error() }
func (e joinError) Unwrap() []error { return []error{e.outer, e.inner} }

// loginErrorBody is the subset of the Kratos error payload we inspect. Fields
// are optional, so every access is nil-safe.
type loginErrorBody struct {
	Error *struct {
		ID      string                 `json:"id"`
		Reason  string                 `json:"reason"`
		Code    int                    `json:"code"`
		Details map[string]interface{} `json:"details"`
	} `json:"error"`
}

func httpStatusFromBody(body []byte) int {
	var parsed loginErrorBody
	if err := json.Unmarshal(body, &parsed); err != nil || parsed.Error == nil {
		return 0
	}
	return parsed.Error.Code
}

func loginReasonFromBody(body []byte) string {
	var parsed loginErrorBody
	if err := json.Unmarshal(body, &parsed); err != nil || parsed.Error == nil {
		return ""
	}
	return parsed.Error.ID
}

func (k *Default) DisableSession(ctx context.Context, identityProviderSessionID string) (err error) {
	ctx, span := k.Tracer(ctx).Tracer().Start(ctx, "kratos.DisableSession")
	defer otelx.End(span, &err)

	adminURL, ok := k.Config().KratosAdminURL(ctx)
	span.SetAttributes(attribute.String("admin_url", fmt.Sprintf("%+v", adminURL)))
	if !ok {
		span.SetAttributes(attribute.Bool("skipped", true))
		span.SetAttributes(attribute.String("reason", "kratos admin url not set"))

		return nil
	}

	if identityProviderSessionID == "" {
		span.SetAttributes(attribute.Bool("skipped", true))
		span.SetAttributes(attribute.String("reason", "kratos session ID is empty"))

		return nil
	}

	configuration := k.clientConfiguration(ctx, adminURL)
	if header := k.Config().KratosRequestHeader(ctx); header != nil {
		configuration.HTTPClient.Transport = httpx.WrapTransportWithHeader(configuration.HTTPClient.Transport, header)
	}
	kratos := client.NewAPIClient(configuration)
	_, err = kratos.IdentityAPI.DisableSession(ctx, identityProviderSessionID).Execute()

	return err
}

func (k *Default) clientConfiguration(ctx context.Context, adminURL *url.URL) *client.Configuration {
	configuration := client.NewConfiguration()
	configuration.Servers = client.ServerConfigurations{{URL: adminURL.String()}}
	configuration.HTTPClient = k.HTTPClient(ctx).StandardClient()

	return configuration
}

func (k *Default) newKratosClient(ctx context.Context, publicURL *url.URL) *client.APIClient {
	configuration := k.clientConfiguration(ctx, publicURL)
	if header := k.Config().KratosRequestHeader(ctx); header != nil {
		configuration.HTTPClient.Transport = httpx.WrapTransportWithHeader(configuration.HTTPClient.Transport, header)
	}
	kratos := client.NewAPIClient(configuration)
	return kratos
}
