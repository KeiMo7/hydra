// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package clientauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/ory/hydra/v2/fosite"
)

// AuthFailure is an optional typed error a Method can return to influence the
// internal audit category. Its public OAuth2 mapping is always a generic
// invalid_client response.
type AuthFailure struct {
	ClientID string
	Category FailureCategory
}

func (e *AuthFailure) Error() string {
	if e == nil || e.Category == "" {
		return string(CategoryVerificationFailed)
	}
	return string(e.Category)
}

// RequestMatcher is an optional Method extension for credentials whose client
// identifier is not in the standard Authorization header, client_id form field
// or JWT subject. It only detects/parses the request; it must not verify.
type RequestMatcher interface {
	MatchRequest(r *http.Request, form url.Values) (clientID string, matches bool)
}

type credentialCarrier string

const (
	carrierNone      credentialCarrier = "none"
	carrierBasic     credentialCarrier = "client_secret_basic"
	carrierPost      credentialCarrier = "client_secret_post"
	carrierAssertion credentialCarrier = "client_assertion"
)

type authMethodCarrier interface {
	GetTokenEndpointAuthMethod() string
}

func clientAuthMethod(client fosite.Client) string {
	if carrier, ok := client.(authMethodCarrier); ok {
		if method := carrier.GetTokenEndpointAuthMethod(); method != "" {
			return method
		}
	}
	return MethodClientSecretBasic
}

// Authenticate is the single endpoint decision function used by token,
// revocation, device and fallback endpoints through Fosite's client
// authentication strategy hook.
func (r *Registry) Authenticate(ctx context.Context, req *http.Request, form url.Values) (client fosite.Client, retErr error) {
	snap := r.Snapshot(ctx)
	ctx = WithSnapshot(ctx, snap)

	ev := Event{Endpoint: endpointName(req)}
	var category FailureCategory

	defer func() {
		if recovered := recover(); recovered != nil {
			client = nil
			retErr = fosite.ErrInvalidClient
			category = CategoryMethodPanic
			if ev.Method == "" {
				ev.Method = "unknown"
			}
		}

		if category == "" {
			if retErr == nil {
				category = CategorySuccess
			} else {
				category = CategorizeError(retErr)
			}
		}

		ev.Category = category
		ev.Success = retErr == nil && category == CategorySuccess
		r.emit(ctx, ev)
	}()

	if req == nil {
		category = CategoryInvalidRequest
		return nil, fosite.ErrInvalidRequest
	}
	if form == nil {
		if err := req.ParseForm(); err != nil {
			category = CategoryMalformedCredential
			return nil, fosite.ErrInvalidRequest.WithHint("The request form could not be parsed.")
		}
		form = req.Form
	}

	basicID, basicSecret, basicOK := req.BasicAuth()
	if basicOK {
		if _, err := url.QueryUnescape(basicID); err != nil {
			category = CategoryMalformedCredential
			return nil, fosite.ErrInvalidRequest.WithHint("The client id in the HTTP authorization header could not be decoded from 'application/x-www-form-urlencoded'.")
		}
		if _, err := url.QueryUnescape(basicSecret); err != nil {
			category = CategoryMalformedCredential
			return nil, fosite.ErrInvalidRequest.WithHint("The client secret in the HTTP authorization header could not be decoded from 'application/x-www-form-urlencoded'.")
		}
	}
	basicSecretPresent := basicOK && basicSecret != ""
	postSecretPresent := form.Get("client_secret") != ""
	assertionPresent := form.Get("client_assertion") != "" || form.Get("client_assertion_type") != ""
	ev.ClientID = candidateClientID(req, form, basicID, basicOK)

	// RFC 6749 / client authentication uniqueness: never choose between an
	// Authorization-header secret and a body JWT assertion or body secret.
	if assertionPresent && (basicSecretPresent || postSecretPresent) {
		category = CategoryAmbiguousCredential
		return nil, fosite.ErrInvalidRequest.WithHint("More than one client authentication credential was provided. Send exactly one client authentication method.")
	}

	carrier := detectCarrier(basicSecretPresent, postSecretPresent, assertionPresent)

	clientID := ev.ClientID
	if clientID == "" {
		if id, ok := r.matchCustomClientID(ctx, snap, req, form); ok {
			clientID = id
		}
	}
	ev.ClientID = clientID

	var cl fosite.Client
	var lookup ClientLookup
	if clientID != "" {
		r.mu.RLock()
		lookup = r.clients
		r.mu.RUnlock()
		if lookup != nil {
			var err error
			cl, err = lookup.GetClient(ctx, clientID)
			if err != nil {
				// Security boundary: unknown client and backend lookup failure
				// have the same external response. Audit keeps the distinction.
				if errors.Is(err, fosite.ErrNotFound) || isNotFoundError(err) {
					category = CategoryClientNotFound
				} else {
					category = CategoryClientLookupFailed
					if r.logger != nil {
						r.logger.Errorf("clientauth: client lookup failed: %v", sanitizeError(err))
					}
				}
				return nil, fosite.ErrInvalidClient
			}
		}
	}

	if cl != nil {
		client = cl
		methodID := clientAuthMethod(cl)
		if methodID == "" {
			methodID = MethodClientSecretBasic
		}
		ev.Method = methodID

		if snap.configError != nil {
			category = CategoryConfigurationError
			return nil, fosite.ErrInvalidClient
		}

		method, registered := r.Method(methodID)
		if !registered {
			category = CategoryUnknownMethod
			return nil, fosite.ErrInvalidClient
		}
		if !snap.Has(methodID) {
			category = CategoryMethodDisabled
			return nil, fosite.ErrInvalidClient
		}

		// Verify that the presented credential carrier belongs to the
		// client's registered method before invoking it. This is the
		// no-downgrade boundary: disabling the registered method cannot be
		// bypassed with another valid credential.
		if c := carrierCategoryMismatch(method.Descriptor(), methodID, carrier); c != "" {
			category = c
			return nil, fosite.ErrInvalidClient
		}

		if isLegacyMethod(methodID) {
			r.mu.RLock()
			legacy := r.legacy
			r.mu.RUnlock()
			if legacy == nil {
				category = CategoryMethodError
				return nil, fosite.ErrInvalidClient
			}
			out, err := legacy(ctx, req, form)
			if err != nil {
				category = classifyBuiltinError(err, methodID, carrier)
				return nil, normalizeAuthError(err)
			}
			category = CategorySuccess
			return out, nil
		}

		if lookup == nil {
			r.mu.RLock()
			lookup = r.clients
			r.mu.RUnlock()
		}
		in := &AuthenticationInput{
			HTTPRequest: req,
			Form:        form,
			Client:      cl,
			Snapshot:    snap,
			Clients:     lookup,
		}
		out, err := r.invokeMethod(ctx, method, in)
		if err != nil {
			var af *AuthFailure
			if errors.As(err, &af) && af != nil && af.Category != "" {
				category = af.Category
				if af.ClientID != "" {
					ev.ClientID = af.ClientID
				}
			} else {
				category = CategoryVerificationFailed
			}
			return nil, fosite.ErrInvalidClient
		}
		if out == nil {
			category = CategoryMethodError
			return nil, fosite.ErrInvalidClient
		}
		if clientAuthMethod(out) != methodID {
			category = CategoryMethodMismatch
			return nil, fosite.ErrInvalidClient
		}
		category = CategorySuccess
		return out, nil
	}

	if snap.configError != nil {
		category = CategoryConfigurationError
		return nil, fosite.ErrInvalidClient
	}

	// No prefetched client: preserve Fosite's historical resolution and error
	// behavior for built-in and edge-case requests.
	r.mu.RLock()
	legacy := r.legacy
	r.mu.RUnlock()
	if legacy == nil {
		category = CategoryNoCredentials
		return nil, fosite.ErrInvalidClient
	}
	out, err := legacy(ctx, req, form)
	if err != nil {
		category = CategorizeError(err)
		return nil, normalizeAuthError(err)
	}
	if out != nil {
		ev.ClientID = out.GetID()
		ev.Method = clientAuthMethod(out)
	}
	category = CategorySuccess
	return out, nil
}

func (r *Registry) invokeMethod(ctx context.Context, method Method, in *AuthenticationInput) (out fosite.Client, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = &AuthFailure{Category: CategoryMethodPanic}
			if r.logger != nil {
				// Do not log the recovered value: it may contain credential
				// material supplied by a buggy third-party method.
				r.logger.Errorf("clientauth: method %q panicked", method.Descriptor().ID)
			}
		}
	}()
	return method.Authenticate(ctx, in)
}

func (r *Registry) matchCustomClientID(ctx context.Context, snap *Snapshot, req *http.Request, form url.Values) (string, bool) {
	if req == nil {
		return "", false
	}
	var foundID string
	matches := 0
	for _, id := range snap.IDs() {
		method, ok := snap.Get(id)
		if !ok || isLegacyMethod(id) {
			continue
		}
		matcher, ok := method.(RequestMatcher)
		if !ok {
			continue
		}
		func() {
			defer func() { _ = recover() }()
			if clientID, matched := matcher.MatchRequest(req, form); matched {
				matches++
				foundID = clientID
			}
		}()
	}
	if matches == 1 {
		return foundID, true
	}
	return "", false
}

func endpointName(req *http.Request) string {
	if req == nil || req.URL == nil {
		return ""
	}
	path := req.URL.Path
	switch {
	case strings.Contains(path, "/revoke"):
		return "revocation"
	case strings.Contains(path, "/device/auth"):
		return "device_authorization"
	case strings.Contains(path, "/token"):
		return "token"
	default:
		return path
	}
}

func detectCarrier(basicSecretPresent, postSecretPresent, assertionPresent bool) credentialCarrier {
	// An empty-password Basic header is an identifier carrier only. This keeps
	// the historical public-client behavior. When real secrets are present,
	// Fosite's Basic precedence is retained.
	if basicSecretPresent {
		return carrierBasic
	}
	if postSecretPresent {
		return carrierPost
	}
	if assertionPresent {
		return carrierAssertion
	}
	return carrierNone
}

func candidateClientID(req *http.Request, form url.Values, basicID string, basicOK bool) string {
	if basicOK && basicID != "" {
		if id, err := url.QueryUnescape(basicID); err == nil {
			return id
		}
		return basicID
	}
	if id := form.Get("client_id"); id != "" {
		return id
	}
	if assertion := form.Get("client_assertion"); assertion != "" {
		if id := unverifiedAssertionSubject(assertion); id != "" {
			return id
		}
	}
	return ""
}

func unverifiedAssertionSubject(assertion string) string {
	parts := strings.Split(assertion, ".")
	if len(parts) < 2 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		if payload, err = base64.URLEncoding.DecodeString(parts[1]); err != nil {
			return ""
		}
	}
	var claims struct {
		Sub string `json:"sub"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return ""
	}
	return claims.Sub
}

func carrierCategoryMismatch(d Descriptor, methodID string, carrier credentialCarrier) FailureCategory {
	switch methodID {
	case MethodClientSecretBasic:
		if carrier != carrierNone && carrier != carrierBasic {
			return CategoryMethodMismatch
		}
	case MethodClientSecretPost:
		if carrier != carrierNone && carrier != carrierPost {
			return CategoryMethodMismatch
		}
	case MethodPrivateKeyJWT:
		if carrier != carrierNone && carrier != carrierAssertion {
			return CategoryMethodMismatch
		}
	case MethodNone:
		if carrier != carrierNone {
			return CategoryMethodMismatch
		}
	default:
		switch d.CredentialType {
		case CredentialSharedSecret:
			if carrier == carrierAssertion {
				return CategoryMethodMismatch
			}
		case CredentialPublicKey:
			if carrier != carrierNone && carrier != carrierAssertion {
				return CategoryMethodMismatch
			}
		case CredentialNone:
			if carrier != carrierNone {
				return CategoryMethodMismatch
			}
		}
	}
	return ""
}

func isLegacyMethod(id string) bool {
	switch id {
	case MethodClientSecretBasic, MethodClientSecretPost, MethodPrivateKeyJWT, MethodNone:
		return true
	}
	return false
}

func normalizeAuthError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, fosite.ErrInvalidClient) {
		// Remove hints, wraps and debug details so unknown client, bad secret
		// and method mismatch have one stable external representation.
		return fosite.ErrInvalidClient
	}
	return err
}

// CategorizeError maps an error into a stable internal audit category.
func CategorizeError(err error) FailureCategory {
	switch {
	case err == nil:
		return CategorySuccess
	case errors.Is(err, fosite.ErrInvalidClient):
		return CategoryInvalidClient
	case errors.Is(err, fosite.ErrInvalidRequest):
		return CategoryInvalidRequest
	case errors.Is(err, fosite.ErrJTIKnown):
		return CategoryReplayDetected
	default:
		return CategoryVerificationFailed
	}
}

func classifyBuiltinError(err error, methodID string, carrier credentialCarrier) FailureCategory {
	if errors.Is(err, fosite.ErrJTIKnown) {
		return CategoryReplayDetected
	}
	if errors.Is(err, fosite.ErrInvalidRequest) {
		return CategoryInvalidRequest
	}
	if errors.Is(err, fosite.ErrInvalidClient) {
		switch methodID {
		case MethodClientSecretBasic, MethodClientSecretPost:
			if carrier == carrierBasic || carrier == carrierPost || carrier == carrierNone {
				return CategoryInvalidSecret
			}
			return CategoryMethodMismatch
		case MethodPrivateKeyJWT:
			return CategoryInvalidAssertion
		case MethodNone:
			return CategoryMethodMismatch
		default:
			return CategoryInvalidClient
		}
	}
	return CategorizeError(err)
}

func isNotFoundError(err error) bool {
	type notFound interface{ IsNotFound() bool }
	var nf notFound
	return errors.As(err, &nf) && nf.IsNotFound()
}

// sanitizeError currently avoids placing third-party error text into structured
// logs. It exists as the single point for future redaction.
func sanitizeError(err error) error {
	if err == nil {
		return nil
	}
	return errors.New("authentication backend error")
}
