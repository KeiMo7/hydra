// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package loginstats

import (
	"context"
	stderr "errors"
	"net"
	"strings"

	"github.com/ory/hydra/v2/fosite"
)

// Classify maps an attempt error (nil for success) to exactly one [Reason].
// The mapping is deterministic: the same (hint, err) pair always yields the
// same reason, and [reasonOrder] documents which rule wins when several
// signals are present.
//
// Classification never inspects, logs or returns caller-supplied identifiers.
// It only looks at error types, RFC6749 error codes and the optional [Hint].
func Classify(err error, hint Hint) Reason {
	if err == nil {
		if hint.Reason == ReasonPending || hint.Reason == ReasonSlowDown {
			return hint.Reason
		}
		return ReasonSuccess
	}

	// 1. Infrastructure conditions win over everything else. A storage
	//    outage or timeout must never be labelled as a bad password.
	switch {
	case stderr.Is(err, ErrBackendTimeout), isTimeout(err):
		return ReasonBackendTimeout
	case stderr.Is(err, ErrBackendUnavailable):
		return ReasonBackendUnavailable
	}

	// 2. Internal credential/client sentinels. These carry the operational
	//    granularity that the external RFC error deliberately hides.
	switch {
	case stderr.Is(err, ErrCredentialAccountUnknown):
		return ReasonCredentialAccountUnknown
	case stderr.Is(err, ErrCredentialPasswordBad):
		return ReasonCredentialPasswordBad
	case stderr.Is(err, ErrClientUnknown):
		return ReasonClientUnknown
	case stderr.Is(err, ErrClientSecretMismatch):
		return ReasonClientSecretMismatch
	}

	// 3. RFC6749 error-code matching. The table is the single place that
	//    translates protocol errors into the internal taxonomy.
	rfc := fosite.ErrorToRFC6749Error(err)
	reason, knownCode := rfcCodeToReason[rfc.ErrorField]
	if !knownCode {
		// 4. A bare network error that was not wrapped in an RFC error still
		//    represents infrastructure, not a credential problem.
		if isNetworkError(err) {
			return ReasonBackendUnavailable
		}
		reason = ReasonUnknown
	}

	// 5. An entry-layer hint may refine a generic protocol reason to a more
	//    specific one within the same category (e.g. invalid_request ->
	//    missing field, invalid_grant -> unknown account). It can never move
	//    an attempt across categories, and unknown hint values are ignored so
	//    a hint cannot introduce an unbounded label.
	if hint.Reason != "" && hint.Reason.refines(reason) {
		return hint.Reason
	}
	return reason
}

// refines reports whether r is a strictly more specific reason within the
// same category as fallback. It keeps hint-based refinement inside one
// category, so a malformed-request hint can never relabel a scope failure.
func (r Reason) refines(fallback Reason) bool {
	if r == fallback {
		return true
	}
	return r.Category() == fallback.Category() && r != ReasonUnknown
}

// rfcCodeToReason maps OAuth2 error codes (the [fosite.RFC6749Error]
// ErrorField values) to the internal reason. Codes that share an entry are
// indistinguishable at the protocol layer and are split, when needed, via
// internal sentinels or entry-layer hints.
var rfcCodeToReason = map[string]Reason{
	// Device flow control answers (not failures).
	"authorization_pending": ReasonPending,
	"slow_down":             ReasonSlowDown,
	"expired_token":         ReasonDeviceCodeExpired,

	// Request shape.
	"invalid_request":            ReasonRequestMalformedOther,
	"invalid_state":              ReasonRequestMalformedOther,
	"insufficient_entropy":       ReasonRequestMalformedOther,
	"request_not_supported":      ReasonRequestMalformedOther,
	"request_uri_not_supported":  ReasonRequestMalformedOther,
	"registration_not_supported": ReasonRequestMalformedOther,
	"invalid_request_uri":        ReasonRequestMalformedOther,
	"invalid_request_object":     ReasonRequestMalformedOther,
	"unsupported_response_mode":  ReasonRequestMalformedOther,

	// Client identity.
	"invalid_client":            ReasonClientSecretMismatch,
	"unauthorized_client":       ReasonClientGrantNotAllowed,
	"unsupported_grant_type":    ReasonClientGrantNotAllowed,
	"unsupported_response_type": ReasonClientGrantNotAllowed,

	// Scope / audience.
	"invalid_scope":     ReasonScopeExceedsClient,
	"scope_not_granted": ReasonScopeExceedsClient,

	// Resource-owner / device-user decisions.
	"access_denied":     ReasonDeviceUserDenied,
	"request_forbidden": ReasonDeviceUserDenied,

	// Grant / token problems at exchange and refresh time.
	"invalid_grant":            ReasonGrantExpiredOrRevoked,
	"token_signature_mismatch": ReasonGrantMalformed,
	"invalid_token":            ReasonGrantMalformed,
	"token_inactive":           ReasonGrantExpiredOrRevoked,
	"token_claim":              ReasonGrantMalformed,
	"jti_known":                ReasonGrantMalformed,

	// Infrastructure.
	"server_error":            ReasonBackendUnavailable,
	"temporarily_unavailable": ReasonBackendUnavailable,
	"misconfiguration":        ReasonBackendUnavailable,
}

// isTimeout recognises context deadlines and net timeouts anywhere in the
// chain. A timeout is a backend condition, never a credential rejection.
func isTimeout(err error) bool {
	if stderr.Is(err, context.DeadlineExceeded) {
		return true
	}
	var ne net.Error
	if stderr.As(err, &ne) && ne.Timeout() {
		return true
	}
	return false
}

// isNetworkError catches dial/DNS/connection failures that reached the handler
// without being wrapped in an RFC error.
func isNetworkError(err error) bool {
	var opErr *net.OpError
	if stderr.As(err, &opErr) {
		return true
	}
	var dnsErr *net.DNSError
	if stderr.As(err, &dnsErr) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "no such host") ||
		strings.Contains(msg, "connection reset")
}
