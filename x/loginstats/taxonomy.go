// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

// Package loginstats turns the outcome of every login-related attempt across
// the OAuth2 entry points (authorization, token, device) into a single,
// explainable failure taxonomy.
//
// The package is intentionally self-contained: it depends neither on the
// fosite handlers nor on the HTTP layer, so the exact same classification is
// used to compute Prometheus metrics and structured audit events. Every label
// that can carry caller-controlled data is bounded (see account.go and
// source.go), which keeps the cardinality of the exported series finite under
// adversarial input.
package loginstats

// Outcome is the high-level result of an attempt. It is always derived from
// the classified [Reason], never recorded independently, so metrics and
// events can never disagree about whether an attempt succeeded.
type Outcome string

const (
	// OutcomeSuccess marks a completed attempt.
	OutcomeSuccess Outcome = "success"
	// OutcomeFailure marks an attempt that terminated with an error.
	OutcomeFailure Outcome = "failure"
	// OutcomePending marks a non-terminal protocol answer such as the device
	// flow "authorization_pending" polling response. These are neither
	// successes nor failures and must not be alerted on as failures.
	OutcomePending Outcome = "pending"
)

// Category is the coarse, closed-set failure family used by dashboards. Every
// [Reason] maps to exactly one category. The set of categories is fixed in
// code, which guarantees a bounded label cardinality regardless of input.
type Category string

const (
	CategorySuccess    Category = "success"
	CategoryPending    Category = "pending"
	CategoryCredential Category = "credential_rejected"
	CategoryClient     Category = "client_rejected"
	CategoryRequest    Category = "request_malformed"
	CategoryScope      Category = "scope_denied"
	CategoryDevice     Category = "device_user_decision"
	CategoryGrant      Category = "grant_invalid"
	CategoryBackend    Category = "backend_unavailable"
	CategoryUnknown    Category = "unknown"
)

// Reason is the fine-grained, explainable cause of an attempt outcome. The
// string values are the stable wire format used in metric labels and audit
// event attributes; do not rename them.
//
// External responses are never derived from these values. In particular the
// two credential reasons share the same outward-facing invalid_grant error,
// so the distinction cannot be used as an account-enumeration channel.
type Reason string

const (
	ReasonSuccess  Reason = "success"
	ReasonPending  Reason = "authorization_pending"
	ReasonSlowDown Reason = "slow_down"

	// Credential failures. Both surface externally as invalid_grant.
	ReasonCredentialAccountUnknown Reason = "credential_account_unknown"
	ReasonCredentialPasswordBad    Reason = "credential_password_bad"

	// Client identity failures.
	ReasonClientUnknown         Reason = "client_unknown"
	ReasonClientSecretMismatch  Reason = "client_secret_mismatch"
	ReasonClientGrantNotAllowed Reason = "client_grant_not_allowed"
	ReasonClientAuthMethodBad   Reason = "client_auth_method_not_allowed"

	// Request shape failures.
	ReasonRequestFieldMissing   Reason = "request_field_missing"
	ReasonRequestParameterDup   Reason = "request_parameter_duplicated"
	ReasonRequestEncodingBad    Reason = "request_encoding_invalid"
	ReasonRequestBodyTruncated  Reason = "request_body_truncated"
	ReasonRequestMalformedOther Reason = "request_malformed"

	// Scope / audience failures.
	ReasonScopeExceedsClient Reason = "scope_or_audience_exceeds_client"

	// Device confirmation step.
	ReasonDeviceUserDenied    Reason = "device_user_denied"
	ReasonDeviceUserCodeBad   Reason = "device_user_code_invalid"
	ReasonDeviceCodeExpired   Reason = "device_code_expired"
	ReasonDeviceUserCancelled Reason = "device_user_cancelled"

	// Token exchange / refresh.
	ReasonGrantExpiredOrRevoked Reason = "grant_expired_or_revoked"
	ReasonGrantClientMismatch   Reason = "grant_client_not_allowed"
	ReasonGrantMalformed        Reason = "grant_malformed"

	// Backend / infrastructure.
	ReasonBackendTimeout     Reason = "backend_timeout"
	ReasonBackendUnavailable Reason = "backend_unavailable"

	// Anything that could not be classified.
	ReasonUnknown Reason = "unknown"
)

// categoryOf is the single source of truth for the reason -> category mapping.
// Every reason appears exactly once, so a reason can never be counted in two
// categories.
var categoryOf = map[Reason]Category{
	ReasonSuccess:                  CategorySuccess,
	ReasonPending:                  CategoryPending,
	ReasonSlowDown:                 CategoryPending,
	ReasonCredentialAccountUnknown: CategoryCredential,
	ReasonCredentialPasswordBad:    CategoryCredential,
	ReasonClientUnknown:            CategoryClient,
	ReasonClientSecretMismatch:     CategoryClient,
	ReasonClientGrantNotAllowed:    CategoryClient,
	ReasonClientAuthMethodBad:      CategoryClient,
	ReasonRequestFieldMissing:      CategoryRequest,
	ReasonRequestParameterDup:      CategoryRequest,
	ReasonRequestEncodingBad:       CategoryRequest,
	ReasonRequestBodyTruncated:     CategoryRequest,
	ReasonRequestMalformedOther:    CategoryRequest,
	ReasonScopeExceedsClient:       CategoryScope,
	ReasonDeviceUserDenied:         CategoryDevice,
	ReasonDeviceUserCodeBad:        CategoryDevice,
	ReasonDeviceCodeExpired:        CategoryDevice,
	ReasonDeviceUserCancelled:      CategoryDevice,
	ReasonGrantExpiredOrRevoked:    CategoryGrant,
	ReasonGrantClientMismatch:      CategoryGrant,
	ReasonGrantMalformed:           CategoryGrant,
	ReasonBackendTimeout:           CategoryBackend,
	ReasonBackendUnavailable:       CategoryBackend,
	ReasonUnknown:                  CategoryUnknown,
}

// Category returns the bounded category the reason belongs to.
func (r Reason) Category() Category {
	if c, ok := categoryOf[r]; ok {
		return c
	}
	return CategoryUnknown
}

// Outcome reduces the reason to the three-value outcome used for success-rate
// calculations. Redirect-based authorization failures are ordinary failure
// reasons here even though their transport response is a 3xx.
func (r Reason) Outcome() Outcome {
	switch r.Category() {
	case CategorySuccess:
		return OutcomeSuccess
	case CategoryPending:
		return OutcomePending
	default:
		return OutcomeFailure
	}
}

// AllReasons returns every reason in classification-priority order. It exists
// for tests and documentation generation.
func AllReasons() []Reason {
	return append([]Reason(nil), reasonOrder...)
}

// reasonOrder fixes the classification priority used by [Classify]. Earlier
// entries win. Infrastructure failures are evaluated before protocol errors so
// a storage outage is never mislabelled as a credential rejection, and explicit
// hints always take precedence over generic error-code matching.
var reasonOrder = []Reason{
	// 1. Non-terminal device polling is a control answer, not a failure.
	ReasonPending,
	ReasonSlowDown,

	// 2. Backend failures must be separated from credential rejection.
	ReasonBackendTimeout,
	ReasonBackendUnavailable,

	// 3. Explicit internal hints (entry-layer knowledge the error alone
	//    cannot carry).
	ReasonCredentialAccountUnknown,
	ReasonCredentialPasswordBad,
	ReasonClientUnknown,
	ReasonClientSecretMismatch,
	ReasonClientGrantNotAllowed,
	ReasonClientAuthMethodBad,
	ReasonRequestFieldMissing,
	ReasonRequestParameterDup,
	ReasonRequestEncodingBad,
	ReasonRequestBodyTruncated,
	ReasonScopeExceedsClient,
	ReasonDeviceUserDenied,
	ReasonDeviceUserCodeBad,
	ReasonDeviceCodeExpired,
	ReasonDeviceUserCancelled,
	ReasonGrantExpiredOrRevoked,
	ReasonGrantClientMismatch,

	// 4. Generic error-code based fallback classification.
	ReasonRequestMalformedOther,
	ReasonGrantMalformed,
	ReasonUnknown,
}
