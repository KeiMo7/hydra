// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package loginstats

import "errors"

// Internal sentinel errors. They never cross the HTTP boundary themselves:
// handlers keep emitting the exact same fosite RFC errors as before. They are
// attached to the error chain (or passed explicitly via a [Hint]) so the
// classifier can distinguish operational causes that share one external error
// code - most importantly an unknown account versus a bad password, and an
// identity-backend outage versus a genuine credential rejection.
var (
	// ErrCredentialAccountUnknown means the presented identifier does not
	// resolve to an account. Externally it is indistinguishable from
	// [ErrCredentialPasswordBad].
	ErrCredentialAccountUnknown = errors.New("loginstats: account unknown")
	// ErrCredentialPasswordBad means the account exists but the presented
	// secret did not verify.
	ErrCredentialPasswordBad = errors.New("loginstats: bad password")

	// ErrClientUnknown means no client with the presented identifier exists.
	ErrClientUnknown = errors.New("loginstats: client unknown")
	// ErrClientSecretMismatch means the client exists but its credential did
	// not verify.
	ErrClientSecretMismatch = errors.New("loginstats: client secret mismatch")

	// ErrBackendTimeout means a dependency exceeded its deadline.
	ErrBackendTimeout = errors.New("loginstats: backend timeout")
	// ErrBackendUnavailable means a dependency rejected the request for an
	// infrastructure reason (connection refused, 5xx, ...).
	ErrBackendUnavailable = errors.New("loginstats: backend unavailable")
)

// Hint carries entry-layer knowledge that is not reliably recoverable from
// the error alone. Hints are optional: a zero Hint means "classify from the
// error chain only". When set, a hint only refines internal granularity; it
// never changes what is written to the HTTP response.
type Hint struct {
	// Reason, when non-empty, refines the reason derived from the error chain.
	// It is validated against the closed reason set, so callers cannot inject
	// arbitrary label values, and it can only refine within one category.
	Reason Reason
}
