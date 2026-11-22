// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite

import (
	"context"
	"net/http"
)

// ClientCredentialsLockoutTracker tracks failed client-credential attempts and
// decides whether a client identifier is currently locked out.
//
// All methods are keyed by the client identifier only (plus, optionally, a
// source dimension chosen by the implementation). Implementations must never
// see, store, or log the client secret itself.
type ClientCredentialsLockoutTracker interface {
	// CheckLockout is called before any credential verification takes place.
	// It returns nil when the authentication attempt may proceed. When the
	// client identifier is currently locked out (or the backing store is
	// unavailable and the implementation fails closed) it returns an error,
	// typically ErrInvalidClient with a lockout-specific hint.
	CheckLockout(ctx context.Context, clientID string, r *http.Request) error

	// RecordFailure atomically records exactly one failed credential
	// verification for the given client identifier. Implementations must be
	// safe for concurrent use and must not lose or double-count failures.
	// Errors are handled internally (e.g. logged); recording a failure must
	// never itself fail the request.
	RecordFailure(ctx context.Context, clientID string, r *http.Request)

	// RecordSuccess resets the failure counter for the given client
	// identifier after a successful credential verification.
	RecordSuccess(ctx context.Context, clientID string, r *http.Request)
}

// ClientCredentialsLockoutTrackerProvider is an optional extension a
// fosite.Configurator can implement to enable client-credential failure
// counting and lockout. It is resolved via type assertion, so existing
// configurators keep working unchanged (lockout disabled).
type ClientCredentialsLockoutTrackerProvider interface {
	GetClientCredentialsLockoutTracker(ctx context.Context) ClientCredentialsLockoutTracker
}

// clientCredentialsLockoutTracker resolves the optional lockout tracker from
// the fosite config. It returns nil when the config does not provide one.
func (f *Fosite) clientCredentialsLockoutTracker(ctx context.Context) ClientCredentialsLockoutTracker {
	if p, ok := f.Config.(ClientCredentialsLockoutTrackerProvider); ok {
		return p.GetClientCredentialsLockoutTracker(ctx)
	}
	return nil
}
