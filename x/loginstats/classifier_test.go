// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package loginstats

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/hydra/v2/fosite"
)

func TestReasonCategoryIsUniqueAndBounded(t *testing.T) {
	t.Parallel()

	seen := map[Reason]struct{}{}
	for _, r := range reasonOrder {
		// Every reason has a category mapping.
		c, ok := categoryOf[r]
		require.True(t, ok, "reason %s has no category", r)
		assert.NotEmpty(t, c)

		// Every reason is listed once in the priority order.
		_, dup := seen[r]
		require.False(t, dup, "reason %s appears more than once", r)
		seen[r] = struct{}{}
	}

	// Every mapped reason has a valid outcome.
	for r, c := range categoryOf {
		out := r.Outcome()
		switch c {
		case CategorySuccess:
			assert.Equal(t, OutcomeSuccess, out)
		case CategoryPending:
			assert.Equal(t, OutcomePending, out)
		default:
			assert.Equal(t, OutcomeFailure, out, "reason %s should be a failure", r)
		}
	}
}

func TestClassifyTable(t *testing.T) {
	t.Parallel()

	timeoutErr := &net.OpError{Op: "read", Net: "tcp", Err: timeoutErr{}}

	for _, tc := range []struct {
		name       string
		err        error
		hint       Hint
		wantReason Reason
		wantCat    Category
		wantOut    Outcome
	}{
		// Success.
		{name: "success", err: nil, wantReason: ReasonSuccess, wantCat: CategorySuccess, wantOut: OutcomeSuccess},

		// Pending device polling.
		{name: "authorization pending", err: fosite.ErrAuthorizationPending, wantReason: ReasonPending, wantCat: CategoryPending, wantOut: OutcomePending},
		{name: "slow down", err: fosite.ErrSlowDown, wantReason: ReasonSlowDown, wantCat: CategoryPending, wantOut: OutcomePending},
		{name: "explicit pending hint", err: nil, hint: Hint{Reason: ReasonPending}, wantReason: ReasonPending, wantCat: CategoryPending, wantOut: OutcomePending},

		// Backend beats credential rejection.
		{name: "context deadline is backend timeout", err: context.DeadlineExceeded, wantReason: ReasonBackendTimeout, wantCat: CategoryBackend, wantOut: OutcomeFailure},
		{name: "net timeout is backend timeout", err: timeoutErr, wantReason: ReasonBackendTimeout, wantCat: CategoryBackend, wantOut: OutcomeFailure},
		{name: "server error", err: fosite.ErrServerError, wantReason: ReasonBackendUnavailable, wantCat: CategoryBackend, wantOut: OutcomeFailure},
		{name: "temporarily unavailable", err: fosite.ErrTemporarilyUnavailable, wantReason: ReasonBackendUnavailable, wantCat: CategoryBackend, wantOut: OutcomeFailure},
		{name: "backend sentinel wins over invalid grant wrapping", err: fosite.ErrInvalidGrant.WithWrap(ErrBackendUnavailable), wantReason: ReasonBackendUnavailable, wantCat: CategoryBackend, wantOut: OutcomeFailure},
		{name: "connection refused", err: errors.New("dial tcp: connection refused"), wantReason: ReasonBackendUnavailable, wantCat: CategoryBackend, wantOut: OutcomeFailure},

		// Credential: internally split, externally identical invalid_grant.
		{name: "unknown account sentinel", err: fosite.ErrInvalidGrant.WithWrap(ErrCredentialAccountUnknown), wantReason: ReasonCredentialAccountUnknown, wantCat: CategoryCredential, wantOut: OutcomeFailure},
		{name: "bad password sentinel", err: fosite.ErrInvalidGrant.WithWrap(ErrCredentialPasswordBad), wantReason: ReasonCredentialPasswordBad, wantCat: CategoryCredential, wantOut: OutcomeFailure},
		{name: "bare invalid grant defaults to grant category", err: fosite.ErrInvalidGrant, wantReason: ReasonGrantExpiredOrRevoked, wantCat: CategoryGrant, wantOut: OutcomeFailure},

		// Client identity.
		{name: "invalid client default secret mismatch", err: fosite.ErrInvalidClient, wantReason: ReasonClientSecretMismatch, wantCat: CategoryClient, wantOut: OutcomeFailure},
		{name: "unknown client sentinel", err: fosite.ErrInvalidClient.WithWrap(ErrClientUnknown), wantReason: ReasonClientUnknown, wantCat: CategoryClient, wantOut: OutcomeFailure},
		{name: "unauthorized client", err: fosite.ErrUnauthorizedClient, wantReason: ReasonClientGrantNotAllowed, wantCat: CategoryClient, wantOut: OutcomeFailure},
		{name: "unsupported grant type", err: fosite.ErrUnsupportedGrantType, wantReason: ReasonClientGrantNotAllowed, wantCat: CategoryClient, wantOut: OutcomeFailure},

		// Request shape.
		{name: "invalid request generic", err: fosite.ErrInvalidRequest, wantReason: ReasonRequestMalformedOther, wantCat: CategoryRequest, wantOut: OutcomeFailure},
		{name: "missing field hint refines invalid request", err: fosite.ErrInvalidRequest, hint: Hint{Reason: ReasonRequestFieldMissing}, wantReason: ReasonRequestFieldMissing, wantCat: CategoryRequest, wantOut: OutcomeFailure},
		{name: "duplicate param hint", err: fosite.ErrInvalidRequest, hint: Hint{Reason: ReasonRequestParameterDup}, wantReason: ReasonRequestParameterDup, wantCat: CategoryRequest, wantOut: OutcomeFailure},
		{name: "encoding hint", err: fosite.ErrInvalidRequest, hint: Hint{Reason: ReasonRequestEncodingBad}, wantReason: ReasonRequestEncodingBad, wantCat: CategoryRequest, wantOut: OutcomeFailure},
		{name: "truncated body hint", err: fosite.ErrInvalidRequest, hint: Hint{Reason: ReasonRequestBodyTruncated}, wantReason: ReasonRequestBodyTruncated, wantCat: CategoryRequest, wantOut: OutcomeFailure},
		{name: "invalid state", err: fosite.ErrInvalidState, wantReason: ReasonRequestMalformedOther, wantCat: CategoryRequest, wantOut: OutcomeFailure},

		// Scope.
		{name: "invalid scope", err: fosite.ErrInvalidScope, wantReason: ReasonScopeExceedsClient, wantCat: CategoryScope, wantOut: OutcomeFailure},
		{name: "scope not granted", err: fosite.ErrScopeNotGranted, wantReason: ReasonScopeExceedsClient, wantCat: CategoryScope, wantOut: OutcomeFailure},
		{name: "scope hint cannot override backend", err: fosite.ErrServerError, hint: Hint{Reason: ReasonScopeExceedsClient}, wantReason: ReasonBackendUnavailable, wantCat: CategoryBackend, wantOut: OutcomeFailure},

		// Device.
		{name: "device expired", err: fosite.ErrDeviceExpiredToken, wantReason: ReasonDeviceCodeExpired, wantCat: CategoryDevice, wantOut: OutcomeFailure},
		{name: "device denied access denied", err: fosite.ErrAccessDenied, wantReason: ReasonDeviceUserDenied, wantCat: CategoryDevice, wantOut: OutcomeFailure},
		{name: "device user code bad hint", err: fosite.ErrInvalidRequest, hint: Hint{Reason: ReasonDeviceUserCodeBad}, wantReason: ReasonRequestMalformedOther, wantCat: CategoryRequest, wantOut: OutcomeFailure},
		{name: "device cancelled hint on access denied", err: fosite.ErrAccessDenied, hint: Hint{Reason: ReasonDeviceUserCancelled}, wantReason: ReasonDeviceUserCancelled, wantCat: CategoryDevice, wantOut: OutcomeFailure},

		// Grant / refresh.
		{name: "inactive token", err: fosite.ErrInactiveToken, wantReason: ReasonGrantExpiredOrRevoked, wantCat: CategoryGrant, wantOut: OutcomeFailure},
		{name: "token signature mismatch", err: fosite.ErrTokenSignatureMismatch, wantReason: ReasonGrantMalformed, wantCat: CategoryGrant, wantOut: OutcomeFailure},
		{name: "grant client mismatch hint", err: fosite.ErrInvalidGrant, hint: Hint{Reason: ReasonGrantClientMismatch}, wantReason: ReasonGrantClientMismatch, wantCat: CategoryGrant, wantOut: OutcomeFailure},

		// Unknown.
		{name: "plain unknown error", err: errors.New("something odd"), wantReason: ReasonUnknown, wantCat: CategoryUnknown, wantOut: OutcomeFailure},
		{name: "unknown hint value ignored", err: fosite.ErrInvalidRequest, hint: Hint{Reason: Reason("totally-made-up")}, wantReason: ReasonRequestMalformedOther, wantCat: CategoryRequest, wantOut: OutcomeFailure},
	} {
		t.Run("case="+tc.name, func(t *testing.T) {
			t.Parallel()
			got := Classify(tc.err, tc.hint)
			assert.Equal(t, tc.wantReason, got)
			assert.Equal(t, tc.wantCat, got.Category())
			assert.Equal(t, tc.wantOut, got.Outcome())
		})
	}
}

// timeoutErr implements net.Error with Timeout()==true.
type timeoutErr struct{}

func (timeoutErr) Error() string     { return "i/o timeout" }
func (timeoutErr) Timeout() bool     { return true }
func (t timeoutErr) Temporary() bool { return true }

func TestBackendNeverClassifiedAsCredential(t *testing.T) {
	t.Parallel()

	// Even when a backend failure is wrapped in the same outward error a bad
	// password produces, the internal reason must stay infra-related.
	err := fosite.ErrInvalidGrant.
		WithHint("Unable to authenticate the provided username and password credentials.").
		WithWrap(ErrBackendTimeout)
	got := Classify(err, Hint{})
	assert.Equal(t, ReasonBackendTimeout, got)
	assert.Equal(t, CategoryBackend, got.Category())
}
