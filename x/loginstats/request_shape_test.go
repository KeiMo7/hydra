// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package loginstats

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/ory/hydra/v2/fosite"
)

func TestRequestShapeHint(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		err  error
		want Reason
	}{
		{name: "missing field", err: fosite.ErrInvalidRequest.WithHint("Request parameter 'grant_type' is missing"), want: ReasonRequestFieldMissing},
		{name: "empty body", err: fosite.ErrInvalidRequest.WithHint("The POST body can not be empty."), want: ReasonRequestFieldMissing},
		{name: "duplicate parameter", err: fosite.ErrInvalidRequest.WithHint("a parameter more than once"), want: ReasonRequestParameterDup},
		{name: "bad encoding", err: fosite.ErrInvalidRequest.WithHint("Unable to parse HTTP body, make sure to send a properly formatted form request body."), want: ReasonRequestEncodingBad},
		{name: "truncated body", err: fosite.ErrInvalidRequest.WithHint("http: request body too large"), want: ReasonRequestBodyTruncated},
		{name: "other malformed", err: fosite.ErrInvalidRequest.WithHint("some other shape problem"), want: ReasonRequestMalformedOther},
		{name: "not an invalid_request", err: fosite.ErrInvalidGrant.WithHint("Request parameter 'grant_type' is missing"), want: ""},
		{name: "nil error", err: nil, want: ""},
	} {
		t.Run("case="+tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, RequestShapeHint(tc.err))
		})
	}
}

func TestRequestShapeHintRefinesOnlyRequestCategory(t *testing.T) {
	t.Parallel()

	// The derived reason must stay inside the request-malformed category so it
	// cannot relabel a scope or backend failure.
	err := fosite.ErrInvalidRequest.WithHint("Request parameter 'grant_type' is missing")
	got := Classify(err, Hint{Reason: RequestShapeHint(err)})
	assert.Equal(t, ReasonRequestFieldMissing, got)
	assert.Equal(t, CategoryRequest, got.Category())
}
