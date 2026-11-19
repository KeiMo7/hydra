// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package kratos

import (
	"errors"
	"reflect"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"

	"github.com/ory/hydra/v2/x/loginstats"
	client "github.com/ory/kratos-client-go"
)

// apiError builds a SDK GenericOpenAPIError with the same unexported fields the
// generated client sets on a non-2xx response, so the body-based classification
// can be unit tested without a running Kratos server.
func apiError(statusText string, body []byte) client.GenericOpenAPIError {
	e := client.GenericOpenAPIError{}
	v := reflect.ValueOf(&e).Elem()
	errField := v.FieldByName("error")
	reflect.NewAt(errField.Type(), unsafe.Pointer(errField.UnsafeAddr())).
		Elem().SetString(statusText)
	bodyField := v.FieldByName("body")
	reflect.NewAt(bodyField.Type(), unsafe.Pointer(bodyField.UnsafeAddr())).
		Elem().SetBytes(body)
	return e
}

func TestClassifyLoginError_Table(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		err  error
		want error
	}{
		{
			name: "network failure is backend",
			err:  errors.New("dial tcp: connection refused"),
			want: loginstats.ErrBackendUnavailable,
		},
		{
			name: "unknown account via 400 envelope",
			err:  apiError("400 Bad Request", []byte(`{"error":{"id":"identifier_unknown","code":400}}`)),
			want: loginstats.ErrCredentialAccountUnknown,
		},
		{
			name: "bad password via 400 envelope",
			err:  apiError("400 Bad Request", []byte(`{"error":{"id":"credentials_invalid","code":400}}`)),
			want: loginstats.ErrCredentialPasswordBad,
		},
		{
			name: "unknown 400 reason defaults to bad password, not outage",
			err:  apiError("400 Bad Request", []byte(`{"error":{"id":"some_new_id","code":400}}`)),
			want: loginstats.ErrCredentialPasswordBad,
		},
		{
			name: "400 with unparseable body still classifies as credential",
			err:  apiError("400 Bad Request", nil),
			want: loginstats.ErrCredentialPasswordBad,
		},
		{
			name: "500 envelope is backend",
			err:  apiError("500 Internal Server Error", []byte(`{"error":{"id":"server_error","code":500}}`)),
			want: loginstats.ErrBackendUnavailable,
		},
		{
			name: "500 with unparseable body is backend via status text",
			err:  apiError("503 Service Unavailable", nil),
			want: loginstats.ErrBackendUnavailable,
		},
	} {
		t.Run("case="+tc.name, func(t *testing.T) {
			t.Parallel()
			got := classifyLoginError(tc.err)
			assert.True(t, errors.Is(got, tc.want), "got %v", got)
		})
	}
}

func TestStatusFromText(t *testing.T) {
	t.Parallel()
	assert.Equal(t, 400, statusFromText("400 Bad Request"))
	assert.Equal(t, 500, statusFromText("500 Internal Server Error"))
	assert.Equal(t, 0, statusFromText("no value given for required property expires_at"))
	assert.Equal(t, 0, statusFromText(""))
}

func TestLoginBodyParsing(t *testing.T) {
	t.Parallel()

	t.Run("nested error envelope", func(t *testing.T) {
		body := []byte(`{"error":{"id":"identifier_unknown","code":400}}`)
		assert.Equal(t, 400, httpStatusFromBody(body))
		assert.Equal(t, "identifier_unknown", loginReasonFromBody(body))
	})

	t.Run("unparseable body yields safe zeros", func(t *testing.T) {
		assert.Equal(t, 0, httpStatusFromBody([]byte("not-json")))
		assert.Equal(t, "", loginReasonFromBody([]byte("not-json")))
	})
}

func TestClassifySentinels(t *testing.T) {
	t.Parallel()

	// A non-API error always degrades to backend, never credential.
	got := classifyLoginError(errors.New("i/o timeout"))
	assert.True(t, errors.Is(got, loginstats.ErrBackendUnavailable))

	// The join preserves the inner error too.
	inner := errors.New("connection reset by peer")
	j := joinError{outer: loginstats.ErrBackendUnavailable, inner: inner}
	assert.True(t, errors.Is(j, loginstats.ErrBackendUnavailable))
	assert.True(t, errors.Is(j, inner))
}
