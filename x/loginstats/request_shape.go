// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package loginstats

import (
	"strings"

	"github.com/ory/hydra/v2/fosite"
)

// RequestShapeHint refines a generic invalid_request protocol error into the
// bounded request-shape reasons. It inspects the RFC error's hint/debug text,
// which is server-generated (never caller-controlled), so the mapping cannot
// introduce new label values. It returns the zero reason when the error is not
// a request-shape error, leaving the ordinary classification untouched.
func RequestShapeHint(err error) Reason {
	if err == nil {
		return ""
	}
	rfc := fosite.ErrorToRFC6749Error(err)
	if rfc == nil || rfc.ErrorField != "invalid_request" {
		return ""
	}

	text := strings.ToLower(rfc.HintField + " " + rfc.DebugField)
	switch {
	case strings.Contains(text, "can not be empty"),
		strings.Contains(text, "is missing"),
		strings.Contains(text, "must not be empty"),
		strings.Contains(text, "is not defined"):
		return ReasonRequestFieldMissing
	case strings.Contains(text, "more than once"),
		strings.Contains(text, "duplicate"):
		return ReasonRequestParameterDup
	case strings.Contains(text, "unexpected eof"),
		strings.Contains(text, "body truncated"),
		strings.Contains(text, "http: request body too large"),
		strings.Contains(text, "content length"):
		return ReasonRequestBodyTruncated
	case strings.Contains(text, "unable to parse"),
		strings.Contains(text, "invalid url escape"),
		strings.Contains(text, "malformed"),
		strings.Contains(text, "percent-encoding"),
		strings.Contains(text, "encoding"):
		return ReasonRequestEncodingBad
	default:
		return ReasonRequestMalformedOther
	}
}
