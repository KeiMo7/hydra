// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"net/http"

	"github.com/pborman/uuid"

	"github.com/ory/hydra/v2/fosite"
	"github.com/ory/hydra/v2/x/loginstats"
	"github.com/ory/x/httpx"
)

// attemptDedupKey returns a stable per-request identifier used to collapse
// duplicate reports of one logical attempt (e.g. entry layer and protocol
// layer both observing the same request).
func attemptDedupKey(r *http.Request) string {
	if existing := r.Header.Get("X-Login-Attempt-Id"); existing != "" {
		return existing
	}
	return uuid.New()
}

// recordLoginAttempt is the single funnel through which every OAuth2 entry
// point reports its terminal outcome. The recorder is a no-op unless the
// feature is enabled. It deliberately runs before the response is written so
// redirect-based failures (303/302) are observed server-side without any
// client callback, and it never alters the response: callers keep their exact
// existing error bodies, status codes and redirect targets.
func (h *Handler) recordLoginAttempt(r *http.Request, entry loginstats.EntryPoint, account, grant, dedupKey string, err error, hint loginstats.Hint) {
	// When the caller did not pin a specific reason, derive the bounded
	// request-shape sub-reason (missing field / duplicate / encoding /
	// truncated) from the server-generated RFC hint. This is purely internal
	// and cannot change the outward error.
	if hint.Reason == "" {
		if shape := loginstats.RequestShapeHint(err); shape != "" {
			hint.Reason = shape
		}
	}
	h.r.LoginAttemptRecorder().Record(r.Context(), loginstats.Attempt{
		EntryPoint: entry,
		Account:    account,
		Remote:     httpx.ClientIP(r),
		GrantType:  grant,
		Err:        err,
		Hint:       hint,
		DedupKey:   dedupKey,
	})
}

// grantTypeFromRequest extracts the grant_type label in a nil-safe way.
func grantTypeFromRequest(ar fosite.Requester) string {
	if ar == nil {
		return ""
	}
	if access, ok := ar.(fosite.AccessRequester); ok {
		if gts := access.GetGrantTypes(); len(gts) > 0 {
			return string(gts[0])
		}
	}
	return ""
}

// accountFromForm extracts the end-user identifier from a token request form
// (the ROPC username). The value is only passed to the recorder, which hashes
// it before it can reach any label or field.
func accountFromForm(r *http.Request) string {
	if r == nil || r.PostForm == nil {
		// ParseMultipartForm is idempotent; the protocol layer has already
		// parsed the body, so this stays cheap.
		_ = r.ParseForm()
	}
	if r.Form != nil {
		return r.Form.Get("username")
	}
	return ""
}

// accountFromRequest returns the authenticated subject once a request has a
// session, otherwise the submitted username. It never returns a client secret.
func accountFromRequest(ar fosite.Requester) string {
	if ar == nil {
		return ""
	}
	if sess := ar.GetSession(); sess != nil && sess.GetSubject() != "" {
		return sess.GetSubject()
	}
	return ""
}
