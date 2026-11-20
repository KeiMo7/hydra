// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package jwk

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/pkg/errors"

	"github.com/ory/herodot"
	"github.com/ory/x/httprouterx"
)

// RotationHandlerPathPrefix holds the administrative rotation endpoints. It is
// separate from KeyHandlerPath so the new routes cannot conflict with the
// existing {set}/{kid} pattern; existing endpoints are left untouched and
// fully compatible.
const RotationHandlerPathPrefix = "/key-rotation"

const (
	rotationDefaultMaxTokenTTL = time.Hour * 24 * 30
	rotationDefaultClockSkew   = time.Minute
)

// RotationHandler exposes the signing-key lifecycle over HTTP.
type RotationHandler struct {
	r InternalRegistry
}

// NewRotationHandler builds the rotation admin handler.
func NewRotationHandler(r InternalRegistry) *RotationHandler {
	return &RotationHandler{r: r}
}

// SetAdminRoutes registers the rotation routes on the admin router.
func (h *RotationHandler) SetAdminRoutes(r *httprouterx.RouterAdmin) {
	r.POST(RotationHandlerPathPrefix+"/{set}/rotate", h.rotate)
	r.GET(RotationHandlerPathPrefix+"/{set}", h.status)
	r.POST(RotationHandlerPathPrefix+"/{set}/cleanup", h.cleanup)
	r.GET(RotationHandlerPathPrefix+"/{set}/export", h.export)
	r.PUT(RotationHandlerPathPrefix+"/{set}/import", h.importSet)
}

func (h *RotationHandler) rotationManager() (RotationManager, error) {
	rm, ok := h.r.KeyManager().(RotationManager)
	if !ok {
		return nil, errors.WithStack(ErrRotationUnsupported)
	}
	return rm, nil
}

type rotateRequestBody struct {
	// Algorithm for the new key. Defaults to RS256 to match the signer.
	Algorithm string `json:"alg"`
	// Use defaults to "sig".
	Use string `json:"use"`
	// MaxTokenTTL is the longest lifetime a token signed by the retiring key
	// may still have. The key stays verifiable for at least this long plus
	// the clock skew. Zero applies the built-in default.
	MaxTokenTTL string `json:"max_token_ttl"`
	// ClockSkew is the tolerated clock difference for cleanup decisions.
	ClockSkew string `json:"clock_skew"`
}

func (b rotateRequestBody) orDefaults() (alg, use string, ttl, skew time.Duration, err error) {
	alg = b.Algorithm
	if alg == "" {
		alg = "RS256"
	}
	use = b.Use
	if use == "" {
		use = "sig"
	}
	ttl = rotationDefaultMaxTokenTTL
	if b.MaxTokenTTL != "" {
		ttl, err = time.ParseDuration(b.MaxTokenTTL)
		if err != nil {
			return "", "", 0, 0, errors.WithStack(herodot.ErrBadRequest().WithReasonf("invalid max_token_ttl: %s", err))
		}
	}
	skew = rotationDefaultClockSkew
	if b.ClockSkew != "" {
		skew, err = time.ParseDuration(b.ClockSkew)
		if err != nil {
			return "", "", 0, 0, errors.WithStack(herodot.ErrBadRequest().WithReasonf("invalid clock_skew: %s", err))
		}
	}
	return alg, use, ttl, skew, nil
}

// swagger:route POST /admin/key-rotation/{set}/rotate jwk rotateSigningKey
//
// # Rotate the signing key of a JSON Web Key Set
//
// Generates a new key, activates it for signing and retires the previously
// active key in one atomic transaction. The retired key remains in the public
// verification set until every token it could have signed has expired.
//
// Produces:
// - application/json
//
// Responses:
//
//	200: rotationResult
//	default: errorOAuth2
func (h *RotationHandler) rotate(w http.ResponseWriter, r *http.Request) {
	rm, err := h.rotationManager()
	if err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}
	var body rotateRequestBody
	if r.ContentLength != 0 {
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			h.r.Writer().WriteError(w, r, errors.WithStack(herodot.ErrBadRequest().WithReasonf("Unable to decode the request body: %s", err)))
			return
		}
	}
	alg, use, ttl, skew, err := body.orDefaults()
	if err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}
	result, err := rm.Rotate(r.Context(), r.PathValue("set"), alg, use, ttl, skew)
	if err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}
	h.r.Writer().Write(w, r, result)
}

// swagger:route GET /admin/key-rotation/{set} jwk getKeyRotationStatus
//
// # Inspect signing key rotation progress
//
// Returns which key is signing, which keys are verification-only, and the
// earliest instant at which the next retired key may be cleaned up.
//
// Produces:
// - application/json
//
// Responses:
//
//	200: lifecycleView
//	default: errorOAuth2
func (h *RotationHandler) status(w http.ResponseWriter, r *http.Request) {
	rm, err := h.rotationManager()
	if err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}
	view, err := rm.GetLifecycle(r.Context(), r.PathValue("set"))
	if err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}
	h.r.Writer().Write(w, r, view)
}

type cleanupRequestBody struct {
	// ClockSkew bounds acceptable instance-vs-storage clock deviation.
	ClockSkew string `json:"clock_skew"`
	// Now overrides the evaluation time. Intended for tests and deterministic
	// scheduled cleanup; leave empty to use the storage clock.
	Now *time.Time `json:"now,omitempty"`
}

// swagger:route POST /admin/key-rotation/{set}/cleanup jwk cleanupRetiredKeys
//
// # Delete key material past its cleanup boundary
//
// Tombstones retired keys whose boundary (retirement time + longest token
// lifetime + clock skew) has passed. Repeating cleanup for an already
// tombstoned key is a no-op. Clock skew beyond tolerance aborts the operation.
//
// Produces:
// - application/json
//
// Responses:
//
//	200: cleanupResult
//	default: errorOAuth2
func (h *RotationHandler) cleanup(w http.ResponseWriter, r *http.Request) {
	rm, err := h.rotationManager()
	if err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}
	var body cleanupRequestBody
	skew := rotationDefaultClockSkew
	var now time.Time
	if r.ContentLength != 0 {
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			h.r.Writer().WriteError(w, r, errors.WithStack(herodot.ErrBadRequest().WithReasonf("Unable to decode the request body: %s", err)))
			return
		}
		if body.ClockSkew != "" {
			skew, err = time.ParseDuration(body.ClockSkew)
			if err != nil {
				h.r.Writer().WriteError(w, r, errors.WithStack(herodot.ErrBadRequest().WithReasonf("invalid clock_skew: %s", err)))
				return
			}
		}
		if body.Now != nil {
			now = *body.Now
		}
	}
	tombstoned, err := rm.Cleanup(r.Context(), r.PathValue("set"), now, skew)
	if err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}
	h.r.Writer().Write(w, r, map[string]any{"set": r.PathValue("set"), "tombstoned": tombstoned})
}

// swagger:route GET /admin/key-rotation/{set}/export jwk exportKeyRotation
//
// # Export a key set with its rotation state
//
// Returns the public verification keys together with lifecycle states and time
// boundaries. Private key material is never included.
//
// Produces:
// - application/json
//
// Responses:
//
//	200: lifecycleExport
//	default: errorOAuth2
func (h *RotationHandler) export(w http.ResponseWriter, r *http.Request) {
	rm, err := h.rotationManager()
	if err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}
	out, err := rm.ExportLifecycle(r.Context(), r.PathValue("set"))
	if err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}
	h.r.Writer().Write(w, r, out)
}

// swagger:route PUT /admin/key-rotation/{set}/import jwk importKeyRotation
//
// # Import a key set with its rotation state
//
// Restores an export produced by the export endpoint, recreating the exact
// rotation state. A key ID already present with a different public key is
// rejected instead of creating two competing keys.
//
// Consumes:
// - application/json
//
// Produces:
// - application/json
//
// Responses:
//
//	200: lifecycleView
//	default: errorOAuth2
func (h *RotationHandler) importSet(w http.ResponseWriter, r *http.Request) {
	rm, err := h.rotationManager()
	if err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}
	var in LifecycleExport
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		h.r.Writer().WriteError(w, r, errors.WithStack(herodot.ErrBadRequest().WithReasonf("Unable to decode the request body: %s", err)))
		return
	}
	view, err := rm.ImportLifecycle(r.Context(), r.PathValue("set"), &in)
	if err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}
	h.r.Writer().Write(w, r, view)
}
