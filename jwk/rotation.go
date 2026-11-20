// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package jwk

import (
	"context"
	"net/http"
	"time"

	"github.com/go-jose/go-jose/v3"

	"github.com/ory/hydra/v2/fosite"
)

// KeyState is the lifecycle state of a single signing key.
type KeyState string

const (
	// KeyStatePending keys are generated but not yet used for signing. They
	// are already part of the public verification set so verifiers can warm
	// up caches before the key becomes active.
	KeyStatePending KeyState = "pending"
	// KeyStateActive keys are eligible for signing new tokens. Exactly one
	// key per set is active at any point in time.
	KeyStateActive KeyState = "active"
	// KeyStateRetired keys no longer sign new tokens but remain in the public
	// verification set until every token they could have signed has expired.
	KeyStateRetired KeyState = "retired"
	// KeyStateTombstoned keys have reached their cleanup boundary. The key
	// material is removed and only the audit record remains.
	KeyStateTombstoned KeyState = "tombstoned"
)

// lifecycleOrder defines the only allowed forward transitions.
var lifecycleOrder = map[KeyState]KeyState{
	KeyStatePending:    KeyStateActive,
	KeyStateActive:     KeyStateRetired,
	KeyStateRetired:    KeyStateTombstoned,
	KeyStateTombstoned: KeyStateTombstoned,
}

// RotationDeltas describe the state transitions recorded by one rotation
// operation. Every entry is written inside the same database transaction as
// the key material changes, which makes the rotation auditable as a unit.
type RotationDelta struct {
	Set        string    `json:"set"`
	Kid        string    `json:"kid"`
	From       KeyState  `json:"from"`
	To         KeyState  `json:"to"`
	ChangedAt  time.Time `json:"changed_at"`
	Generation int64     `json:"generation"`
}

// KeyLifecycle is the persisted metadata for one key inside a set. It never
// carries key material: the encrypted JWK lives in hydra_jwk as before.
type KeyLifecycle struct {
	// Set is the JSON Web Key Set name.
	Set string `json:"set" db:"sid"`
	// Kid is the JSON Web Key ID.
	Kid string `json:"kid" db:"kid"`
	// State is the current lifecycle state.
	State KeyState `json:"state" db:"state"`
	// Generation is monotonically increased on every rotation touching the
	// set. The key with the highest generation that is active wins signing.
	Generation int64 `json:"generation" db:"generation"`
	// ActivatedAt records when the key became (or will become) active.
	ActivatedAt time.Time `json:"activated_at" db:"activated_at"`
	// RetiredAt records when the key stopped signing new tokens.
	RetiredAt time.Time `json:"retired_at" db:"retired_at"`
	// CleanupAfter is the earliest instant at which the key material may be
	// deleted. It is computed at retirement as RetiredAt plus the longest
	// historical token lifetime plus the clock-skew tolerance.
	CleanupAfter time.Time `json:"cleanup_after" db:"cleanup_after"`
	// TombstonedAt records when the key material was deleted.
	TombstonedAt time.Time `json:"tombstoned_at" db:"tombstoned_at"`
	// UpdatedAt is the last metadata write, used for audit ordering.
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// IsPubliclyVisible reports whether the key belongs in the verification set
// published via /.well-known/jwks.json.
func (l KeyLifecycle) IsPubliclyVisible() bool {
	switch l.State {
	case KeyStatePending, KeyStateActive, KeyStateRetired:
		return true
	default:
		return false
	}
}

// CanSign reports whether the key may sign new tokens.
func (l KeyLifecycle) CanSign() bool {
	return l.State == KeyStateActive
}

// LifecycleView is the externally visible rotation progress for one set.
type LifecycleView struct {
	Set string `json:"set"`
	// SigningKID is the key currently used to sign new tokens. Empty when no
	// active key exists (a fresh set before first signing).
	SigningKID string `json:"signing_kid,omitempty"`
	// Keys lists every key with its state and time boundaries.
	Keys []KeyLifecycle `json:"keys"`
	// NextCleanupAt is the earliest CleanupAfter among retired keys that are
	// still visible. Zero when nothing is waiting for cleanup.
	NextCleanupAt time.Time `json:"next_cleanup_at,omitempty"`
}

// RotationResult is returned by Rotate and EnsureSigningKey.
type RotationResult struct {
	Set   string          `json:"set"`
	View  LifecycleView   `json:"view"`
	Delta []RotationDelta `json:"deltas"`
}

// RotationManager encapsulates the consistent signing-key lifecycle. It is an
// optional capability of a Manager: SQL-backed managers implement it while
// backends without transactional metadata (HSM) do not.
type RotationManager interface {
	// EnsureSigningKey returns the active signing key for the set, creating
	// the first generation atomically when the set has none. Concurrent
	// callers across instances converge on exactly one active key.
	EnsureSigningKey(ctx context.Context, set, alg, use string) (*RotationResult, error)

	// Rotate generates a fresh key, activates it and retires the previously
	// active key in one atomic transaction. The public verification set
	// never loses a key during the operation.
	Rotate(ctx context.Context, set, alg, use string, maxTokenTTL, clockSkew time.Duration) (*RotationResult, error)

	// GetLifecycle returns the rotation progress of a set, including each
	// key's state and cleanup boundary.
	GetLifecycle(ctx context.Context, set string) (*LifecycleView, error)

	// Cleanup deletes key material whose cleanup boundary has passed. Keys
	// that were re-activated before the boundary are never deleted. Deleting
	// an already tombstoned key is a no-op without an error.
	Cleanup(ctx context.Context, set string, now time.Time, clockSkew time.Duration) (tombstoned []string, err error)

	// ExportLifecycle returns the public verification set together with the
	// lifecycle metadata. Private keys are never included.
	ExportLifecycle(ctx context.Context, set string) (*LifecycleExport, error)

	// ImportLifecycle restores an export produced by ExportLifecycle,
	// recreating the exact rotation state. It fails rather than merge when
	// the stored set contains a conflicting key ID with a different key.
	ImportLifecycle(ctx context.Context, set string, in *LifecycleExport) (*LifecycleView, error)
}

// LifecycleExport is the portable representation of a set's rotation state.
// All JWKs are public keys only.
type LifecycleExport struct {
	Version int               `json:"version"`
	Set     string            `json:"set"`
	Keys    []jose.JSONWebKey `json:"keys"`
	Meta    []KeyLifecycle    `json:"meta"`
}

// Sentinel errors. Callers use errors.Is to distinguish retryable failures.
var (
	// ErrRotationUnsupported is returned by backends that cannot provide
	// transactional rotation metadata (e.g. HSM).
	ErrRotationUnsupported = &fosite.RFC6749Error{
		CodeField:        http.StatusNotImplemented,
		ErrorField:       http.StatusText(http.StatusNotImplemented),
		DescriptionField: "Signing key rotation is not supported by the configured key manager backend",
	}

	// ErrKeyGeneration is returned when fresh key material could not be
	// generated or persisted. The previously active key keeps signing, so the
	// operation is safe to retry.
	ErrKeyGeneration = &fosite.RFC6749Error{
		CodeField:        http.StatusServiceUnavailable,
		ErrorField:       http.StatusText(http.StatusServiceUnavailable),
		DescriptionField: "Failed to generate and persist the new signing key; the existing signing key is unchanged and the operation can be retried",
	}

	// ErrKeyIDConflict is returned when the same kid maps to two different
	// public keys. The write is rejected before any half-written state exists.
	ErrKeyIDConflict = &fosite.RFC6749Error{
		CodeField:        http.StatusConflict,
		ErrorField:       http.StatusText(http.StatusConflict),
		DescriptionField: "The same key ID is already associated with a different public key",
	}

	// ErrClockSkew is returned when the local clock deviates beyond the
	// configured tolerance from the storage clock. Automatic cleanup is
	// refused; an operator must investigate.
	ErrClockSkew = &fosite.RFC6749Error{
		CodeField:        http.StatusServiceUnavailable,
		ErrorField:       http.StatusText(http.StatusServiceUnavailable),
		DescriptionField: "Clock skew between this instance and the storage backend exceeds the configured tolerance; automatic key cleanup was refused",
	}

	// ErrEmptyVerificationSet guards the invariant that a rotation must never
	// publish an empty verification set.
	ErrEmptyVerificationSet = &fosite.RFC6749Error{
		CodeField:        http.StatusConflict,
		ErrorField:       http.StatusText(http.StatusConflict),
		DescriptionField: "Refusing to apply a key set change that would leave the public verification set empty",
	}
)
