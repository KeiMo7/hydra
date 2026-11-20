// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package jwk

import (
	"time"

	"github.com/gofrs/uuid"
)

// RotationSQLData is one row of signing-key lifecycle metadata. It carries no
// key material; the encrypted JWK itself stays in hydra_jwk. The (nid, sid,
// kid) unique index mirrors hydra_jwk's identity and makes concurrent writes
// converge on a single row per key.
type RotationSQLData struct {
	ID           uuid.UUID `db:"pk"`
	NID          uuid.UUID `json:"-" db:"nid"`
	Set          string    `db:"sid"`
	KID          string    `db:"kid"`
	State        string    `db:"state"`
	Generation   int64     `db:"generation"`
	ActivatedAt  time.Time `db:"activated_at"`
	RetiredAt    time.Time `db:"retired_at"`
	CleanupAfter time.Time `db:"cleanup_after"`
	TombstonedAt time.Time `db:"tombstoned_at"`
	UpdatedAt    time.Time `db:"updated_at"`
}

func (RotationSQLData) TableName() string { return "hydra_jwk_rotation" }

func (d RotationSQLData) toLifecycle() KeyLifecycle {
	return KeyLifecycle{
		Set:          d.Set,
		Kid:          d.KID,
		State:        KeyState(d.State),
		Generation:   d.Generation,
		ActivatedAt:  d.ActivatedAt,
		RetiredAt:    d.RetiredAt,
		CleanupAfter: d.CleanupAfter,
		TombstonedAt: d.TombstonedAt,
		UpdatedAt:    d.UpdatedAt,
	}
}

// NewRotationSQLData builds a persistence row from domain lifecycle metadata.
func NewRotationSQLData(nid uuid.UUID, l KeyLifecycle, now time.Time) RotationSQLData {
	return RotationSQLData{
		ID:           uuid.Must(uuid.NewV4()),
		NID:          nid,
		Set:          l.Set,
		KID:          l.Kid,
		State:        string(l.State),
		Generation:   l.Generation,
		ActivatedAt:  l.ActivatedAt,
		RetiredAt:    l.RetiredAt,
		CleanupAfter: l.CleanupAfter,
		TombstonedAt: l.TombstonedAt,
		UpdatedAt:    now,
	}
}

// RotationSQLDataRows is the persisted slice type used by pop queries.
type RotationSQLDataRows []RotationSQLData

// ToLifecycleView converts persisted rows into domain lifecycle metadata.
func (rows RotationSQLDataRows) ToLifecycleView() []KeyLifecycle {
	out := make([]KeyLifecycle, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.toLifecycle())
	}
	return out
}
