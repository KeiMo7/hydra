// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"net/http"
	"time"

	"github.com/ory/hydra/v2/oauth2/lockout"
	"github.com/ory/x/httpx"
)

// lockoutStatus is the operator-facing view of a client's lockout state.
type lockoutStatus struct {
	ClientID     string               `json:"client_id"`
	Locked       bool                 `json:"locked"`
	LockedUntil  *time.Time           `json:"locked_until,omitempty"`
	FailureCount int64                `json:"failure_count"`
	LockoutRound int64                `json:"lockout_round"`
	Entries      []lockoutStatusEntry `json:"entries"`
}

type lockoutStatusEntry struct {
	Source          string     `json:"source,omitempty"`
	FailureCount    int64      `json:"failure_count"`
	WindowStartedAt time.Time  `json:"window_started_at"`
	LockedUntil     *time.Time `json:"locked_until,omitempty"`
	LockoutRound    int64      `json:"lockout_round"`
}

func lockoutStatusFromEntries(clientID string, entries []lockout.Entry, now time.Time) lockoutStatus {
	s := lockoutStatus{
		ClientID: clientID,
		Entries:  make([]lockoutStatusEntry, 0, len(entries)),
	}
	for _, e := range entries {
		s.FailureCount += e.FailureCount
		if e.LockoutRound > s.LockoutRound {
			s.LockoutRound = e.LockoutRound
		}
		if e.Locked(now) {
			s.Locked = true
			if s.LockedUntil == nil || e.LockedUntil.After(*s.LockedUntil) {
				s.LockedUntil = e.LockedUntil
			}
		}
		s.Entries = append(s.Entries, lockoutStatusEntry{
			Source:          e.Source,
			FailureCount:    e.FailureCount,
			WindowStartedAt: e.WindowStartedAt,
			LockedUntil:     e.LockedUntil,
			LockoutRound:    e.LockoutRound,
		})
	}
	return s
}

// getOAuth2ClientLockout returns the current failure counters and lockout
// state for the given client identifier.
func (h *Handler) getOAuth2ClientLockout(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	entries, err := h.r.ClientLockoutManager().Status(r.Context(), id)
	if err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}
	h.r.Writer().Write(w, r, lockoutStatusFromEntries(id, entries, time.Now().UTC()))
}

// deleteOAuth2ClientLockout manually clears all failure counters and the
// lockout for the given client identifier. The action is recorded in the
// audit trail.
func (h *Handler) deleteOAuth2ClientLockout(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := h.r.ClientLockoutManager().Unlock(r.Context(), id, httpx.ClientIP(r)); err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
