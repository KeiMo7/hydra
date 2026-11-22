// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	. "github.com/ory/hydra/v2/fosite"
	"github.com/ory/hydra/v2/fosite/storage"
)

// countingHasher counts Compare invocations so tests can assert that no
// expensive secret comparison happens while a client is locked out.
type countingHasher struct {
	mu    sync.Mutex
	calls int
}

func (h *countingHasher) Compare(_ context.Context, hash, data []byte) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.calls++
	if string(hash) != string(data) {
		return errors.New("secret mismatch")
	}
	return nil
}

func (h *countingHasher) Hash(_ context.Context, data []byte) ([]byte, error) {
	return data, nil
}

func (h *countingHasher) compareCalls() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.calls
}

type recordingLockoutTracker struct {
	mu        sync.Mutex
	lockErr   error
	failures  []string
	successes []string
	checks    int
}

func (t *recordingLockoutTracker) CheckLockout(context.Context, string, *http.Request) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.checks++
	return t.lockErr
}

func (t *recordingLockoutTracker) RecordFailure(_ context.Context, clientID string, _ *http.Request) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.failures = append(t.failures, clientID)
}

func (t *recordingLockoutTracker) RecordSuccess(_ context.Context, clientID string, _ *http.Request) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.successes = append(t.successes, clientID)
}

type lockoutTrackerConfig struct {
	*Config
	tracker ClientCredentialsLockoutTracker
}

func (c *lockoutTrackerConfig) GetClientCredentialsLockoutTracker(context.Context) ClientCredentialsLockoutTracker {
	return c.tracker
}

func TestAuthenticateClientLockoutHooks(t *testing.T) {
	hasher := &countingHasher{}
	tracker := &recordingLockoutTracker{}
	store := storage.NewMemoryStore()
	f := &Fosite{
		Store: store,
		Config: &lockoutTrackerConfig{
			Config: &Config{
				ClientSecretsHasher: hasher,
				TokenURL:            "token-url",
			},
			tracker: tracker,
		},
	}

	store.Clients["confidential"] = &DefaultClient{
		ID:     "confidential",
		Secret: []byte("secret"),
	}
	store.Clients["public"] = &DefaultClient{
		ID:     "public",
		Public: true,
	}

	ctx := context.Background()
	form := url.Values{"grant_type": {"client_credentials"}}

	newRequest := func(header http.Header) *http.Request {
		r := httptest.NewRequest("POST", "/oauth2/token", nil)
		r.Header = header
		return r
	}

	t.Run("wrong secret records a failure", func(t *testing.T) {
		tracker.mu.Lock()
		tracker.failures = nil
		tracker.mu.Unlock()

		_, err := f.AuthenticateClient(ctx, newRequest(clientBasicAuthHeader("confidential", "wrong")), form)
		require.Error(t, err)
		assert.Equal(t, []string{"confidential"}, tracker.failures)
		assert.Empty(t, tracker.successes)
	})

	t.Run("correct secret records a success", func(t *testing.T) {
		_, err := f.AuthenticateClient(ctx, newRequest(clientBasicAuthHeader("confidential", "secret")), form)
		require.NoError(t, err)
		assert.Equal(t, []string{"confidential"}, tracker.successes)
	})

	t.Run("unknown client records a failure like a wrong secret", func(t *testing.T) {
		tracker.mu.Lock()
		tracker.failures = nil
		tracker.mu.Unlock()

		_, err := f.AuthenticateClient(ctx, newRequest(clientBasicAuthHeader("does-not-exist", "whatever")), form)
		require.Error(t, err)
		assert.Equal(t, []string{"does-not-exist"}, tracker.failures,
			"unknown client identifiers must be counted like wrong secrets")
	})

	t.Run("public client is not tracked", func(t *testing.T) {
		tracker.mu.Lock()
		tracker.failures = nil
		tracker.successes = nil
		tracker.checks = 0
		tracker.mu.Unlock()

		r := httptest.NewRequest("POST", "/oauth2/token", nil)
		publicForm := url.Values{"grant_type": {"client_credentials"}, "client_id": {"public"}}
		_, err := f.AuthenticateClient(ctx, r, publicForm)
		require.NoError(t, err)
		assert.Empty(t, tracker.failures)
		assert.Empty(t, tracker.successes)
	})

	t.Run("locked client is rejected before the secret comparison", func(t *testing.T) {
		tracker.mu.Lock()
		tracker.lockErr = ErrInvalidClient.WithHint("The OAuth 2.0 Client is temporarily locked out.")
		tracker.mu.Unlock()
		before := hasher.compareCalls()

		_, err := f.AuthenticateClient(ctx, newRequest(clientBasicAuthHeader("confidential", "secret")), form)
		require.Error(t, err)
		var rfcErr *RFC6749Error
		require.ErrorAs(t, err, &rfcErr)
		assert.Contains(t, rfcErr.GetDescription(), "locked out")
		assert.Equal(t, before, hasher.compareCalls(),
			"no secret comparison must happen while the client is locked out")

		tracker.mu.Lock()
		tracker.lockErr = nil
		tracker.mu.Unlock()
	})
}
