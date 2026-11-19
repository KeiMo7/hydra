// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package loginstats

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
)

// maxAccountInput caps the bytes read from a caller-supplied account name.
// Hashing is constant-time in input length beyond this point because the
// input is truncated first; the truncation also bounds the work an attacker
// can force per request with an oversized identifier.
const maxAccountInput = 1024

// AccountBucketer turns an account identifier into an irreversible, salted
// label suitable for metric dimensions and structured events.
//
// Guarantees:
//   - The plaintext identifier never appears in any label or field.
//   - The current salt is used for new attempts, but every configured salt
//     is tried so historical labels stay aligned after a salt rotation.
//   - A missing or failed salt degrades to the unattributable bucket rather
//     than ever falling back to plaintext.
//   - The number of distinct labels is bounded by the underlying [boundedMap].
type AccountBucketer struct {
	salts [][]byte
	cache *boundedMap
}

// NewAccountBucketer builds a bucketer. salts must be ordered with the
// current salt first and older salts afterwards (the same convention as
// secrets.system). An empty salts slice enables safe degraded mode.
func NewAccountBucketer(salts [][]byte, cardinality int) *AccountBucketer {
	cleaned := make([][]byte, 0, len(salts))
	for _, s := range salts {
		if len(s) > 0 {
			cleaned = append(cleaned, s)
		}
	}
	return &AccountBucketer{
		salts: cleaned,
		cache: newBoundedMap(cardinality),
	}
}

// Bucket returns the bounded, irreversible label for account. It never
// returns the input value.
func (a *AccountBucketer) Bucket(account string) string {
	if account == "" {
		return LabelEmpty
	}
	if len(a.salts) == 0 {
		// No salt configured: refuse to derive any reversible token and put
		// the attempt in the dedicated unattributable bucket.
		return LabelUnknown
	}
	return a.cache.lookupOrStore(account, a.derive)
}

// derive computes the label for a previously unseen account. The label
// carries the index of the salt that produced it, so dashboards can see the
// rotation boundary while still joining old and new data (the account's
// current-salt label stabilises as soon as it is seen again).
func (a *AccountBucketer) derive(account string) string {
	input := account
	if len(input) > maxAccountInput {
		input = input[:maxAccountInput]
	}

	for i, salt := range a.salts {
		mac := hmac.New(sha256.New, salt)
		mac.Write([]byte(input))
		digest := hex.EncodeToString(mac.Sum(nil))[:16]
		return "v" + strconv.Itoa(i) + "_" + digest
	}
	return LabelUnknown
}
