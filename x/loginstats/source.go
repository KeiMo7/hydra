// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package loginstats

import (
	"net"
	"net/netip"
	"strings"
)

// SourceConfig controls how source addresses are folded into network-segment
// labels. Prefix lengths are configurable so deployments can choose their own
// aggregation granularity; larger prefixes mean fewer, coarser buckets.
type SourceConfig struct {
	// IPv4Prefix is the number of leading bits kept for IPv4 addresses
	// (0..32). Zero defaults to 24 (a /24 segment).
	IPv4Prefix int
	// IPv6Prefix is the number of leading bits kept for IPv6 addresses
	// (0..128). Zero defaults to 48, which collapses typical per-customer
	// IPv6 allocations into one bucket and prevents prefix-exhaustion attacks
	// from blowing up label cardinality.
	IPv6Prefix int
	// Cardinality bounds the number of distinct segment labels.
	Cardinality int
}

func (c SourceConfig) withDefaults() SourceConfig {
	if c.IPv4Prefix <= 0 || c.IPv4Prefix > 32 {
		c.IPv4Prefix = 24
	}
	if c.IPv6Prefix <= 0 || c.IPv6Prefix > 128 {
		c.IPv6Prefix = 48
	}
	if c.Cardinality <= 0 {
		c.Cardinality = 256
	}
	return c
}

// SourceBucketer folds caller addresses (including proxy chains and IPv6)
// into bounded network-segment labels. The raw address is never emitted.
type SourceBucketer struct {
	cfg   SourceConfig
	cache *boundedMap
}

// NewSourceBucketer builds a bucketer from the supplied configuration.
func NewSourceBucketer(cfg SourceConfig) *SourceBucketer {
	cfg = cfg.withDefaults()
	return &SourceBucketer{cfg: cfg, cache: newBoundedMap(cfg.Cardinality)}
}

// Bucket returns the segment label for a caller address. The input may be a
// bare IP or an ip:port pair as produced by http.Request.RemoteAddr. Empty
// input maps to [LabelEmpty], unparseable input to [LabelUnknown].
func (s *SourceBucketer) Bucket(remote string) string {
	remote = strings.TrimSpace(remote)
	if remote == "" {
		return LabelEmpty
	}
	return s.cache.lookupOrStore(remote, s.derive)
}

func (s *SourceBucketer) derive(remote string) string {
	addr := remote
	if host, _, err := net.SplitHostPort(remote); err == nil {
		addr = host
	}
	// Strip brackets from bare "[::1]" style inputs.
	addr = strings.Trim(addr, "[]")

	ip, err := netip.ParseAddr(addr)
	if err != nil {
		return LabelUnknown
	}

	prefixLen := s.cfg.IPv4Prefix
	if ip.Is6() {
		prefixLen = s.cfg.IPv6Prefix
	}
	prefix, err := ip.Prefix(prefixLen)
	if err != nil {
		return LabelUnknown
	}

	// Masked() zeroes the host bits, so hosts inside one segment share a
	// label. String() yields a canonical, version-tagged form ("1.2.3.0/24",
	// "2001:db8::/48").
	return prefix.Masked().String()
}
