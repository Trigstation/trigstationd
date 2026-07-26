// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Simon Wright

package clientaddr

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
)

// No test in this file passes an address, a prefix or a header value to a
// formatting call. Failures are reported by case name. That is not fastidiousness
// about test output: DIRECTORY-SPEC.md §6.4 says no code path may emit the
// address, and a t.Errorf printing the address of a failing case is a code path.
// TestNoRenderingOfAddresses in source_test.go enforces it.

// addr parses a test address.
func addr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("a fixture address does not parse")
	}
	return a
}

// mustPrefix parses a test prefix.
func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatalf("a fixture prefix does not parse")
	}
	return p
}

// extractor builds an Extractor from the flag syntax, so that the tests exercise
// the same path an operator does.
func extractor(t *testing.T, trusted string) *Extractor {
	t.Helper()
	prefixes, err := ParsePrefixes(trusted)
	if err != nil {
		t.Fatalf("a fixture trusted-proxy list does not parse")
	}
	return New(prefixes)
}

// A realistic proxy front end for most cases below: the directory listens on
// loopback and nginx or Caddy sits in front of it.
const localProxy = "127.0.0.0/8"

// --- rule 1: no trust by default -------------------------------------------

// TestEmptyTrustedListIgnoresTheForwardedHeader is §6.4 rule 1. An unconfigured
// directory must get a limiter that is useless but safe, never one that is
// bypassable — so a well-formed header from a plausible proxy is ignored just as
// firmly as a malformed one.
func TestEmptyTrustedListIgnoresTheForwardedHeader(t *testing.T) {
	tests := []struct {
		name string
		peer string
		xff  string
	}{
		{"well formed single entry", "127.0.0.1", "203.0.113.9"},
		{"well formed chain", "127.0.0.1", "1.2.3.4, 203.0.113.9"},
		{"header from a public peer", "198.51.100.7", "203.0.113.9"},
		{"IPv6 entry", "::1", "2001:db8::9"},
		{"absent header", "127.0.0.1", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			peer := addr(t, tt.peer)

			// Every way of expressing "trust nothing" must behave alike.
			builders := []struct {
				name string
				make func() *Extractor
			}{
				{"New(nil)", func() *Extractor { return New(nil) }},
				{"New(empty slice)", func() *Extractor { return New([]netip.Prefix{}) }},
				{"zero value", func() *Extractor { return &Extractor{} }},
				{"nil receiver", func() *Extractor { return nil }},
			}
			for _, b := range builders {
				t.Run(b.name, func(t *testing.T) {
					e := b.make()
					if e.Addr(peer, tt.xff) != peer {
						t.Errorf("with nothing trusted the header changed the key; the default must ignore X-Forwarded-For entirely")
					}
				})
			}
		})
	}
}

// --- rule 2: trust is decided by the immediate peer only --------------------

// TestUntrustedPeerIgnoresTheForwardedHeader is §6.4 rule 2. A configured list
// does not make the header readable from anywhere: only a peer inside the list
// may speak for another address.
func TestUntrustedPeerIgnoresTheForwardedHeader(t *testing.T) {
	tests := []struct {
		name    string
		trusted string
		peer    string
		xff     string
	}{
		{"public peer, well formed header", localProxy, "198.51.100.7", "203.0.113.9"},
		{"public peer, chain header", localProxy, "198.51.100.7", "1.2.3.4, 203.0.113.9"},
		{"peer just outside the /24", "192.0.2.0/24", "192.0.3.1", "203.0.113.9"},
		{"peer just below the /24", "192.0.2.0/24", "192.0.1.255", "203.0.113.9"},
		{"IPv6 peer, IPv4 proxy trusted", localProxy, "2001:db8::7", "203.0.113.9"},
		{"IPv4 peer, IPv6 proxy trusted", "2001:db8::/64", "198.51.100.7", "203.0.113.9"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := extractor(t, tt.trusted)
			peer := addr(t, tt.peer)
			if e.Addr(peer, tt.xff) != peer {
				t.Errorf("an untrusted peer was allowed to set its own limiter key through X-Forwarded-For")
			}
		})
	}
}

// --- rule 3: rightmost, not leftmost ----------------------------------------

// TestRightmostEntryDefeatsAClientSuppliedHeader is the whole point of §6.4's
// fourth bullet, written out as its own test so that nobody can shorten it away.
//
// READ THIS BEFORE "SIMPLIFYING" IT. A client may send its own X-Forwarded-For.
// The trusted proxy does not replace that value, it preserves it and appends the
// address it observed. So in "1.2.3.4, 203.0.113.9" the client chose 1.2.3.4 and
// the proxy saw 203.0.113.9. An implementation that takes the leftmost entry
// lets any client pick its own limiter key with a single header, and it passes
// every test written from honest traffic, because honest clients send no such
// header at all and every entry is then the proxy's.
//
// If this test fails, the rate limiter is bypassable. It is not a style
// question.
func TestRightmostEntryDefeatsAClientSuppliedHeader(t *testing.T) {
	tests := []struct {
		name string
		xff  string
		want string
	}{
		{
			name: "one forged entry, proxy appends",
			xff:  "1.2.3.4, 203.0.113.9",
			want: "203.0.113.9",
		},
		{
			name: "forged entry naming the proxy itself",
			xff:  "127.0.0.1, 203.0.113.9",
			want: "203.0.113.9",
		},
		{
			name: "three forged entries, proxy appends",
			xff:  "1.2.3.4, 5.6.7.8, 9.10.11.12, 203.0.113.9",
			want: "203.0.113.9",
		},
		{
			name: "forged entries including IPv6",
			xff:  "2001:db8::dead, 1.2.3.4, 203.0.113.9",
			want: "203.0.113.9",
		},
		{
			name: "forged entry claiming a private address",
			xff:  "10.0.0.1, 198.51.100.200",
			want: "198.51.100.200",
		},
		{
			name: "forged rubbish before the observed address",
			xff:  "unknown, _hidden, 198.51.100.200",
			want: "198.51.100.200",
		},
		{
			name: "no comma at all, so the only entry is the proxy's",
			xff:  "203.0.113.9",
			want: "203.0.113.9",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := extractor(t, localProxy)
			peer := addr(t, "127.0.0.1")
			want := addr(t, tt.want)

			got := e.Addr(peer, tt.xff)
			if got == peer {
				t.Fatalf("the forwarded address was not used at all, so every client behind the proxy shares one key")
			}
			if got != want {
				t.Errorf("the rightmost entry was not the one used: a client-supplied X-Forwarded-For chose the limiter key, which is the §6.4 bypass this test exists to prevent")
			}
		})
	}
}

// --- the general table ------------------------------------------------------

// TestAddr covers the forms an entry can take and the ways a header can fail to
// yield one.
func TestAddr(t *testing.T) {
	tests := []struct {
		name    string
		trusted string
		peer    string
		xff     string
		want    string
	}{
		// The ordinary case.
		{
			name:    "single entry from a trusted proxy",
			trusted: localProxy,
			peer:    "127.0.0.1",
			xff:     "203.0.113.9",
			want:    "203.0.113.9",
		},
		{
			name:    "bare address entry, trusted proxy on a LAN",
			trusted: "10.0.0.0/8",
			peer:    "10.4.5.6",
			xff:     "198.51.100.7",
			want:    "198.51.100.7",
		},

		// Nothing usable in the header: fall back to the peer.
		{
			name:    "absent header",
			trusted: localProxy,
			peer:    "127.0.0.1",
			xff:     "",
			want:    "127.0.0.1",
		},
		{
			name:    "whitespace-only header",
			trusted: localProxy,
			peer:    "127.0.0.1",
			xff:     "   ",
			want:    "127.0.0.1",
		},
		{
			name:    "header of a single comma",
			trusted: localProxy,
			peer:    "127.0.0.1",
			xff:     ",",
			want:    "127.0.0.1",
		},
		{
			name:    "trailing comma, no entry after it",
			trusted: localProxy,
			peer:    "127.0.0.1",
			xff:     "203.0.113.9,",
			want:    "127.0.0.1",
		},
		{
			name:    "trailing comma and spaces",
			trusted: localProxy,
			peer:    "127.0.0.1",
			xff:     "203.0.113.9,   ",
			want:    "127.0.0.1",
		},

		// An unparseable rightmost entry must not step leftward. The entries to
		// the left are attacker-chosen, so using one would hand the client the
		// choice of key that rule 1 denies it.
		{
			name:    "unparseable rightmost entry falls back to the peer",
			trusted: localProxy,
			peer:    "127.0.0.1",
			xff:     "not-an-address",
			want:    "127.0.0.1",
		},
		{
			name:    "unparseable rightmost entry does not fall back leftward",
			trusted: localProxy,
			peer:    "127.0.0.1",
			xff:     "1.2.3.4, garbage",
			want:    "127.0.0.1",
		},
		{
			name:    "RFC 7239 obfuscated identifier is not an address",
			trusted: localProxy,
			peer:    "127.0.0.1",
			xff:     "203.0.113.9, _hidden",
			want:    "127.0.0.1",
		},
		{
			name:    "hostname is not an address",
			trusted: localProxy,
			peer:    "127.0.0.1",
			xff:     "proxy.example.nz",
			want:    "127.0.0.1",
		},
		{
			name:    "quoted entry is not an address",
			trusted: localProxy,
			peer:    "127.0.0.1",
			xff:     "\"203.0.113.9\"",
			want:    "127.0.0.1",
		},
		{
			name:    "truncated IPv4 is not an address",
			trusted: localProxy,
			peer:    "127.0.0.1",
			xff:     "203.0.113",
			want:    "127.0.0.1",
		},

		// Whitespace variations around entries.
		{
			name:    "no space after the comma",
			trusted: localProxy,
			peer:    "127.0.0.1",
			xff:     "1.2.3.4,203.0.113.9",
			want:    "203.0.113.9",
		},
		{
			name:    "several spaces after the comma",
			trusted: localProxy,
			peer:    "127.0.0.1",
			xff:     "1.2.3.4,    203.0.113.9",
			want:    "203.0.113.9",
		},
		{
			name:    "tabs around the entry",
			trusted: localProxy,
			peer:    "127.0.0.1",
			xff:     "1.2.3.4,\t203.0.113.9\t",
			want:    "203.0.113.9",
		},
		{
			name:    "leading and trailing spaces on the whole value",
			trusted: localProxy,
			peer:    "127.0.0.1",
			xff:     "  1.2.3.4 ,  203.0.113.9  ",
			want:    "203.0.113.9",
		},
		{
			name:    "a folded continuation line's whitespace",
			trusted: localProxy,
			peer:    "127.0.0.1",
			xff:     "1.2.3.4,\r\n 203.0.113.9",
			want:    "203.0.113.9",
		},

		// host:port and bracketed forms.
		{
			name:    "IPv4 with a port",
			trusted: localProxy,
			peer:    "127.0.0.1",
			xff:     "203.0.113.9:41234",
			want:    "203.0.113.9",
		},
		{
			name:    "bracketed IPv6 with a port",
			trusted: localProxy,
			peer:    "127.0.0.1",
			xff:     "[2001:db8::9]:41234",
			want:    "2001:db8::9",
		},
		{
			name:    "bracketed IPv6 without a port",
			trusted: localProxy,
			peer:    "127.0.0.1",
			xff:     "[2001:db8::9]",
			want:    "2001:db8::9",
		},
		{
			name:    "unbracketed IPv6 with a port is read as an address",
			trusted: localProxy,
			peer:    "127.0.0.1",
			// 2001:db8::1:8080 is a valid address and is indistinguishable
			// from "port 8080 on 2001:db8::1". parseEntry reads it as the
			// address, which is the only reading that cannot be manufactured.
			xff:  "2001:db8::1:8080",
			want: "2001:db8::1:8080",
		},
		{
			name:    "unmatched bracket is not an address",
			trusted: localProxy,
			peer:    "127.0.0.1",
			xff:     "[2001:db8::9",
			want:    "127.0.0.1",
		},
		{
			name:    "empty brackets are not an address",
			trusted: localProxy,
			peer:    "127.0.0.1",
			xff:     "[]",
			want:    "127.0.0.1",
		},

		// IPv6 peers and IPv6 forwarded entries.
		{
			name:    "IPv6 peer, IPv6 forwarded entry",
			trusted: "2001:db8:1::/48",
			peer:    "2001:db8:1::5",
			xff:     "2001:db8:beef::9",
			want:    "2001:db8:beef::9",
		},
		{
			name:    "IPv6 loopback peer",
			trusted: "::1/128",
			peer:    "::1",
			xff:     "2001:db8::9",
			want:    "2001:db8::9",
		},
		{
			name:    "IPv6 peer, IPv4 forwarded entry",
			trusted: "2001:db8:1::/48",
			peer:    "2001:db8:1::5",
			xff:     "198.51.100.7",
			want:    "198.51.100.7",
		},

		// IPv4-mapped IPv6 must come back unmapped, so that this package and
		// internal/ratelimit cannot disagree about which bucket an address
		// lands in.
		{
			name:    "mapped peer, untrusted, comes back unmapped",
			trusted: localProxy,
			peer:    "::ffff:198.51.100.7",
			xff:     "203.0.113.9",
			want:    "198.51.100.7",
		},
		{
			name:    "mapped peer matches an IPv4 trusted prefix",
			trusted: localProxy,
			peer:    "::ffff:127.0.0.1",
			xff:     "203.0.113.9",
			want:    "203.0.113.9",
		},
		{
			name:    "mapped forwarded entry comes back unmapped",
			trusted: localProxy,
			peer:    "127.0.0.1",
			xff:     "::ffff:203.0.113.9",
			want:    "203.0.113.9",
		},
		{
			name:    "mapped forwarded entry with a port comes back unmapped",
			trusted: localProxy,
			peer:    "127.0.0.1",
			xff:     "[::ffff:203.0.113.9]:41234",
			want:    "203.0.113.9",
		},
		{
			name:    "mapped peer, mapped entry, both unmapped",
			trusted: localProxy,
			peer:    "::ffff:127.0.0.1",
			xff:     "::ffff:203.0.113.9",
			want:    "203.0.113.9",
		},

		// The header is not filtered on what it contains: a forwarded address
		// is whatever the trusted proxy observed, and the proxy is trusted.
		{
			name:    "forwarded private address is used as given",
			trusted: localProxy,
			peer:    "127.0.0.1",
			xff:     "10.1.2.3",
			want:    "10.1.2.3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := extractor(t, tt.trusted)
			peer := addr(t, tt.peer)
			want := addr(t, tt.want)
			if e.Addr(peer, tt.xff) != want {
				t.Errorf("the resolved address is not the expected one for this case")
			}
		})
	}
}

// TestAddrIgnoresAnInvalidPeer: a zero netip.Addr is not a member of any prefix,
// so the header is not consulted and the zero value is handed back. Rate
// limiting refuses an invalid address, so this fails closed.
func TestAddrIgnoresAnInvalidPeer(t *testing.T) {
	e := extractor(t, localProxy)
	got := e.Addr(netip.Addr{}, "203.0.113.9")
	if got.IsValid() {
		t.Errorf("an invalid peer produced a valid key; an unparseable peer must not become a trusted one")
	}
}

// --- rule 2, in detail: which peers are trusted -----------------------------

// TestTrustMatching covers prefix membership at the edges, with the two
// deployments an operator actually has: a proxy on loopback, and one on the
// Docker bridge network.
func TestTrustMatching(t *testing.T) {
	tests := []struct {
		name    string
		trusted string
		peer    string
		want    bool
	}{
		{"inside a /24, first host", "192.0.2.0/24", "192.0.2.0", true},
		{"inside a /24, middle", "192.0.2.0/24", "192.0.2.128", true},
		{"inside a /24, last host", "192.0.2.0/24", "192.0.2.255", true},
		{"one below a /24", "192.0.2.0/24", "192.0.1.255", false},
		{"one above a /24", "192.0.2.0/24", "192.0.3.0", false},
		{"loopback, the usual reverse proxy", "127.0.0.1/8", "127.0.0.1", true},
		{"loopback, another address in the /8", "127.0.0.1/8", "127.1.2.3", true},
		{"loopback does not cover 128/8", "127.0.0.1/8", "128.0.0.1", false},
		{"docker bridge default", "172.17.0.0/16", "172.17.0.1", true},
		{"docker bridge, a container", "172.17.0.0/16", "172.17.255.254", true},
		{"docker bridge does not cover 172.18", "172.17.0.0/16", "172.18.0.1", false},
		{"docker's whole range", "172.16.0.0/12", "172.31.255.255", true},
		{"docker's whole range excludes 172.32", "172.16.0.0/12", "172.32.0.1", false},
		{"single host, exact", "203.0.113.9", "203.0.113.9", true},
		{"single host, neighbour", "203.0.113.9", "203.0.113.10", false},
		{"IPv6 /64 inside", "2001:db8:1:2::/64", "2001:db8:1:2:3:4:5:6", true},
		{"IPv6 /64 outside", "2001:db8:1:2::/64", "2001:db8:1:3::1", false},
		{"IPv6 single host", "2001:db8::1", "2001:db8::1", true},
		{"IPv6 single host, neighbour", "2001:db8::1", "2001:db8::2", false},
		{"IPv6 loopback", "::1/128", "::1", true},
		{"several prefixes, second matches", "127.0.0.0/8, 172.17.0.0/16", "172.17.0.5", true},
		{"several prefixes, none matches", "127.0.0.0/8, 172.17.0.0/16", "192.0.2.1", false},
		{"host bits in the configured prefix are ignored", "192.0.2.77/24", "192.0.2.1", true},
		{"mapped IPv4 prefix still matches an IPv4 peer", "::ffff:172.17.0.0/112", "172.17.0.5", true},
		{"a broad private range", "10.0.0.0/8", "10.200.30.40", true},
	}

	// A distinctive forwarded address: seeing it in the result means the peer
	// was trusted, and seeing the peer means it was not.
	const forwarded = "203.0.113.200"

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := extractor(t, tt.trusted)
			peer := addr(t, tt.peer)
			trustedResult := e.Addr(peer, forwarded) != peer
			if trustedResult != tt.want {
				if tt.want {
					t.Errorf("the peer was not recognised as a trusted proxy, so every client behind it shares one limiter key")
				} else {
					t.Errorf("the peer was treated as a trusted proxy although it is outside the configured list")
				}
			}
		})
	}
}

// --- ParsePrefixes ----------------------------------------------------------

func TestParsePrefixes(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    []string // normalised prefixes, in order
		wantErr error
	}{
		{name: "empty string", in: "", want: nil},
		{name: "whitespace only", in: "   ", want: nil},
		{name: "a single comma", in: ",", want: nil},
		{name: "commas and spaces only", in: " , , ", want: nil},

		{name: "one IPv4 CIDR", in: "10.0.0.0/8", want: []string{"10.0.0.0/8"}},
		{name: "one IPv6 CIDR", in: "2001:db8::/32", want: []string{"2001:db8::/32"}},
		{name: "IPv4 /32", in: "127.0.0.1/32", want: []string{"127.0.0.1/32"}},
		{name: "IPv6 /128", in: "::1/128", want: []string{"::1/128"}},
		{name: "default route", in: "0.0.0.0/0", want: []string{"0.0.0.0/0"}},

		{name: "bare IPv4 becomes a /32", in: "127.0.0.1", want: []string{"127.0.0.1/32"}},
		{name: "bare IPv6 becomes a /128", in: "2001:db8::1", want: []string{"2001:db8::1/128"}},

		{
			name: "mixed CIDR and bare, several entries",
			in:   "127.0.0.0/8,172.17.0.0/16,10.1.2.3,::1",
			want: []string{"127.0.0.0/8", "172.17.0.0/16", "10.1.2.3/32", "::1/128"},
		},
		{
			name: "order is preserved",
			in:   "172.17.0.0/16,127.0.0.0/8",
			want: []string{"172.17.0.0/16", "127.0.0.0/8"},
		},
		{
			name: "whitespace around every entry",
			in:   "  127.0.0.0/8 ,\t172.17.0.0/16  ,  ::1  ",
			want: []string{"127.0.0.0/8", "172.17.0.0/16", "::1/128"},
		},
		{
			name: "trailing comma is skipped",
			in:   "127.0.0.0/8,",
			want: []string{"127.0.0.0/8"},
		},
		{
			name: "leading comma is skipped",
			in:   ",127.0.0.0/8",
			want: []string{"127.0.0.0/8"},
		},
		{
			name: "empty entry in the middle is skipped",
			in:   "127.0.0.0/8,,172.17.0.0/16",
			want: []string{"127.0.0.0/8", "172.17.0.0/16"},
		},
		{
			name: "host bits are masked off",
			in:   "192.0.2.77/24",
			want: []string{"192.0.2.0/24"},
		},
		{
			name: "IPv6 host bits are masked off",
			in:   "2001:db8:1:2:3:4:5:6/64",
			want: []string{"2001:db8:1:2::/64"},
		},
		{
			name: "a mapped IPv4 prefix is unmapped",
			in:   "::ffff:172.17.0.0/112",
			want: []string{"172.17.0.0/16"},
		},
		{
			name: "a bare mapped IPv4 address is unmapped",
			in:   "::ffff:127.0.0.1",
			want: []string{"127.0.0.1/32"},
		},

		{name: "not an address at all", in: "nonsense", wantErr: ErrInvalidProxy},
		{name: "hostname", in: "proxy.example.nz", wantErr: ErrInvalidProxy},
		{name: "prefix length out of range", in: "10.0.0.0/33", wantErr: ErrInvalidProxy},
		{name: "IPv6 prefix length out of range", in: "2001:db8::/129", wantErr: ErrInvalidProxy},
		{name: "negative prefix length", in: "10.0.0.0/-1", wantErr: ErrInvalidProxy},
		{name: "missing prefix length", in: "10.0.0.0/", wantErr: ErrInvalidProxy},
		{name: "truncated IPv4", in: "10.0.0", wantErr: ErrInvalidProxy},
		{name: "address with a port", in: "127.0.0.1:8080", wantErr: ErrInvalidProxy},
		{name: "bracketed address", in: "[::1]", wantErr: ErrInvalidProxy},
		{name: "one bad entry fails the whole list", in: "127.0.0.0/8,rubbish", wantErr: ErrInvalidProxy},
		{name: "IPv6 zone is refused", in: "fe80::1%eth0", wantErr: ErrZonedProxy},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParsePrefixes(tt.in)

			if tt.wantErr != nil {
				if err == nil {
					t.Fatalf("case %s was accepted, want rejected", tt.name)
				}
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("case %s produced the wrong sentinel error", tt.name)
				}
				if got != nil {
					t.Errorf("case %s returned a list alongside its error, want nil", tt.name)
				}
				return
			}

			if err != nil {
				t.Fatalf("case %s was rejected, want accepted", tt.name)
			}
			if got == nil {
				t.Fatalf("case %s returned a nil slice, want an empty one", tt.name)
			}
			// The counts are bound to plain integers before being reported. A
			// count is not address material, but len(got) mentions a name that
			// is, and the source check declines to reason about the difference.
			nGot, nWant := len(got), len(tt.want)
			if nGot != nWant {
				t.Fatalf("case %s produced %d prefixes, want %d", tt.name, nGot, nWant)
			}
			for n := 0; n < len(tt.want); n++ {
				if got[n] != mustPrefix(t, tt.want[n]) {
					t.Errorf("case %s: prefix %d is not the expected one", tt.name, n)
				}
			}
		})
	}
}

// TestParsePrefixesEmptyIsUsable: the empty result is what New is given on an
// unconfigured instance, and it must produce an Extractor that trusts nothing
// rather than one that panics or trusts everything.
func TestParsePrefixesEmptyIsUsable(t *testing.T) {
	prefixes, err := ParsePrefixes("")
	if err != nil {
		t.Fatalf("the empty list was rejected, want accepted")
	}
	if n := len(prefixes); n != 0 {
		t.Fatalf("the empty list produced %d prefixes, want 0", n)
	}
	e := New(prefixes)
	peer := addr(t, "127.0.0.1")
	if e.Addr(peer, "203.0.113.9") != peer {
		t.Errorf("an Extractor built from the empty list read the header, want it ignored")
	}
}

// --- New --------------------------------------------------------------------

// TestNewCopiesTheTrustedList: a caller must not be able to widen trust after
// construction by mutating the slice it handed over.
func TestNewCopiesTheTrustedList(t *testing.T) {
	prefixes := []netip.Prefix{mustPrefix(t, "127.0.0.0/8")}
	e := New(prefixes)

	prefixes[0] = mustPrefix(t, "0.0.0.0/0")

	peer := addr(t, "198.51.100.7")
	if e.Addr(peer, "203.0.113.9") != peer {
		t.Errorf("mutating the caller's slice widened the trusted list after construction")
	}
}

// TestNewDropsInvalidPrefixes: a zero Prefix matches nothing, so keeping it
// would only be a way to make the list look longer than it is.
func TestNewDropsInvalidPrefixes(t *testing.T) {
	e := New([]netip.Prefix{{}, mustPrefix(t, "127.0.0.0/8"), {}})

	peer := addr(t, "127.0.0.1")
	want := addr(t, "203.0.113.9")
	if e.Addr(peer, "203.0.113.9") != want {
		t.Errorf("a valid prefix alongside invalid ones stopped working")
	}
	if n := len(e.trusted); n != 1 {
		t.Errorf("the trusted list holds %d prefixes, want 1", n)
	}
}

// TestNewNormalisesPrefixes: New and ParsePrefixes must agree, or an operator's
// list would behave differently depending on which door it came in through.
func TestNewNormalisesPrefixes(t *testing.T) {
	tests := []struct {
		name  string
		given string
		peer  string
	}{
		{"host bits are masked off", "192.0.2.77/24", "192.0.2.1"},
		{"a mapped prefix is unmapped", "::ffff:172.17.0.0/112", "172.17.0.5"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := New([]netip.Prefix{mustPrefix(t, tt.given)})
			peer := addr(t, tt.peer)
			want := addr(t, "203.0.113.9")
			if e.Addr(peer, "203.0.113.9") != want {
				t.Errorf("case %s: the peer was not recognised as trusted", tt.name)
			}
		})
	}
}

// --- joined header field-lines ----------------------------------------------

// TestJoinedFieldLines documents the assumption Addr's contract states: where a
// request carries several X-Forwarded-For field-lines, the caller joins them in
// arrival order with a comma, and the rightmost entry of the join is still the
// address the trusted proxy observed.
func TestJoinedFieldLines(t *testing.T) {
	// What a client sent, followed by what the proxy appended as its own
	// field-line.
	lines := []string{"1.2.3.4", "5.6.7.8, 203.0.113.9"}

	e := extractor(t, localProxy)
	peer := addr(t, "127.0.0.1")
	want := addr(t, "203.0.113.9")

	if e.Addr(peer, strings.Join(lines, ",")) != want {
		t.Errorf("joining the field-lines in arrival order did not yield the proxy's observation")
	}
}

// TestTrustingEverythingFallsBackToThePeer covers the degenerate configuration
// an operator reaches for when the trusted list "does not seem to work":
// trusting the whole internet.
//
// Under the walk of §6.4 every entry in the header is a trusted proxy, so the
// list is exhausted and there is no client address in it — the peer is the
// nearest true observation and is what is returned.
//
// This is worth its own test because the rightmost-only rule it replaced was
// *bypassable* in this configuration: any client could set X-Forwarded-For and
// have that value taken as its own limiter key, with no proxy involved at all.
// The walk closes that. A configuration that trusts everything is now merely
// useless rather than an open door, and useless-not-dangerous is the failure
// direction §6.4 asks for throughout.
func TestTrustingEverythingFallsBackToThePeer(t *testing.T) {
	e := extractor(t, "0.0.0.0/0")
	peer := addr(t, "198.51.100.7")

	for _, xff := range []string{
		"1.2.3.4",
		"1.2.3.4, 5.6.7.8",
		"9.9.9.9, 1.2.3.4, 203.0.113.9",
	} {
		t.Run(xff, func(t *testing.T) {
			if e.Addr(peer, xff) != peer {
				t.Error("Addr did not return the peer: with everything trusted " +
					"the header holds no client address, and taking one from it " +
					"would let any client choose its own limiter key")
			}
		})
	}
}

// TestChainWalk covers the multi-proxy case §6.4 added: entries are consumed
// from the right while each is itself trusted, and the first that is not is the
// client.
//
// The shape modelled is client → CDN → inner proxy → directory, where the client
// has spoofed a header of its own. Each hop appends what it observed, so the
// arriving value is "spoofed, client_real, cdn_egress" and the peer is the inner
// proxy.
func TestChainWalk(t *testing.T) {
	const (
		spoofed    = "1.2.3.4"
		clientReal = "203.0.113.9"
		cdnEgress  = "192.0.2.50"
	)
	peer := addr(t, "172.28.0.5")

	t.Run("every hop enumerated finds the true client", func(t *testing.T) {
		e := extractor(t, "172.28.0.0/24,192.0.2.0/24")
		if e.Addr(peer, spoofed+", "+clientReal+", "+cdnEgress) != addr(t, clientReal) {
			t.Error("the walk did not return the true client: it must skip the " +
				"trusted CDN egress and stop at the first untrusted entry")
		}
	})

	t.Run("the spoofed entry is never reachable", func(t *testing.T) {
		e := extractor(t, "172.28.0.0/24,192.0.2.0/24")
		if e.Addr(peer, spoofed+", "+clientReal+", "+cdnEgress) == addr(t, spoofed) {
			t.Fatal("the client-supplied leftmost entry was used; every entry to " +
				"its right must be trusted before it can be reached")
		}
	})

	t.Run("under-enumeration degrades safely, never to a bypass", func(t *testing.T) {
		// The CDN's range is not listed, so the walk stops at it. Every client
		// behind that CDN shares one key: useless, but not forgeable.
		e := extractor(t, "172.28.0.0/24")
		got := e.Addr(peer, spoofed+", "+clientReal+", "+cdnEgress)
		if got != addr(t, cdnEgress) {
			t.Error("with the CDN unlisted the walk must stop at the CDN egress")
		}
		if got == addr(t, spoofed) {
			t.Fatal("under-enumeration must never expose the spoofed entry")
		}
	})
}
