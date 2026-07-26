// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Simon Wright

// Package clientaddr resolves the address that rate limiting is keyed on when
// the directory runs behind a reverse proxy, under DIRECTORY-SPEC.md §6.4.
//
// # Why this package exists
//
// §9's deployment story terminates TLS in front of the directory, so a proxy is
// the normal configuration rather than an exotic one. A directory behind one
// sees the proxy's address on every request: every client in the world collapses
// into a single limiter key, the §6.2 limit is reached almost immediately, and
// the directory then refuses everybody. That is an outage, not a weakened
// defence.
//
// The remedy — reading the client address out of a forwarded header — brings its
// own hazard, because the header is under the client's control right up to the
// moment the trusted proxy touches it. §6.4 therefore imposes four rules, and
// each one alone leaves a hole. This package implements all four:
//
//  1. No trust by default. An empty trusted list means Addr returns the peer and
//     ignores the header entirely. Trusting X-Forwarded-For whenever it is
//     present is the evasion, not the fix: any client can set the header and so
//     choose its own limiter key.
//  2. Trust is decided by the immediate peer only. The header is consulted when,
//     and only when, the peer falls inside one of the configured prefixes.
//     Otherwise it is ignored completely.
//  3. The address taken from X-Forwarded-For is the RIGHTMOST entry, never the
//     leftmost. See rightmostEntry.
//  4. A forwarded address is subject to §6.4 in full. It is more sensitive than
//     the peer address, not less, because it is the address of an actual client
//     rather than of a machine the operator runs.
//
// An operator who deploys behind a proxy without configuring the list gets a
// limiter that is useless but safe, rather than one that is bypassable. That
// ordering is deliberate and is not a default to be softened.
//
// # What this package may not do
//
// Everything §6.4 forbids of internal/ratelimit is forbidden here, for the
// stronger reason that this package handles the address before truncation:
//
//   - The implementation imports errors, net/netip and strings, and nothing
//     else. There is no fmt, no log, no os, no io — no facility exists here with
//     which an address could reach an output stream, at any severity, under any
//     configuration. TestImportsAreAllowlisted holds that true after review.
//   - No type declared here has a String, Error or Marshal method, so nothing of
//     this package renders itself. netip.Addr is a Stringer and Addr returns
//     one, which is unavoidable and correct — the caller needs the value. What
//     must not happen is this package rendering it.
//   - Addr answers with a value and no error. An error is a string that travels,
//     and the string it would most naturally carry is the header it failed to
//     parse. Every failure here resolves to "use the peer" instead.
//   - The single error path, in ParsePrefixes, returns a fixed sentinel that
//     names nothing it was given. That input is operator configuration rather
//     than a client address, but a sentinel costs the operator only a glance at
//     a flag they typed themselves, and it means no misuse of this package in
//     future can turn a parse failure into a disclosure.
//
// # No HTTP
//
// This package takes a peer address and a header string. It does not import
// net/http and knows nothing about requests. That keeps it testable without a
// server, and keeps the trust decision out of middleware where it would be
// entangled with routing.
//
// # Concurrency
//
// An Extractor is immutable once constructed and is safe for concurrent use.
package clientaddr

import (
	"errors"
	"net/netip"
	"strings"
)

// ErrInvalidProxy is returned by ParsePrefixes for an entry that is neither a
// CIDR prefix nor a bare IP address.
//
// It deliberately does not name the offending entry. See the package comment:
// nothing here echoes its input, and the operator is looking at a flag value
// they typed.
// The text carries no context of its own, in the Go convention: the caller
// wrapping it names the flag, so an operator sees the whole of what they need.
var ErrInvalidProxy = errors.New("an entry is neither a CIDR prefix nor an IP address")

// ErrZonedProxy is returned by ParsePrefixes for an entry carrying an IPv6 zone,
// such as fe80::1%eth0.
//
// A zone is a property of the local host's interfaces, not of a network, and
// netip.Prefix cannot represent one. Accepting the entry would produce a prefix
// that silently matches nothing — a misconfiguration that presents as the outage
// this package exists to prevent, so it is refused at startup instead.
var ErrZonedProxy = errors.New("an IPv6 zone may not appear in a trusted proxy entry")

// Extractor resolves a client address against a fixed list of trusted proxies.
//
// The zero value trusts nothing, which is the §6.4 default and is safe: Addr on
// it returns the peer. Construct one with New.
type Extractor struct {
	// trusted holds the prefixes whose members may speak for another address.
	// These are the operator's own machines, which §6.4 rates as less sensitive
	// than a client address — but only less, so nothing renders them either.
	trusted []netip.Prefix
}

// New returns an Extractor that trusts the given proxy prefixes. A nil or empty
// slice trusts nothing, which is the default.
//
// The slice is copied, so a caller cannot widen trust after construction by
// mutating what it passed in. Each prefix is normalised the way ParsePrefixes
// normalises: masked to its network, and unmapped if it was given in
// IPv4-in-IPv6 form. Prefixes that are not valid are dropped, since a prefix
// that cannot match is indistinguishable from one that is absent.
func New(trusted []netip.Prefix) *Extractor {
	e := &Extractor{}
	if len(trusted) == 0 {
		return e
	}
	e.trusted = make([]netip.Prefix, 0, len(trusted))
	for _, p := range trusted {
		n := normalise(p)
		if n.IsValid() {
			e.trusted = append(e.trusted, n)
		}
	}
	return e
}

// Addr returns the address rate limiting should be keyed on.
//
// peer is the immediate transport peer. xff is the raw X-Forwarded-For header
// value, or "" if the header is absent.
//
// The result is always unmapped: an IPv4-in-IPv6 address such as
// ::ffff:198.51.100.7, which is what a client reaching a dual-stack listener
// presents as, comes back as 198.51.100.7. internal/ratelimit unmaps again
// before truncating, so this is belt and braces — but two places that agree on
// the form of an address cannot disagree about which bucket it lands in.
//
// # Multiple header field-lines
//
// This takes one string. Where a request carries several X-Forwarded-For
// field-lines, the caller MUST join them, in the order they arrived, with a
// comma — which is what RFC 9110 §5.3 says the combined field value means.
// net/http's Header.Values preserves arrival order, so strings.Join(…, ",") is
// the whole of it. A proxy appends its observation at the end of the last
// field-line or adds a new one after them, so under that joining rule the
// rightmost entry of the combined value is still the address the trusted proxy
// observed. A caller that passes only the first field-line would be reading a
// value the client fully controls; that is the caller's bug, and it is why the
// joining rule is stated here rather than assumed.
//
// # Failure is always "use the peer"
//
// An absent, empty, malformed or unparseable header yields peer. In particular
// an unparseable rightmost entry does not cause a walk further leftward: the
// entries to the left are attacker-chosen, so falling back to them would hand a
// client the choice of limiter key that rule 1 exists to deny it.
func (e *Extractor) Addr(peer netip.Addr, xff string) netip.Addr {
	p := peer.Unmap()

	// Rules 1 and 2, in one condition. With nothing trusted, or with a peer
	// that is not one of the trusted proxies, xff is not read at all — not
	// parsed, not inspected, not consulted as a tie-break.
	if e == nil || len(e.trusted) == 0 || !p.IsValid() || !e.trusts(p) {
		return p
	}

	return e.walk(xff, p)
}

// walk consumes X-Forwarded-For entries from the right while each is itself a
// trusted proxy, and returns the first that is not. That address is the client.
//
// # Why a walk, and why it is safe
//
// With one proxy this returns the rightmost entry and nothing more. The walk
// matters once a chain exists: with a CDN in front of a reverse proxy the
// rightmost entry is the address the inner proxy observed — the *outer proxy* —
// so taking it regardless would put every client behind that CDN into one
// rate-limiter key. That is the outage §6.4 exists to prevent, reintroduced by
// following its first sentence literally.
//
// Walking leftward over attacker-influenced entries sounds like the bypass this
// package is written to close, and it would be without the stopping condition.
// An entry is only ever reached when *every* entry to its right is trusted, so
// a client-supplied value is unreachable unless the operator has trusted the
// client's own address. The spoofed leftmost entry of
//
//	"1.2.3.4, client_real, cdn_egress"
//
// is never consulted: cdn_egress is trusted so it is skipped, client_real is not
// so the walk stops and returns it.
//
// The failure direction is safe. An operator who under-enumerates the hops gets
// a walk that stops early at a proxy's address, collapsing clients behind it
// into one key — useless, but exactly the single-proxy behaviour, and never
// bypassable.
//
// Note the hazard §6.4 states and this code cannot enforce: a trusted range that
// is *shared* trusts every party able to send from it. Listing a CDN's egress
// ranges permits any customer of that CDN to forge a client address.
func (e *Extractor) walk(xff string, peer netip.Addr) netip.Addr {
	rest := xff
	for {
		entry, remainder, found := lastEntry(rest)
		if entry == "" && !found {
			// Ran out of entries: every one was a trusted proxy. There is no
			// client address in the header, so the nearest true observation is
			// the peer.
			return peer
		}

		addr, ok := parseEntry(entry)
		if !ok {
			// An unparseable entry stops the walk at the peer rather than
			// stepping past it. The next entry along is attacker-influenced,
			// and skipping to it is the bypass wearing a different hat.
			return peer
		}
		if !e.trusts(addr) {
			return addr
		}
		rest = remainder
	}
}

// lastEntry splits the final comma-separated entry from an X-Forwarded-For
// value, returning it trimmed along with everything to its left. found reports
// whether an entry was present at all, which distinguishes an exhausted list
// from one whose final entry is empty.
func lastEntry(s string) (entry, remainder string, found bool) {
	if strings.TrimSpace(s) == "" {
		return "", "", false
	}
	if i := strings.LastIndexByte(s, ','); i >= 0 {
		return strings.TrimSpace(s[i+1:]), s[:i], true
	}
	return strings.TrimSpace(s), "", true
}

// trusts reports whether a is inside one of the configured prefixes.
//
// The list is short — an operator runs one proxy, or a handful — so a linear
// scan is both the clearest and the fastest thing available.
//
// netip.Prefix.Contains answers false for an address carrying an IPv6 zone and
// for one of the other family. Both are the right answer here: an unconfigured
// or mismatched peer is untrusted, and this package fails towards ignoring the
// header.
func (e *Extractor) trusts(a netip.Addr) bool {
	for _, p := range e.trusted {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// rightmostEntry returns the last comma-separated entry of an X-Forwarded-For
// value, with surrounding optional whitespace removed.
//
// # Rightmost, not leftmost
//
// This is the crux of §6.4 and the most common way the header is read wrongly.
// A client may send its own X-Forwarded-For. The proxy does not replace it: it
// preserves what arrived and appends the address it observed. So in
//
//	X-Forwarded-For: 1.2.3.4, 203.0.113.9
//
// the value 1.2.3.4 was chosen by whoever made the request and 203.0.113.9 is
// what the trusted proxy actually saw. Taking the leftmost entry lets any client
// pick its own limiter key with one header — and it looks correct under test,
// because honest clients send no such header and every entry is then the
// proxy's. TestRightmostEntryDefeatsAClientSuppliedHeader exists so that a future
// reader cannot "simplify" this to the leftmost without a failing test.
//
// An empty result — no header, an empty header, whitespace only, or a trailing
// comma — is returned as "" and the caller falls back to the peer. It does not
// step leftward to find something non-empty, for the same reason.
func rightmostEntry(xff string) string {
	if i := strings.LastIndexByte(xff, ','); i >= 0 {
		xff = xff[i+1:]
	}
	return strings.TrimSpace(xff)
}

// parseEntry parses one X-Forwarded-For entry, reporting whether it was
// understood.
//
// Three forms are accepted, in an order chosen so that no input is read two
// ways:
//
//   - A bare address, which covers 198.51.100.7 and 2001:db8::1. This is tried
//     first, so a bare IPv6 address is never mistaken for a host:port pair. The
//     ambiguity is real — ::1:80 is both a valid address and something that
//     looks like port 80 on ::1 — and resolving it in favour of the address is
//     the only reading that cannot be manufactured, since an address is what the
//     header field is defined to hold.
//   - A bracketed IPv6 address with no port, [2001:db8::1], which some proxies
//     emit.
//   - An address with a port, either 198.51.100.7:41234 or [2001:db8::1]:41234.
//     netip.ParseAddrPort requires the brackets for IPv6, so this form is
//     unambiguous by construction; an unbracketed IPv6-with-port such as
//     2001:db8::1:41234 is indistinguishable from an address and is read as one.
//
// Anything else — an RFC 7239 obfuscated identifier, a quoted value, a hostname,
// rubbish — is not understood, and the caller uses the peer.
func parseEntry(entry string) (netip.Addr, bool) {
	if entry == "" {
		return netip.Addr{}, false
	}
	if a, err := netip.ParseAddr(entry); err == nil {
		return a.Unmap(), a.IsValid()
	}
	if len(entry) > 2 && entry[0] == '[' && entry[len(entry)-1] == ']' {
		if a, err := netip.ParseAddr(entry[1 : len(entry)-1]); err == nil {
			return a.Unmap(), a.IsValid()
		}
		return netip.Addr{}, false
	}
	if ap, err := netip.ParseAddrPort(entry); err == nil {
		a := ap.Addr().Unmap()
		return a, a.IsValid()
	}
	return netip.Addr{}, false
}

// ParsePrefixes parses a comma-separated list of CIDR prefixes and bare
// addresses for the -trusted-proxies flag. A bare address becomes a single-host
// prefix. Empty input yields an empty slice and no error.
//
// Whitespace around entries is ignored, and an empty entry — which is what a
// trailing comma produces — is skipped rather than refused. Skipping can only
// ever narrow the list, so it cannot create trust that the operator did not
// write.
//
// Every accepted entry is normalised: masked to its network, so that
// 10.1.2.3/8 and 10.0.0.0/8 are stored identically, and unmapped where it was
// written in IPv4-in-IPv6 form. See normalise.
//
// Errors are the fixed sentinels ErrInvalidProxy and ErrZonedProxy, which name
// nothing they were given.
func ParsePrefixes(s string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0)
	if strings.TrimSpace(s) == "" {
		return out, nil
	}
	for _, field := range strings.Split(s, ",") {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}

		p, perr := netip.ParsePrefix(field)
		if perr != nil {
			// Not a CIDR prefix, so try a bare address, which stands for the
			// single host.
			a, aerr := netip.ParseAddr(field)
			if aerr != nil {
				return nil, ErrInvalidProxy
			}
			if a.Zone() != "" {
				return nil, ErrZonedProxy
			}
			a = a.Unmap()
			p = netip.PrefixFrom(a, a.BitLen())
		}

		n := normalise(p)
		if !n.IsValid() {
			return nil, ErrInvalidProxy
		}
		out = append(out, n)
	}
	return out, nil
}

// normalise puts a prefix into the one form Addr compares against.
//
// Two things happen. An IPv4-in-IPv6 prefix is unmapped, because Addr unmaps the
// peer before matching and netip.Prefix.Contains answers false across families —
// so an operator who writes ::ffff:172.17.0.0/112 would otherwise get a trusted
// list that matches nothing, and a list that matches nothing is exactly the
// collapsed-to-one-key outage §6.4 describes. Unmapping is exact rather than
// approximate: the mapped range occupies the last 32 bits of a /96, so a /112
// over it is the same set of hosts as a /16 under it.
//
// A mapped prefix broader than /96 covers addresses outside the mapped range and
// so has no IPv4 equivalent; it is left alone, and will match nothing.
//
// Then the prefix is masked, so that the host bits an operator left in are
// discarded rather than carried around in configuration.
func normalise(p netip.Prefix) netip.Prefix {
	if !p.IsValid() {
		return netip.Prefix{}
	}
	if a := p.Addr(); a.Is4In6() && p.Bits() >= 96 {
		p = netip.PrefixFrom(a.Unmap(), p.Bits()-96)
	}
	return p.Masked()
}
