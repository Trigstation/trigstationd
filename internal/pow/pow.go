// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Simon Wright

// Package pow implements the publish proof of work of DIRECTORY-SPEC.md §6.1.
//
// The directory only ever verifies. Solve is here because the test vectors ship
// a solved value, and because a worked example of the search is useful to
// implementers — but a directory that solves proofs of work has misunderstood
// which side of the exchange it is on.
package pow

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/bits"
)

// Prefix is the domain separation string from DIRECTORY-SPEC.md §0. It is
// byte-exact wire format.
const Prefix = "trig-pow-v1"

// Len is the width of the pow field in the envelope: "an 8-byte counter"
// (§6.1), which the §0.1 width table restates as 8 bytes.
const Len = 8

// DefaultBits is the default difficulty from DIRECTORY-SPEC.md §6.1, described
// there as roughly 100 ms of CPU for an honest publisher.
//
// An instance advertises its own value in GET /v1/meta and MAY raise it under
// load. Clients MUST read it rather than hardcoding, so nothing outside this
// constant's own default should depend on the number being 20.
const DefaultBits = 20

// MaxBits guards Solve against a difficulty that would never terminate. It is
// not a protocol limit; it is a refusal to spin forever on a nonsensical input.
const MaxBits = 40

var (
	ErrBits      = errors.New("pow: difficulty out of range")
	ErrExhausted = errors.New("pow: counter space exhausted without a solution")
)

// Input builds the byte string that is hashed (DIRECTORY-SPEC.md §6.1):
//
//	SHA-256("trig-pow-v1" || lookup_id || expires_at || pow)
//
// # Integer encoding
//
// Per DIRECTORY-SPEC.md §0.1, expires_at is an 8-byte big-endian unsigned
// integer here, as it is in the envelope signing input. The §0.1 width table
// also gives the pow counter as 8 bytes, matching Len below.
//
// Divergence is fatal to interoperability and hard to diagnose: a publisher
// that encodes expires_at differently produces a pow this directory rejects
// with 403, indistinguishable under §5.2 from a signature failure.
//
// Note also that the proof binds only lookup_id and expires_at — not wk_pub,
// nonce or ct. A solved proof therefore remains valid for any payload published
// under the same identifier and expiry, so it can be reused across republishes
// within that second. Given that lookup_id is bound to wk_pub by §5.2 and the
// expiry is bounded by max_ttl, this is a cost the spec appears to accept
// deliberately: the work is priced per identifier, not per record.
func Input(lookupID []byte, expiresAt int64, pow []byte) []byte {
	out := make([]byte, 0, len(Prefix)+len(lookupID)+8+len(pow))
	out = append(out, Prefix...)
	out = append(out, lookupID...)
	out = binary.BigEndian.AppendUint64(out, uint64(expiresAt))
	out = append(out, pow...)
	return out
}

// LeadingZeroBits counts the leading zero bits of a digest.
func LeadingZeroBits(digest []byte) int {
	n := 0
	for _, b := range digest {
		if b != 0 {
			return n + bits.LeadingZeros8(b)
		}
		n += 8
	}
	return n
}

// Verify reports whether pow satisfies the challenge at the given difficulty.
//
// A pow field of the wrong length fails rather than being padded or truncated:
// accepting a short counter would let a publisher search a different, smaller
// input space than the one the difficulty was priced for.
func Verify(lookupID []byte, expiresAt int64, pow []byte, powBits int) bool {
	if len(pow) != Len || powBits < 0 {
		return false
	}
	sum := sha256.Sum256(Input(lookupID, expiresAt, pow))
	return LeadingZeroBits(sum[:]) >= powBits
}

// Solve searches for a counter satisfying the challenge, returning the 8-byte
// value to place in the envelope.
//
// The counter is incremented as a big-endian uint64 starting from zero. Search
// order has no protocol significance — only the resulting hash is checked — so
// an implementation is free to search differently, and a parallel solver would
// simply partition the space.
//
// ctx is honoured between attempts so that a caller can abandon a difficulty
// that turns out to be more expensive than expected.
func Solve(ctx context.Context, lookupID []byte, expiresAt int64, powBits int) ([]byte, error) {
	if powBits < 0 || powBits > MaxBits {
		return nil, ErrBits
	}

	// Build the fixed prefix once and mutate only the trailing counter. At 20
	// bits this saves roughly a million redundant copies of the same 51 bytes.
	buf := Input(lookupID, expiresAt, make([]byte, Len))
	counter := buf[len(buf)-Len:]

	const checkInterval = 1 << 16
	for i := uint64(0); ; i++ {
		if i%checkInterval == 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
			}
		}

		binary.BigEndian.PutUint64(counter, i)
		sum := sha256.Sum256(buf)
		if LeadingZeroBits(sum[:]) >= powBits {
			out := make([]byte, Len)
			copy(out, counter)
			return out, nil
		}

		if i == ^uint64(0) {
			return nil, ErrExhausted
		}
	}
}
