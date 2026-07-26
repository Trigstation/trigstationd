// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Simon Wright

// Package b64 provides the unpadded base64url encoding used throughout the
// wire format (DIRECTORY-SPEC.md §0 and §4.4, RFC 4648 §5).
//
// The rule is strict in both directions:
//
//	"Implementations MUST NOT emit padding, and MUST reject padded input as
//	 malformed rather than stripping it."
//	"Base64url values MUST be canonically encoded."
//
// So Encode never emits '=', and Decode rejects both padding and a
// non-canonical spelling — one whose unused trailing bits are non-zero.
//
// # Why this is strict, when an earlier version of this package was not
//
// This package previously tolerated trailing '=' on input, reasoning that every
// signature in the protocol is computed over raw bytes rather than over the
// base64 text, so two spellings of one value could not produce two verification
// outcomes. That was true, and it stopped being sufficient when §5.2 made
// directories store and return envelopes verbatim.
//
// A tolerant directory no longer absorbs a malformed encoding. It stores those
// exact bytes and serves them unchanged to every client that queries, including
// strict ones — so tolerance distributes the problem instead of containing it.
// The directory is the only choke point in the system, and a choke point that
// launders malformed input is worse than none.
//
// The canonical-encoding rule closes the same gap from the other side. A 32-byte
// value occupies 43 characters carrying 258 bits, so two bits of the final
// character decode to nothing; without the rule there are four legal spellings
// of every such value, all of which verify and all of which would be served.
package b64

import (
	"encoding/base64"
	"errors"
	"fmt"
)

// ErrLength is returned by DecodeFixed when the decoded value is not the
// expected size. It is deliberately free of the offending value.
var ErrLength = errors.New("b64: unexpected decoded length")

// enc is the one encoding this package uses: unpadded base64url, strict.
//
// Strict is what enforces §4.4's canonical-encoding requirement — without it
// Go's decoder silently accepts non-zero trailing bits, which is exactly the
// multiple-spellings problem the rule exists to prevent. RawURLEncoding rejects
// '=' as an invalid character, which is what makes padded input an error rather
// than something to be trimmed.
var enc = base64.RawURLEncoding.Strict()

// Encode returns the unpadded base64url encoding of b.
func Encode(b []byte) string {
	return enc.EncodeToString(b)
}

// Decode decodes unpadded, canonically encoded base64url.
//
// Padded input is an error, not something to strip: a publisher that emits
// padding is violating §4.4's "MUST NOT emit padding", and the failure belongs
// at the point of publication where the party who can fix it will see it.
func Decode(s string) ([]byte, error) {
	return enc.DecodeString(s)
}

// DecodeFixed decodes s and requires the result to be exactly n bytes. Every
// binary field in the wire format except the ciphertext has a fixed width, so
// this is the usual entry point when parsing an envelope.
//
// The returned error names the field's expected size but never the value that
// failed, so that it is safe to surface in an error log.
func DecodeFixed(s string, n int) ([]byte, error) {
	b, err := Decode(s)
	if err != nil {
		return nil, err
	}
	if len(b) != n {
		return nil, fmt.Errorf("%w: want %d bytes, got %d", ErrLength, n, len(b))
	}
	return b, nil
}
