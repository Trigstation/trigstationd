// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Simon Wright

// Package b64 provides the unpadded base64url encoding used throughout the
// wire format (DIRECTORY-SPEC.md §0 and §4.4, RFC 4648 §5).
//
// The rule in the spec is deliberately asymmetric:
//
//	"Implementations MUST accept unpadded input and MUST NOT emit padding."
//
// Encode therefore never emits '='. Decode accepts the unpadded form the spec
// mandates, and additionally tolerates trailing padding on input so that a peer
// which emits padding in violation of the spec still interoperates on the
// receive path. Tolerating padding is safe here because every signature in the
// protocol is computed over raw bytes, never over the base64 text, so two
// spellings of the same value cannot produce two different verification
// outcomes.
package b64

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// ErrLength is returned by DecodeFixed when the decoded value is not the
// expected size. It is deliberately free of the offending value.
var ErrLength = errors.New("b64: unexpected decoded length")

// Encode returns the unpadded base64url encoding of b.
func Encode(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// Decode decodes unpadded base64url. Trailing '=' padding is tolerated on
// input but is not required and is never produced by Encode.
func Decode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
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
