// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Simon Wright

// Package record implements the envelope and payload formats of
// DIRECTORY-SPEC.md §4.
//
// The split matters. The envelope is what the directory stores and can see: an
// opaque identifier, an ephemeral public key, an expiry and ciphertext. The
// payload is what the paired client decrypts. This package can construct both,
// because it also generates the test vectors, but the server side of the
// codebase uses only the envelope half — Verify, and nothing that touches a
// RecordKey.
package record

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/trigstation/trigstationd/internal/b64"
)

// Version is the protocol version pinned by DIRECTORY-SPEC.md §10.
const Version = 1

// Field widths from DIRECTORY-SPEC.md §4.1.
const (
	LookupIDLen = 32
	WKPubLen    = 32
	NonceLen    = 12
	PoWLen      = 8
	SigLen      = ed25519.SignatureSize // 64
	TagLen      = 16                    // AES-GCM tag, appended to the ciphertext
)

// MaxEnvelopeBytes is the default cap from DIRECTORY-SPEC.md §4.3, applied to
// the encoded envelope as received.
const MaxEnvelopeBytes = 4096

// MaxTTL is the default maximum record lifetime from DIRECTORY-SPEC.md §4.3.
const MaxTTL = 48 * 60 * 60

// Errors returned when an envelope fails to parse or verify.
//
// Each names the failure mode and never the value that caused it, so that any
// of them is safe to surface. Logging the offending lookup_id or wk_pub would
// defeat the point of the service; see CLAUDE.md, "No request logging".
var (
	ErrVersion    = errors.New("record: unsupported envelope version")
	ErrFieldSize  = errors.New("record: field has wrong length")
	ErrLookupID   = errors.New("record: lookup_id is not SHA-256(wk_pub)")
	ErrSignature  = errors.New("record: envelope signature does not verify")
	ErrCiphertext = errors.New("record: ciphertext shorter than the AEAD tag")
)

// Envelope is the outer record, DIRECTORY-SPEC.md §4.1.
//
// Binary fields are unpadded base64url on the wire. They are kept as strings
// here so that a malformed field is a decode error at the point of use rather
// than a parse failure that loses the rest of the envelope.
//
// Unknown fields are ignored on decode, never rejected (DIRECTORY-SPEC.md §5
// and §10). encoding/json does that by default; do not add DisallowUnknownFields.
type Envelope struct {
	V         int    `json:"v"`
	LookupID  string `json:"lookup_id"`
	WKPub     string `json:"wk_pub"`
	ExpiresAt int64  `json:"expires_at"`
	CT        string `json:"ct"`
	Nonce     string `json:"nonce"`
	PoW       string `json:"pow"`
	Sig       string `json:"sig"`
}

// Decoded holds an envelope's binary fields after base64url decoding and length
// checking. Holding the raw bytes separately keeps the verification path from
// decoding the same field twice.
type Decoded struct {
	V         uint8
	LookupID  []byte
	WKPub     []byte
	ExpiresAt int64
	CT        []byte
	Nonce     []byte
	PoW       []byte
	Sig       []byte
}

// Decode parses and length-checks every binary field of an envelope. It does
// not verify the signature, the lookup_id binding or the proof of work; see
// Verify and the pow package for those.
func (e *Envelope) Decode() (*Decoded, error) {
	if e.V != Version {
		return nil, fmt.Errorf("%w: want %d, got %d", ErrVersion, Version, e.V)
	}

	d := &Decoded{V: uint8(e.V), ExpiresAt: e.ExpiresAt}

	fields := []struct {
		name string
		src  string
		n    int
		dst  *[]byte
	}{
		{"lookup_id", e.LookupID, LookupIDLen, &d.LookupID},
		{"wk_pub", e.WKPub, WKPubLen, &d.WKPub},
		{"nonce", e.Nonce, NonceLen, &d.Nonce},
		{"pow", e.PoW, PoWLen, &d.PoW},
		{"sig", e.Sig, SigLen, &d.Sig},
	}
	for _, f := range fields {
		v, err := b64.DecodeFixed(f.src, f.n)
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %v", ErrFieldSize, f.name, err)
		}
		*f.dst = v
	}

	// ct is the only variable-length field. It must at least hold the AEAD tag.
	ct, err := b64.Decode(e.CT)
	if err != nil {
		return nil, fmt.Errorf("%w: ct: %v", ErrFieldSize, err)
	}
	if len(ct) < TagLen {
		return nil, ErrCiphertext
	}
	d.CT = ct

	return d, nil
}

// SigningBytes returns the canonical form this envelope's signature covers.
func (d *Decoded) SigningBytes() []byte {
	return CanonicalEnvelope(d.V, d.LookupID, d.WKPub, d.ExpiresAt, d.Nonce, d.CT)
}

// Verify checks the two authorisation conditions that live in this package:
// that lookup_id equals SHA-256(wk_pub), and that sig verifies under wk_pub.
//
// These are the first two bullets of DIRECTORY-SPEC.md §5.2. The remaining
// three — expiry window, envelope size and proof of work — are enforced by the
// caller, because they depend on the instance's advertised limits and on the
// current time rather than on the envelope alone.
//
// Note what this does not establish. A valid signature proves only that the
// writer held WK_priv for this epoch, which every paired client can derive. It
// is not proof that the record came from the server. That guarantee is the
// inner payload signature under IK, which only a client can check
// (DIRECTORY-SPEC.md §8.1).
func (d *Decoded) Verify() error {
	want := sha256.Sum256(d.WKPub)
	if subtle.ConstantTimeCompare(want[:], d.LookupID) != 1 {
		return ErrLookupID
	}
	if !ed25519.Verify(ed25519.PublicKey(d.WKPub), d.SigningBytes(), d.Sig) {
		return ErrSignature
	}
	return nil
}

// Sign produces the envelope signature over the canonical form. It is used to
// build test vectors; a directory never signs anything.
func Sign(wk ed25519.PrivateKey, v uint8, lookupID, wkPub []byte, expiresAt int64, nonce, ct []byte) []byte {
	return ed25519.Sign(wk, CanonicalEnvelope(v, lookupID, wkPub, expiresAt, nonce, ct))
}
