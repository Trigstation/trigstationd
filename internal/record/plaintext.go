// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Simon Wright

package record

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
)

// The payload plaintext, DIRECTORY-SPEC.md §4.2.
//
// This is what sits inside ct. The directory never sees it, never decrypts it,
// and — critically — never verifies the signature it carries. Nothing in the
// server half of this codebase calls anything in this file. It exists so the
// test vectors can contain a complete record, and so that the client-side
// verification rule has a worked example.
//
// # Layout
//
//	offset   size  field
//	------   ----  ---------------------------------------------------
//	0        2     body_len, uint16 big-endian
//	2        N     body, UTF-8 JSON
//	2+N      64    sig, Ed25519(IK_priv, body)
//
// # The verification rule, which is the whole point
//
// sig is detached and covers the LITERAL TRANSMITTED BYTES of body. §4.2 is
// emphatic: a verifier MUST verify over the received bytes and MUST NOT
// re-serialise, reorder or normalise first. There is no canonicalisation rule
// for the payload and none is needed — the verifier never reconstructs the
// signing input, because it already has it.
//
// The practical consequence for anyone maintaining this file: never unmarshal
// body and then re-marshal it to verify. Go's encoding/json would round-trip
// most inputs unchanged and the bug would pass every test written against
// bodies this codebase generated, then fail against every other implementation
// on key ordering, whitespace or number formatting. VerifyPayload therefore
// takes raw bytes and there is deliberately no overload that takes a Body.
//
// This is the detached-payload pattern of JWS and COSE. §4.2 prefers it over a
// canonical binary encoding because endpoints, tls and caps are composite and
// variable-length, where the bare concatenation used for the envelope (§4.1)
// would be neither well defined nor injective.
//
// The signature stays inside the ciphertext deliberately (§4.2, final
// paragraph): an inner signature visible in the envelope would let anyone
// holding a server's ik_pub pick that server's record out of a prefix bucket
// and defeat the blinding of §5.3. Do not move it into the envelope.

// Payload plaintext framing sizes.
const (
	// BodyLenSize is the width of the uint16 big-endian length prefix.
	BodyLenSize = 2

	// PayloadSigLen is the detached Ed25519 signature appended after body.
	PayloadSigLen = ed25519.SignatureSize // 64

	// MaxBodyLen is the largest body the uint16 length prefix can describe.
	// The §4.3 envelope cap of 4096 bytes binds long before this does.
	MaxBodyLen = 1<<16 - 1
)

// Endpoint types from the DIRECTORY-SPEC.md §4.2 example.
const (
	EndpointLAN  = "lan"
	EndpointWAN4 = "wan4"
	EndpointWAN6 = "wan6"
	EndpointDNS  = "dns"
)

// TLS modes from DIRECTORY-SPEC.md §4.2.
const (
	TLSModePKI    = "pki"
	TLSModePinned = "pinned"
)

var (
	ErrPayloadFormat    = errors.New("record: payload plaintext is malformed")
	ErrBodyTooLarge     = errors.New("record: payload body exceeds the uint16 length prefix")
	ErrPayloadSignature = errors.New("record: payload signature does not verify under ik_pub")
)

// Endpoint is one candidate address for the media server.
type Endpoint struct {
	Type string `json:"type"`
	Host string `json:"host"`
	Port int    `json:"port"`
}

// TLSInfo describes how the client should authenticate the media server's
// certificate. Fingerprint is set only when Mode is "pinned", in which case it
// is the SHA-256 of the server certificate.
type TLSInfo struct {
	Mode        string `json:"mode"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

// Body is the JSON object that the detached signature covers.
//
// There is no Sig field: the signature is not part of the JSON, it follows it.
// Adding one back would reintroduce exactly the chicken-and-egg the detached
// layout exists to avoid.
//
// This type is a convenience for constructing and reading bodies. It is not the
// signing input and must never be used as one — see the note on VerifyPayload.
// endpoints and caps are ordered sequences, not sets (§4.2); a verifier MUST
// NOT reorder them, and since verification is over raw bytes, reordering would
// break the signature anyway.
type Body struct {
	V         int        `json:"v"`
	TS        int64      `json:"ts"`
	Endpoints []Endpoint `json:"endpoints"`
	TLS       TLSInfo    `json:"tls"`
	Caps      []string   `json:"caps"`
}

// MarshalPlaintext frames and signs a body, producing the plaintext to encrypt.
//
// body is taken as bytes, already serialised by the caller, because those exact
// bytes are what the signature covers. "Serialised however the implementation
// likes" (§4.2) is only true if the bytes that were signed are the bytes that
// are sent.
func MarshalPlaintext(ik ed25519.PrivateKey, body []byte) ([]byte, error) {
	if len(body) > MaxBodyLen {
		return nil, fmt.Errorf("%w: %d bytes", ErrBodyTooLarge, len(body))
	}

	out := make([]byte, 0, BodyLenSize+len(body)+PayloadSigLen)
	out = binary.BigEndian.AppendUint16(out, uint16(len(body)))
	out = append(out, body...)
	out = append(out, ed25519.Sign(ik, body)...)
	return out, nil
}

// ParsePlaintext splits a decrypted plaintext into the literal body bytes and
// the detached signature.
//
// The returned body aliases plaintext; callers must not modify either.
//
// A plaintext whose length is not exactly 2 + body_len + 64 is rejected rather
// than truncated. Trailing bytes would mean the framing no longer determines
// what was signed, and silently ignoring them is how a parser turns into an
// attack surface. See the phase 1b report, ambiguity #1 — the spec's offset
// table implies an exact length but does not say so outright.
func ParsePlaintext(plaintext []byte) (body, sig []byte, err error) {
	if len(plaintext) < BodyLenSize+PayloadSigLen {
		return nil, nil, fmt.Errorf("%w: shorter than the framing", ErrPayloadFormat)
	}

	bodyLen := int(binary.BigEndian.Uint16(plaintext[:BodyLenSize]))
	want := BodyLenSize + bodyLen + PayloadSigLen
	if len(plaintext) != want {
		return nil, nil, fmt.Errorf("%w: length %d, framing declares %d",
			ErrPayloadFormat, len(plaintext), want)
	}

	body = plaintext[BodyLenSize : BodyLenSize+bodyLen]
	sig = plaintext[BodyLenSize+bodyLen:]
	return body, sig, nil
}

// VerifyPayload checks the detached signature over the literal body bytes.
//
// This is the check that establishes authenticity (§4.2). A client MUST perform
// it against the ik_pub obtained at pairing and MUST discard the record if it
// fails. A directory can neither produce nor tamper with this signature, and
// must not attempt to verify it — it holds no ik_pub and never will.
//
// body MUST be the bytes as received. There is intentionally no variant of this
// function that accepts a Body struct, because such a variant could only work
// by re-serialising, which §4.2 forbids.
func VerifyPayload(ikPub ed25519.PublicKey, body, sig []byte) error {
	if len(sig) != PayloadSigLen {
		return fmt.Errorf("%w: signature is %d bytes", ErrPayloadSignature, len(sig))
	}
	if !ed25519.Verify(ikPub, body, sig) {
		return ErrPayloadSignature
	}
	return nil
}

// VerifyPlaintext parses a decrypted plaintext and verifies its detached
// signature, returning the literal body bytes on success.
//
// This is the whole client-side check in one call, and the returned bytes are
// the ones the caller should unmarshal for reading. Unmarshalling is a read
// operation only; the bytes remain the authority.
func VerifyPlaintext(ikPub ed25519.PublicKey, plaintext []byte) ([]byte, error) {
	body, sig, err := ParsePlaintext(plaintext)
	if err != nil {
		return nil, err
	}
	if err := VerifyPayload(ikPub, body, sig); err != nil {
		return nil, err
	}
	return body, nil
}
