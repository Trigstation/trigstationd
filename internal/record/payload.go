// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Simon Wright

package record

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
)

// RecordKeyLen is the AES-256 key size. The payload is encrypted under the
// epoch's RecordKey, which the directory never holds.
const RecordKeyLen = 32

var (
	ErrRecordKeyLen = errors.New("record: RecordKey must be 32 bytes")
	ErrNonceLen     = errors.New("record: nonce must be 12 bytes")
)

// newGCM builds the AEAD used for the payload: AES-256-GCM with a 12-byte
// nonce, per DIRECTORY-SPEC.md §0 and §4.1.
//
// DIRECTORY-SPEC.md §4.4 records why this is AES-GCM rather than a ChaCha20
// variant: AES-GCM is in the standard library of every platform the protocol is
// likely to reach, including .NET, Java and WebCrypto, whereas
// XChaCha20-Poly1305 would force a libsodium dependency on those. It is a
// portability decision, not a cryptographic preference, and it is wire format.
func newGCM(recordKey []byte) (cipher.AEAD, error) {
	if len(recordKey) != RecordKeyLen {
		return nil, ErrRecordKeyLen
	}
	block, err := aes.NewCipher(recordKey)
	if err != nil {
		return nil, fmt.Errorf("record: aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("record: gcm: %w", err)
	}
	if gcm.NonceSize() != NonceLen {
		// Defensive: crypto/cipher's standard GCM is 12-byte nonce, but the
		// wire format depends on it, so assert rather than assume.
		return nil, ErrNonceLen
	}
	return gcm, nil
}

// Seal encrypts the payload under RecordKey with a fresh random nonce, and
// returns the nonce and the ciphertext with its 16-byte tag appended.
//
// DIRECTORY-SPEC.md §4.1 is explicit that the nonce is 12 bytes freshly
// generated for every publish, that it MUST NOT be a counter, and that it MUST
// come from a CSPRNG. crypto/rand is the only source used here. No additional
// authenticated data is used.
func Seal(recordKey, plaintext []byte) (nonce, ct []byte, err error) {
	gcm, err := newGCM(recordKey)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, NonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("record: nonce: %w", err)
	}
	return nonce, gcm.Seal(nil, nonce, plaintext, nil), nil
}

// SealWithNonce encrypts under a caller-supplied nonce.
//
// This exists solely so that the committed test vectors are reproducible: a
// vector whose nonce came from a CSPRNG could not be regenerated or checked by
// anyone else. Nothing that publishes a real record may use it. Reusing a nonce
// under one RecordKey is a total loss of confidentiality and integrity for
// AES-GCM, which is precisely why Seal does not take one.
func SealWithNonce(recordKey, nonce, plaintext []byte) ([]byte, error) {
	gcm, err := newGCM(recordKey)
	if err != nil {
		return nil, err
	}
	if len(nonce) != NonceLen {
		return nil, ErrNonceLen
	}
	return gcm.Seal(nil, nonce, plaintext, nil), nil
}

// Open authenticates and decrypts a payload.
//
// Per DIRECTORY-SPEC.md §5.3, a client attempts this against every envelope a
// prefix query returned, and authentication failure is the filter: exactly one
// will succeed and the rest are discarded. A failure here is therefore an
// ordinary, expected outcome on the client path, not an anomaly.
func Open(recordKey, nonce, ct []byte) ([]byte, error) {
	gcm, err := newGCM(recordKey)
	if err != nil {
		return nil, err
	}
	if len(nonce) != NonceLen {
		return nil, ErrNonceLen
	}
	pt, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("record: payload did not authenticate: %w", err)
	}
	return pt, nil
}
