// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Simon Wright

// Package derive implements the epoch-derived key schedule of
// DIRECTORY-SPEC.md §3.3, and the mirrored pairing schedule of
// PAIRING-SPEC.md §3.1.
//
// Nothing in this package is used by the directory service itself. A directory
// never derives a key — it only verifies an Ed25519 signature and recomputes
// one SHA-256 (DIRECTORY-SPEC.md §4.4). This package exists so that the
// reference implementation can generate the test vectors that independent
// implementations check themselves against, and so that the derivations have a
// worked example in the same language as the server.
//
// # Encoding of the epoch in the HKDF info string
//
// §0.1 is normative and absolute: wherever the specification concatenates an
// integer into a byte string, it is a fixed-width unsigned big-endian integer,
// never decimal text. The width table gives `epoch` as 8 bytes, and §3.3
// restates it for these derivations specifically. epochInfo implements exactly
// that and TestEpochInfoEncoding pins it.
//
// §0.1 also explains why it is worth a normative rule of its own: divergence is
// silent. Two implementations each behave correctly in isolation and can never
// read each other's records, because every one of WriteSeed, LookupID,
// RecordKey and MailboxID differs, and the failure presents as "the directory
// has no record" rather than as any kind of protocol error.
//
// # HKDF construction
//
// §3.3 specifies full RFC 5869 Extract-then-Expand with an empty salt, which
// RFC 5869 §2.2 defines as HashLen zero bytes. The spec explicitly rejects the
// Expand-only reading — permissible under RFC 5869 §3.3, since S_dir is already
// 32 uniformly random bytes — because it produces entirely different output.
// Go's hkdf.Key with a nil salt is precisely the specified construction.
package derive

import (
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// Info strings from DIRECTORY-SPEC.md §0. These are byte-exact wire format and
// must not be altered.
const (
	InfoWrite   = "trig-write-v1"
	InfoRecord  = "trig-record-v1"
	InfoMailbox = "trig-mailbox-v1"

	// Pairing derivations, PAIRING-SPEC.md §3.1. Distinct labels so that a
	// pairing record and a normal record can never collide.
	InfoPairWrite  = "trig-pair-write-v1"
	InfoPairRecord = "trig-pair-record-v1"
)

// EpochSeconds is the epoch length from DIRECTORY-SPEC.md §3.3: one day, UTC.
//
// DIRECTORY-SPEC.md §11.1 lists the epoch length as an open question — 6 hours
// and 7 days are both under consideration. Changing this constant changes every
// derived identifier, so it is wire format, not a tuning knob.
const EpochSeconds = 86400

// SDirLen is the length of the directory secret S_dir (DIRECTORY-SPEC.md §3.1).
const SDirLen = 32

// KeyLen is the length of every value this package derives.
const KeyLen = 32

// ErrSDirLen reports a directory secret of the wrong size. It never contains
// the secret.
var ErrSDirLen = errors.New("derive: S_dir must be 32 bytes")

// Epoch returns floor(unixTime / EpochSeconds) per DIRECTORY-SPEC.md §3.3.
//
// Go's integer division truncates towards zero, which is not floor for negative
// operands, so pre-epoch timestamps are handled explicitly. They cannot arise
// in practice, but silently deriving a different key for them would be a nasty
// way to find that out.
func Epoch(unixTime int64) int64 {
	if unixTime < 0 {
		// -1 / 86400 truncates to 0; floor is -1.
		return -((-unixTime + EpochSeconds - 1) / EpochSeconds)
	}
	return unixTime / EpochSeconds
}

// EpochStart returns the first second of the given epoch.
func EpochStart(epoch int64) int64 {
	return epoch * EpochSeconds
}

// epochInfo builds the HKDF info string: the fixed label followed by the epoch
// as an 8-byte big-endian unsigned integer, per DIRECTORY-SPEC.md §0.1.
func epochInfo(label string, epoch int64) string {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(epoch))
	return label + string(b[:])
}

// derived runs HKDF-SHA256 over a 32-byte secret for the given label and epoch.
// The secret is S_dir for the §3.3 derivations and S_pair for the
// PAIRING-SPEC.md §3.1 ones; the construction is identical, which is why they
// share this function.
func derived(secret []byte, label string, epoch int64) ([]byte, error) {
	if len(secret) != SDirLen {
		return nil, ErrSDirLen
	}
	// Salt is nil: RFC 5869 §2.2 defines that as HashLen zero bytes, which is
	// the empty salt DIRECTORY-SPEC.md §3.3 specifies.
	out, err := hkdf.Key(sha256.New, secret, nil, epochInfo(label, epoch), KeyLen)
	if err != nil {
		// Unreachable for KeyLen = 32; hkdf.Key only fails when the requested
		// length exceeds 255 * HashLen. Propagated rather than dropped.
		return nil, fmt.Errorf("derive: hkdf: %w", err)
	}
	return out, nil
}

// WriteSeed returns the 32-byte Ed25519 seed for the epoch's write key.
func WriteSeed(sDir []byte, epoch int64) ([]byte, error) {
	return derived(sDir, InfoWrite, epoch)
}

// RecordKey returns the AES-256-GCM key that the payload is encrypted under.
// The directory never holds this value.
func RecordKey(sDir []byte, epoch int64) ([]byte, error) {
	return derived(sDir, InfoRecord, epoch)
}

// MailboxID returns the signal channel identifier the server long-polls for
// incoming ICE offers (DIRECTORY-SPEC.md §5.4).
func MailboxID(sDir []byte, epoch int64) ([]byte, error) {
	return derived(sDir, InfoMailbox, epoch)
}

// WriteKey returns the epoch's Ed25519 write keypair, WK.
//
// §3.3 specifies RFC 8032 §5.1.5 seed derivation: WriteSeed is the 32-byte seed
// that is hashed to produce the scalar and prefix, and is explicitly NOT
// treated as an already-clamped scalar. ed25519.NewKeyFromSeed is exactly that
// procedure.
//
// The returned value is the 64-byte seed || public layout that §3.3 recommends
// implementations publish, whose first 32 bytes equal WriteSeed.
func WriteKey(sDir []byte, epoch int64) (ed25519.PrivateKey, error) {
	seed, err := WriteSeed(sDir, epoch)
	if err != nil {
		return nil, err
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// The pairing key schedule, PAIRING-SPEC.md §3.1.
//
// These mirror the S_dir derivations exactly, with distinct info strings so a
// pairing record and a normal record can never collide. §3.1 states that all
// DIRECTORY-SPEC.md conventions apply unchanged — §0.1 integer encoding,
// Extract-then-Expand with an empty salt, RFC 8032 §5.1.5 seed derivation — so
// they share the implementation rather than restating it.
//
// A directory needs none of this: a pairing record is an ordinary envelope
// under an ordinary lookup_id, and §3.2 introduces no new record type. It is
// implemented and vectored only for the benefit of media-server implementers.

// PairWriteSeed returns the 32-byte Ed25519 seed for the epoch's pairing write key.
func PairWriteSeed(sPair []byte, epoch int64) ([]byte, error) {
	return derived(sPair, InfoPairWrite, epoch)
}

// PairRecordKey returns the AES-256-GCM key for a pairing record's payload.
func PairRecordKey(sPair []byte, epoch int64) ([]byte, error) {
	return derived(sPair, InfoPairRecord, epoch)
}

// PairWriteKey returns the epoch's pairing write keypair, PairWK.
func PairWriteKey(sPair []byte, epoch int64) (ed25519.PrivateKey, error) {
	seed, err := PairWriteSeed(sPair, epoch)
	if err != nil {
		return nil, err
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// LookupID returns SHA-256(WK_pub), the opaque per-epoch identifier a record is
// stored under.
//
// This is the one derivation the directory also performs, in order to check
// that lookup_id == SHA-256(wk_pub) on publish (DIRECTORY-SPEC.md §5.2).
//
// It also computes PairLookupID (PAIRING-SPEC.md §3.1), which is the same
// function applied to PairWK_pub. There is deliberately no separate entry
// point: a pairing record is an ordinary record and the directory cannot tell
// the difference, which is the point.
func LookupID(wkPub ed25519.PublicKey) []byte {
	sum := sha256.Sum256(wkPub)
	return sum[:]
}
