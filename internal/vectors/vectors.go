// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Simon Wright

// Package vectors generates and describes testdata/vectors.json.
//
// DIRECTORY-SPEC.md §9 requires the reference implementation to ship test
// vectors "so that independent implementations can be verified against the spec
// rather than against this codebase". That phrasing sets the standard for this
// file: the vectors are a deliverable, and the generation must be fully
// deterministic so that anyone can regenerate them and get byte-identical
// output. Nothing here may read the clock or draw from a CSPRNG.
//
// That determinism requires a fixed nonce for the sample envelope, which is the
// one place these vectors deliberately violate the spec's own rules. See
// FixedNonce.
package vectors

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"github.com/trigstation/trigstationd/internal/b64"
	"github.com/trigstation/trigstationd/internal/derive"
	"github.com/trigstation/trigstationd/internal/pow"
	"github.com/trigstation/trigstationd/internal/record"
)

// Test-only key material.
//
// These are counting patterns, not random values, so that no one can mistake
// them for something that ought to be kept. They are visibly, structurally
// fake. A directory secret with this value must never be used by a real server:
// anyone holding it can derive that server's LookupID and RecordKey for every
// epoch, for ever.
var (
	// TestSDir is S_dir = 0x00 0x01 ... 0x1f. TEST ONLY.
	TestSDir = countingBytes(0x00, derive.SDirLen)

	// TestIKSeed is the seed for the server identity key IK. TEST ONLY.
	TestIKSeed = countingBytes(0x20, ed25519.SeedSize)

	// TestSPair is S_pair, the single-use pairing secret of PAIRING-SPEC.md
	// §3. Distinct from TestSDir so the vectors demonstrate that the two
	// schedules are separated by their info strings alone. TEST ONLY.
	TestSPair = countingBytes(0x40, derive.SDirLen)

	// FixedNonce is the AES-GCM nonce used for the sample envelope. TEST ONLY.
	//
	// DIRECTORY-SPEC.md §4.1 requires a fresh CSPRNG nonce for every publish
	// and forbids a counter. A vector generated that way could not be
	// reproduced or independently checked, so this one is fixed. It is the
	// single knowing deviation in this file and it must not be copied into
	// anything that publishes a real record.
	FixedNonce = countingBytes(0xa0, record.NonceLen)
)

// Sample times chosen to exercise the epoch boundary.
//
// 1753488000 is exactly 86400 * 20295, so it is the first second of an epoch —
// the same instant that DIRECTORY-SPEC.md §4.2 uses for its example body `ts`.
// Sampling one second either side of two consecutive boundaries pins down
// whether an implementation's epoch division rounds the way floor() does.
var sampleTimes = []struct {
	unixTime int64
	note     string
}{
	{1753487999, "last second of epoch 20294 — one second before a boundary"},
	{1753488000, "first second of epoch 20295 — exactly on the boundary, 86400 * 20295"},
	{1753574399, "last second of epoch 20295"},
	{1753574400, "first second of epoch 20296 — exactly on the boundary, 86400 * 20296"},
}

// Times used to build the sample envelope. Both come from the worked examples
// in DIRECTORY-SPEC.md §4.1 and §4.2.
const (
	sampleTS        = 1753488000 // body ts: publish time, epoch 20295
	sampleExpiresAt = 1753574400 // envelope expires_at: 24 hours later
)

// File is the top-level structure of testdata/vectors.json.
//
// Field order is marshalling order, and the leading underscore keys are meant
// to be read first by a human opening the file.
type File struct {
	Comment     string      `json:"_comment"`
	Warning     []string    `json:"_warning"`
	Spec        string      `json:"spec"`
	Encoding    string      `json:"encoding"`
	Conventions Conventions `json:"conventions"`

	SDir   string `json:"s_dir"`
	SPair  string `json:"s_pair"`
	IKSeed string `json:"ik_seed"`
	IKPub  string `json:"ik_pub"`

	Epochs   []Epoch  `json:"epochs"`
	Pairing  []Pair   `json:"pairing"`
	Envelope Envelope `json:"envelope"`
	PoW      PoW      `json:"pow"`
}

// Conventions cites the normative rule behind each encoding decision, so that
// an implementer comparing against these vectors can find the clause rather
// than reverse-engineering the bytes.
type Conventions struct {
	Note              string `json:"_note"`
	IntegerEncoding   string `json:"integer_encoding"`
	HKDFConstruction  string `json:"hkdf_construction"`
	Ed25519Seed       string `json:"ed25519_seed"`
	EnvelopeSignature string `json:"envelope_signature"`
	PayloadSignature  string `json:"payload_signature"`
	PoWInput          string `json:"pow_input"`
}

// Epoch is one row of the key schedule, DIRECTORY-SPEC.md §3.3.
type Epoch struct {
	Note       string `json:"note"`
	UnixTime   int64  `json:"unix_time"`
	Epoch      int64  `json:"epoch"`
	EpochStart int64  `json:"epoch_start"`
	WriteSeed  string `json:"write_seed"`
	WKPub      string `json:"wk_pub"`
	WKPriv     string `json:"wk_priv"`
	LookupID   string `json:"lookup_id"`
	RecordKey  string `json:"record_key"`
	MailboxID  string `json:"mailbox_id"`
}

// Pair is one row of the pairing key schedule, PAIRING-SPEC.md §3.1. Derived
// from S_pair rather than S_dir, under the trig-pair-* info strings.
type Pair struct {
	Note          string `json:"note"`
	Epoch         int64  `json:"epoch"`
	PairWriteSeed string `json:"pair_write_seed"`
	PairWKPub     string `json:"pair_wk_pub"`
	PairWKPriv    string `json:"pair_wk_priv"`
	PairLookupID  string `json:"pair_lookup_id"`
	PairRecordKey string `json:"pair_record_key"`
}

// Envelope is a complete signed and encrypted record, plus the intermediate
// values needed to debug a mismatch rather than merely observe one.
type Envelope struct {
	Note                 string          `json:"note"`
	Epoch                int64           `json:"epoch"`
	BodyUTF8             string          `json:"body_utf8"`
	Body                 string          `json:"body"`
	BodyLen              int             `json:"body_len"`
	PayloadSig           string          `json:"payload_sig"`
	Plaintext            string          `json:"plaintext"`
	Nonce                string          `json:"nonce"`
	EnvelopeSigningInput string          `json:"envelope_signing_input"`
	Envelope             record.Envelope `json:"envelope"`
}

// PoW is the solved proof of work for the sample envelope, DIRECTORY-SPEC.md §6.1.
type PoW struct {
	Note            string `json:"note"`
	Bits            int    `json:"bits"`
	LookupID        string `json:"lookup_id"`
	ExpiresAt       int64  `json:"expires_at"`
	Input           string `json:"input"`
	Value           string `json:"value"`
	Digest          string `json:"digest"`
	LeadingZeroBits int    `json:"leading_zero_bits"`
}

// Path is the committed location of the vector file, relative to the module
// root. Tests resolve it relative to their own package directory.
const Path = "testdata/vectors.json"

// Marshal renders the vector file exactly as it is committed: two-space indent,
// HTML escaping off so that URLs and '&' survive unmangled, and a trailing
// newline. Both the generator and the self-check test go through here, so a
// formatting difference can never be mistaken for a value difference.
func Marshal(f *File) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(f); err != nil {
		return nil, fmt.Errorf("vectors: marshal: %w", err)
	}
	return buf.Bytes(), nil
}

// countingBytes returns n bytes starting at start and incrementing.
func countingBytes(start byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = start + byte(i)
	}
	return b
}

// sampleBody returns the body object from the DIRECTORY-SPEC.md §4.2 example.
//
// The bytes this marshals to are the signing input — §4.2 signs the literal
// transmitted bytes, so whatever this produces is definitive for the vector,
// and the vector publishes those bytes verbatim as `body`.
func sampleBody() *record.Body {
	return &record.Body{
		V:  record.Version,
		TS: sampleTS,
		Endpoints: []record.Endpoint{
			{Type: record.EndpointLAN, Host: "192.168.1.50", Port: 8096},
			{Type: record.EndpointWAN4, Host: "203.0.113.7", Port: 8443},
			{Type: record.EndpointWAN6, Host: "2001:db8::42", Port: 8443},
			{Type: record.EndpointDNS, Host: "media.example.net", Port: 443},
		},
		TLS:  record.TLSInfo{Mode: record.TLSModePKI},
		Caps: []string{"ice", "quic", "hls"},
	}
}

// Generate builds the complete vector file. It is deterministic: the same
// inputs always produce byte-identical output.
func Generate(ctx context.Context) (*File, error) {
	ik := ed25519.NewKeyFromSeed(TestIKSeed)
	ikPub := ik.Public().(ed25519.PublicKey)

	f := &File{
		Comment: "Trigstation directory service — protocol v1 test vectors. " +
			"Generated by cmd/gen-vectors; regenerating must reproduce this file byte for byte.",
		Warning: []string{
			"TEST ONLY. s_dir, s_pair and ik_seed are counting patterns, not secrets. " +
				"Anyone holding this s_dir can derive this server's LookupID and RecordKey for every epoch, for ever.",
			"The envelope nonce is FIXED so that the vector is reproducible. " +
				"DIRECTORY-SPEC.md §4.1 requires a fresh CSPRNG nonce for every real publish and forbids a counter.",
			"The `body` bytes are definitive. Per §4.2 the payload signature covers the literal " +
				"transmitted bytes of body, so verify against the `body` field as given — do not " +
				"re-serialise body_utf8 through your own JSON encoder and expect the signature to hold. " +
				"A different spelling of the same object is a different, equally valid record with a " +
				"different signature.",
		},
		Spec:     "DIRECTORY-SPEC.md protocol version 1 (draft)",
		Encoding: "All binary values are unpadded base64url, RFC 4648 §5. No '=' padding is emitted.",
		Conventions: Conventions{
			Note: "The normative rule behind each encoding, for cross-checking against the spec.",
			IntegerEncoding: "§0.1 — every integer concatenated into a byte string is fixed-width " +
				"unsigned big-endian, never decimal text. epoch 8 bytes, expires_at 8, ts 8, v 1, pow 8.",
			HKDFConstruction: "§3.3 — HKDF-SHA256, full RFC 5869 Extract-then-Expand with an empty salt " +
				"(RFC 5869 §2.2: HashLen zero bytes). Expand-only is explicitly NOT what the spec means.",
			Ed25519Seed: "§3.3 — RFC 8032 §5.1.5 seed derivation; the seed is hashed to produce the " +
				"scalar and prefix, not treated as a clamped scalar. wk_priv is the 64-byte " +
				"seed||public layout §3.3 recommends; its first 32 bytes equal write_seed.",
			EnvelopeSignature: "§4.1 — Ed25519(WK_priv, v||lookup_id||wk_pub||expires_at||nonce||ct) over " +
				"raw byte values, integers per §0.1. Safe as bare concatenation only because ct is " +
				"the sole variable-length field and is last.",
			PayloadSignature: "§4.2 — detached. Plaintext is body_len(uint16 BE)||body||sig(64), and " +
				"sig = Ed25519(IK_priv, body) over the literal transmitted bytes. There is no " +
				"canonicalisation rule; verifiers MUST NOT re-serialise before verifying.",
			PoWInput: "§6.1 — SHA-256(\"trig-pow-v1\"||lookup_id||expires_at||pow), expires_at and pow " +
				"8 bytes each per §0.1.",
		},
		SDir:   b64.Encode(TestSDir),
		SPair:  b64.Encode(TestSPair),
		IKSeed: b64.Encode(TestIKSeed),
		IKPub:  b64.Encode(ikPub),
	}

	for _, s := range sampleTimes {
		e, err := epochVector(s.unixTime, s.note)
		if err != nil {
			return nil, err
		}
		f.Epochs = append(f.Epochs, *e)

		// One pairing row per distinct epoch; the schedule is epoch-keyed and
		// repeating it for two times in the same epoch adds nothing.
		if len(f.Pairing) == 0 || f.Pairing[len(f.Pairing)-1].Epoch != e.Epoch {
			p, err := pairVector(e.Epoch)
			if err != nil {
				return nil, err
			}
			f.Pairing = append(f.Pairing, *p)
		}
	}

	if err := f.buildEnvelope(ctx, ik); err != nil {
		return nil, err
	}

	return f, nil
}

func epochVector(unixTime int64, note string) (*Epoch, error) {
	ep := derive.Epoch(unixTime)

	seed, err := derive.WriteSeed(TestSDir, ep)
	if err != nil {
		return nil, err
	}
	wk, err := derive.WriteKey(TestSDir, ep)
	if err != nil {
		return nil, err
	}
	recKey, err := derive.RecordKey(TestSDir, ep)
	if err != nil {
		return nil, err
	}
	mailbox, err := derive.MailboxID(TestSDir, ep)
	if err != nil {
		return nil, err
	}
	wkPub := wk.Public().(ed25519.PublicKey)

	return &Epoch{
		Note:       note,
		UnixTime:   unixTime,
		Epoch:      ep,
		EpochStart: derive.EpochStart(ep),
		WriteSeed:  b64.Encode(seed),
		WKPub:      b64.Encode(wkPub),
		WKPriv:     b64.Encode(wk),
		LookupID:   b64.Encode(derive.LookupID(wkPub)),
		RecordKey:  b64.Encode(recKey),
		MailboxID:  b64.Encode(mailbox),
	}, nil
}

// pairVector derives the PAIRING-SPEC.md §3.1 schedule from S_pair. The
// directory needs none of these values; they are here for implementers of the
// media-server side, since §3.1 states the pairing derivations inherit every
// DIRECTORY-SPEC.md convention unchanged.
func pairVector(ep int64) (*Pair, error) {
	seed, err := derive.PairWriteSeed(TestSPair, ep)
	if err != nil {
		return nil, err
	}
	wk, err := derive.PairWriteKey(TestSPair, ep)
	if err != nil {
		return nil, err
	}
	recKey, err := derive.PairRecordKey(TestSPair, ep)
	if err != nil {
		return nil, err
	}
	wkPub := wk.Public().(ed25519.PublicKey)

	return &Pair{
		Note:          "PAIRING-SPEC.md §3.1, derived from s_pair (not s_dir) under the trig-pair-* info strings",
		Epoch:         ep,
		PairWriteSeed: b64.Encode(seed),
		PairWKPub:     b64.Encode(wkPub),
		PairWKPriv:    b64.Encode(wk),
		PairLookupID:  b64.Encode(derive.LookupID(wkPub)),
		PairRecordKey: b64.Encode(recKey),
	}, nil
}

func (f *File) buildEnvelope(ctx context.Context, ik ed25519.PrivateKey) error {
	ep := derive.Epoch(sampleTS)

	wk, err := derive.WriteKey(TestSDir, ep)
	if err != nil {
		return err
	}
	recKey, err := derive.RecordKey(TestSDir, ep)
	if err != nil {
		return err
	}
	wkPub := wk.Public().(ed25519.PublicKey)
	lookupID := derive.LookupID(wkPub)

	// The body is serialised once, and those exact bytes are what the detached
	// signature covers (§4.2). Marshalling it a second time anywhere would be a
	// bug waiting to happen, so the bytes are threaded through from here.
	body, err := json.Marshal(sampleBody())
	if err != nil {
		return fmt.Errorf("vectors: marshal body: %w", err)
	}

	plaintext, err := record.MarshalPlaintext(ik, body)
	if err != nil {
		return err
	}
	_, payloadSig, err := record.ParsePlaintext(plaintext)
	if err != nil {
		return err
	}

	ct, err := record.SealWithNonce(recKey, FixedNonce, plaintext)
	if err != nil {
		return err
	}

	powValue, err := pow.Solve(ctx, lookupID, sampleExpiresAt, pow.DefaultBits)
	if err != nil {
		return fmt.Errorf("vectors: solve proof of work: %w", err)
	}
	powInput := pow.Input(lookupID, sampleExpiresAt, powValue)
	powDigest := sha256.Sum256(powInput)

	envSigningInput := record.CanonicalEnvelope(record.Version, lookupID, wkPub, sampleExpiresAt, FixedNonce, ct)
	sig := record.Sign(wk, record.Version, lookupID, wkPub, sampleExpiresAt, FixedNonce, ct)

	f.Envelope = Envelope{
		Note: "A complete record for epoch " + fmt.Sprint(ep) +
			". ts and expires_at are the worked example values from §4.1 and §4.2. " +
			"body is the signing input for payload_sig; plaintext is body_len||body||payload_sig.",
		Epoch:                ep,
		BodyUTF8:             string(body),
		Body:                 b64.Encode(body),
		BodyLen:              len(body),
		PayloadSig:           b64.Encode(payloadSig),
		Plaintext:            b64.Encode(plaintext),
		Nonce:                b64.Encode(FixedNonce),
		EnvelopeSigningInput: b64.Encode(envSigningInput),
		Envelope: record.Envelope{
			V:         record.Version,
			LookupID:  b64.Encode(lookupID),
			WKPub:     b64.Encode(wkPub),
			ExpiresAt: sampleExpiresAt,
			CT:        b64.Encode(ct),
			Nonce:     b64.Encode(FixedNonce),
			PoW:       b64.Encode(powValue),
			Sig:       b64.Encode(sig),
		},
	}

	f.PoW = PoW{
		Note:            "Solved by incrementing an 8-byte big-endian counter from zero. Search order has no protocol significance.",
		Bits:            pow.DefaultBits,
		LookupID:        b64.Encode(lookupID),
		ExpiresAt:       sampleExpiresAt,
		Input:           b64.Encode(powInput),
		Value:           b64.Encode(powValue),
		Digest:          b64.Encode(powDigest[:]),
		LeadingZeroBits: pow.LeadingZeroBits(powDigest[:]),
	}

	return nil
}
