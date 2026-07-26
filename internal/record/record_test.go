// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Simon Wright

package record

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"

	"github.com/trigstation/trigstationd/internal/b64"
)

// fixture builds a valid signed envelope so that each test can corrupt exactly
// one thing and observe that the corruption alone is what fails.
type fixture struct {
	wk        ed25519.PrivateKey
	wkPub     ed25519.PublicKey
	lookupID  []byte
	recordKey []byte
	nonce     []byte
	ct        []byte
	env       Envelope
}

func newFixture(t *testing.T) *fixture {
	t.Helper()

	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	wk := ed25519.NewKeyFromSeed(seed)
	pub := wk.Public().(ed25519.PublicKey)
	sum := sha256.Sum256(pub)

	recordKey := make([]byte, RecordKeyLen)
	for i := range recordKey {
		recordKey[i] = byte(0x40 + i)
	}
	nonce := make([]byte, NonceLen)
	for i := range nonce {
		nonce[i] = byte(0xa0 + i)
	}

	ct, err := SealWithNonce(recordKey, nonce, []byte(`{"v":1}`))
	if err != nil {
		t.Fatalf("SealWithNonce: %v", err)
	}

	const expiresAt = 1753574400
	sig := Sign(wk, Version, sum[:], pub, expiresAt, nonce, ct)

	return &fixture{
		wk: wk, wkPub: pub, lookupID: sum[:], recordKey: recordKey, nonce: nonce, ct: ct,
		env: Envelope{
			V:         Version,
			LookupID:  b64.Encode(sum[:]),
			WKPub:     b64.Encode(pub),
			ExpiresAt: expiresAt,
			CT:        b64.Encode(ct),
			Nonce:     b64.Encode(nonce),
			PoW:       b64.Encode(make([]byte, 8)),
			Sig:       b64.Encode(sig),
		},
	}
}

func TestEnvelopeVerifyAcceptsValid(t *testing.T) {
	f := newFixture(t)
	d, err := f.env.Decode()
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if err := d.Verify(); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

// TestEnvelopeRejections exercises the two §5.2 conditions this package owns,
// one at a time. Each is a security property, not an error case: lookup_id
// binding is what stops a flooder writing under an arbitrary identifier, and
// the signature is the entirety of the authorisation.
func TestEnvelopeRejections(t *testing.T) {
	tests := []struct {
		name    string
		corrupt func(*fixture)
		wantErr error
	}{
		{
			name:    "wrong protocol version",
			corrupt: func(f *fixture) { f.env.V = 2 },
			wantErr: ErrVersion,
		},
		{
			name: "lookup_id is not SHA-256(wk_pub)",
			corrupt: func(f *fixture) {
				other := bytes.Clone(f.lookupID)
				other[0] ^= 0x01
				f.env.LookupID = b64.Encode(other)
			},
			wantErr: ErrLookupID,
		},
		{
			name: "signature does not verify",
			corrupt: func(f *fixture) {
				sig, _ := b64.Decode(f.env.Sig)
				sig[0] ^= 0x01
				f.env.Sig = b64.Encode(sig)
			},
			wantErr: ErrSignature,
		},
		{
			name: "signature is over a different expires_at",
			corrupt: func(f *fixture) {
				// Extending the expiry without resigning is the obvious
				// tampering attempt, and it must fail because expires_at is
				// inside the canonical form.
				f.env.ExpiresAt++
			},
			wantErr: ErrSignature,
		},
		{
			name: "signature is over a different ciphertext",
			corrupt: func(f *fixture) {
				ct := bytes.Clone(f.ct)
				ct[0] ^= 0x01
				f.env.CT = b64.Encode(ct)
			},
			wantErr: ErrSignature,
		},
		{
			name: "signature is over a different nonce",
			corrupt: func(f *fixture) {
				nonce := bytes.Clone(f.nonce)
				nonce[0] ^= 0x01
				f.env.Nonce = b64.Encode(nonce)
			},
			wantErr: ErrSignature,
		},
		{
			name:    "lookup_id wrong length",
			corrupt: func(f *fixture) { f.env.LookupID = b64.Encode(make([]byte, 31)) },
			wantErr: ErrFieldSize,
		},
		{
			name:    "wk_pub wrong length",
			corrupt: func(f *fixture) { f.env.WKPub = b64.Encode(make([]byte, 33)) },
			wantErr: ErrFieldSize,
		},
		{
			name:    "nonce wrong length",
			corrupt: func(f *fixture) { f.env.Nonce = b64.Encode(make([]byte, 16)) },
			wantErr: ErrFieldSize,
		},
		{
			name:    "pow wrong length",
			corrupt: func(f *fixture) { f.env.PoW = b64.Encode(make([]byte, 4)) },
			wantErr: ErrFieldSize,
		},
		{
			name:    "sig wrong length",
			corrupt: func(f *fixture) { f.env.Sig = b64.Encode(make([]byte, 63)) },
			wantErr: ErrFieldSize,
		},
		{
			name:    "ciphertext shorter than the AEAD tag",
			corrupt: func(f *fixture) { f.env.CT = b64.Encode(make([]byte, TagLen-1)) },
			wantErr: ErrCiphertext,
		},
		{
			name:    "malformed base64",
			corrupt: func(f *fixture) { f.env.WKPub = "!!!!" },
			wantErr: ErrFieldSize,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t)
			tt.corrupt(f)

			d, err := f.env.Decode()
			if err != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("Decode error = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err := d.Verify(); !errors.Is(err, tt.wantErr) {
				t.Fatalf("Verify error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

// TestSignedFormIsNotJSON is the rule from DIRECTORY-SPEC.md §4.4 stated as a
// test: the canonical form must be raw concatenated bytes, so it can contain
// neither JSON punctuation nor the base64 spellings of the fields.
func TestSignedFormIsNotJSON(t *testing.T) {
	f := newFixture(t)
	d, err := f.env.Decode()
	if err != nil {
		t.Fatal(err)
	}
	signed := d.SigningBytes()

	if bytes.ContainsAny(signed[:1+64], `{}":,`) {
		t.Error("canonical form appears to contain JSON punctuation")
	}
	if bytes.Contains(signed, []byte(f.env.LookupID)) {
		t.Error("canonical form contains the base64 text of lookup_id, not its raw bytes")
	}

	wantLen := 1 + LookupIDLen + WKPubLen + 8 + NonceLen + len(f.ct)
	if len(signed) != wantLen {
		t.Errorf("canonical form length = %d, want %d", len(signed), wantLen)
	}
	if signed[0] != Version {
		t.Errorf("canonical form does not begin with the version byte: %d", signed[0])
	}
}

// TestCanonicalEnvelopeInjectivity encodes the normative constraint in §4.1:
// bare concatenation is safe ONLY because exactly one field is variable-length
// and it is last. Any field added under §10 MUST be fixed-width and MUST go
// before ct.
//
// A change that appends after ct, or inserts anything variable-length, fails
// here rather than silently making the signature forgeable.
func TestCanonicalEnvelopeInjectivity(t *testing.T) {
	lookupID := bytes.Repeat([]byte{0x11}, LookupIDLen)
	wkPub := bytes.Repeat([]byte{0x22}, WKPubLen)
	nonce := bytes.Repeat([]byte{0x33}, NonceLen)

	if FixedPrefixLen != 85 {
		t.Errorf("FixedPrefixLen = %d, want 85 (1+32+32+8+12 per the §4.1 table)", FixedPrefixLen)
	}

	// The prefix before ct must be identical no matter what ct is, and ct must
	// occupy the entire tail.
	var prefix []byte
	for _, ctLen := range []int{0, 1, 16, 512} {
		ct := bytes.Repeat([]byte{0x44}, ctLen)
		got := CanonicalEnvelope(1, lookupID, wkPub, 1753574400, nonce, ct)

		if len(got) != FixedPrefixLen+ctLen {
			t.Fatalf("length with %d-byte ct = %d, want %d", ctLen, len(got), FixedPrefixLen+ctLen)
		}
		if !bytes.Equal(got[FixedPrefixLen:], ct) {
			t.Errorf("ct does not occupy the tail for ct length %d", ctLen)
		}
		if prefix == nil {
			prefix = bytes.Clone(got[:FixedPrefixLen])
		} else if !bytes.Equal(prefix, got[:FixedPrefixLen]) {
			t.Errorf("the fixed prefix changed when ct length changed to %d", ctLen)
		}
	}

	// Two envelopes differing only in where a boundary falls must not collide.
	// This is the property length prefixes would otherwise be needed for.
	a := CanonicalEnvelope(1, lookupID, wkPub, 1, nonce, []byte{0x01, 0x02})
	b := CanonicalEnvelope(1, lookupID, wkPub, 1, nonce, []byte{0x01})
	if bytes.Equal(a, b) {
		t.Error("different ciphertexts produced the same signing input")
	}
}

// TestCanonicalEnvelopeLayout pins the field order and the §0.1 integer widths.
func TestCanonicalEnvelopeLayout(t *testing.T) {
	lookupID := bytes.Repeat([]byte{0x11}, LookupIDLen)
	wkPub := bytes.Repeat([]byte{0x22}, WKPubLen)
	nonce := bytes.Repeat([]byte{0x33}, NonceLen)
	ct := []byte{0x44, 0x55}

	got := CanonicalEnvelope(1, lookupID, wkPub, 1753574400, nonce, ct)

	var want []byte
	want = append(want, 0x01)
	want = append(want, lookupID...)
	want = append(want, wkPub...)
	want = append(want, 0x00, 0x00, 0x00, 0x00, 0x68, 0x85, 0x6c, 0x00) // 1753574400 big-endian
	want = append(want, nonce...)
	want = append(want, ct...)

	if !bytes.Equal(got, want) {
		t.Errorf("CanonicalEnvelope =\n%x\nwant\n%x", got, want)
	}
}

// TestUnknownFieldsAreIgnored is required by DIRECTORY-SPEC.md §5 and §10:
// unknown fields MUST be ignored, never rejected, or no additive change to v1
// is ever deployable.
func TestUnknownFieldsAreIgnored(t *testing.T) {
	f := newFixture(t)
	raw, err := json.Marshal(f.env)
	if err != nil {
		t.Fatal(err)
	}

	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	m["a_field_from_a_later_revision"] = "ignore me"
	m["another"] = map[string]any{"nested": 1}

	raw, err = json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}

	var env Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("unknown fields caused a parse failure: %v", err)
	}
	d, err := env.Decode()
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if err := d.Verify(); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestPayloadSealOpen(t *testing.T) {
	key := bytes.Repeat([]byte{0x5a}, RecordKeyLen)
	plaintext := []byte(`{"v":1,"ts":1753488000}`)

	nonce, ct, err := Seal(key, plaintext)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if len(nonce) != NonceLen {
		t.Errorf("nonce length = %d, want %d", len(nonce), NonceLen)
	}
	if len(ct) != len(plaintext)+TagLen {
		t.Errorf("ciphertext length = %d, want plaintext+%d", len(ct), TagLen)
	}

	got, err := Open(key, nonce, ct)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("Open = %q, want %q", got, plaintext)
	}
}

// TestSealUsesAFreshNonce guards the §4.1 requirement that the nonce is random
// per publish and never a counter. Repeats would be catastrophic under AES-GCM.
func TestSealUsesAFreshNonce(t *testing.T) {
	key := bytes.Repeat([]byte{0x5a}, RecordKeyLen)
	seen := make(map[string]bool)

	for i := 0; i < 64; i++ {
		nonce, _, err := Seal(key, []byte("x"))
		if err != nil {
			t.Fatal(err)
		}
		if seen[string(nonce)] {
			t.Fatalf("Seal repeated a nonce after %d calls", i)
		}
		seen[string(nonce)] = true
	}
}

// TestPayloadOpenRejections. Decryption failure is the client's filter on a
// prefix query (§5.3), so the negative path is the common one and must be
// reliable.
func TestPayloadOpenRejections(t *testing.T) {
	key := bytes.Repeat([]byte{0x5a}, RecordKeyLen)
	other := bytes.Repeat([]byte{0x5b}, RecordKeyLen)
	nonce := bytes.Repeat([]byte{0x01}, NonceLen)

	ct, err := SealWithNonce(key, nonce, []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name  string
		key   []byte
		nonce []byte
		ct    []byte
	}{
		{"wrong key", other, nonce, ct},
		{"wrong nonce", key, bytes.Repeat([]byte{0x02}, NonceLen), ct},
		{"tampered ciphertext", key, nonce, flip(ct, 0)},
		{"tampered tag", key, nonce, flip(ct, len(ct)-1)},
		{"truncated", key, nonce, ct[:len(ct)-1]},
		{"short key", key[:16], nonce, ct},
		{"short nonce", key, nonce[:8], ct},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Open(tt.key, tt.nonce, tt.ct); err == nil {
				t.Error("Open succeeded, want failure")
			}
		})
	}
}

func testIK(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	ik := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x20}, ed25519.SeedSize))
	return ik, ik.Public().(ed25519.PublicKey)
}

func TestPlaintextRoundTrip(t *testing.T) {
	ik, ikPub := testIK(t)
	body := []byte(`{"v":1,"ts":1753488000,"caps":["ice"]}`)

	plaintext, err := MarshalPlaintext(ik, body)
	if err != nil {
		t.Fatalf("MarshalPlaintext: %v", err)
	}

	// Layout per §4.2: body_len (uint16 BE) || body || sig (64).
	if len(plaintext) != BodyLenSize+len(body)+PayloadSigLen {
		t.Fatalf("plaintext length = %d, want %d", len(plaintext), BodyLenSize+len(body)+PayloadSigLen)
	}
	if got := int(plaintext[0])<<8 | int(plaintext[1]); got != len(body) {
		t.Errorf("body_len prefix = %d, want %d", got, len(body))
	}
	if !bytes.Equal(plaintext[BodyLenSize:BodyLenSize+len(body)], body) {
		t.Error("body is not stored literally between the prefix and the signature")
	}

	got, err := VerifyPlaintext(ikPub, plaintext)
	if err != nil {
		t.Fatalf("VerifyPlaintext: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Errorf("VerifyPlaintext returned %q, want %q", got, body)
	}
}

// TestDifferentSpellingsEachVerify is the property the detached layout exists
// to provide (§4.2). Two different JSON spellings of the same logical object
// are different byte strings, so they carry different signatures — and each one
// verifies against its own bytes. Neither is "more canonical" than the other,
// because no canonicalisation rule exists.
func TestDifferentSpellingsEachVerify(t *testing.T) {
	ik, ikPub := testIK(t)

	spellings := []struct {
		name string
		body string
	}{
		{"compact", `{"v":1,"ts":1753488000,"caps":["ice","quic"]}`},
		{"reordered keys", `{"ts":1753488000,"caps":["ice","quic"],"v":1}`},
		{"whitespace", `{ "v": 1, "ts": 1753488000, "caps": [ "ice", "quic" ] }`},
		{"newlines and indent", "{\n  \"v\": 1,\n  \"ts\": 1753488000,\n  \"caps\": [\"ice\", \"quic\"]\n}"},
		{"number formatting", `{"v":1.0,"ts":1753488000,"caps":["ice","quic"]}`},
	}

	seen := make(map[string]bool)
	for _, s := range spellings {
		t.Run(s.name, func(t *testing.T) {
			plaintext, err := MarshalPlaintext(ik, []byte(s.body))
			if err != nil {
				t.Fatalf("MarshalPlaintext: %v", err)
			}

			body, sig, err := ParsePlaintext(plaintext)
			if err != nil {
				t.Fatalf("ParsePlaintext: %v", err)
			}
			if err := VerifyPayload(ikPub, body, sig); err != nil {
				t.Errorf("a valid spelling failed to verify: %v", err)
			}
			if string(body) != s.body {
				t.Errorf("body was altered in transit: got %q", body)
			}

			// Each distinct spelling must produce a distinct signature.
			if seen[string(sig)] {
				t.Error("two different spellings produced the same signature")
			}
			seen[string(sig)] = true
		})
	}

	if len(seen) != len(spellings) {
		t.Errorf("got %d distinct signatures for %d spellings", len(seen), len(spellings))
	}
}

// TestReserialisingBeforeVerifyingFails is the trap §4.2 warns about, written
// down so nobody reintroduces it. A verifier that unmarshals the body and
// re-marshals it to reconstruct the signing input will pass against bodies this
// codebase produced and fail against every other implementation.
//
// Here the received body is spelled with whitespace and reordered keys; Go's
// encoding/json re-marshals it compact and in struct order, and the signature
// no longer verifies.
func TestReserialisingBeforeVerifyingFails(t *testing.T) {
	ik, ikPub := testIK(t)

	received := []byte(`{ "ts": 1753488000, "v": 1, "endpoints": [], "tls": {"mode":"pki"}, "caps": ["ice"] }`)
	plaintext, err := MarshalPlaintext(ik, received)
	if err != nil {
		t.Fatal(err)
	}

	body, sig, err := ParsePlaintext(plaintext)
	if err != nil {
		t.Fatal(err)
	}

	// The correct way: verify over the bytes as received.
	if err := VerifyPayload(ikPub, body, sig); err != nil {
		t.Fatalf("verification over received bytes failed: %v", err)
	}

	// The wrong way: unmarshal, re-marshal, verify over the reconstruction.
	var b Body
	if err := json.Unmarshal(body, &b); err != nil {
		t.Fatal(err)
	}
	reserialised, err := json.Marshal(&b)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(reserialised, body) {
		t.Fatal("re-serialisation happened to be byte-identical; the test proves nothing")
	}
	if err := VerifyPayload(ikPub, reserialised, sig); !errors.Is(err, ErrPayloadSignature) {
		t.Errorf("verifying over a re-serialised body succeeded; it must not")
	}
}

// TestPayloadSignatureRejections. The inner signature is the only thing
// establishing authenticity (§4.2), so every way of getting it wrong must fail.
func TestPayloadSignatureRejections(t *testing.T) {
	ik, ikPub := testIK(t)
	body := []byte(`{"v":1,"ts":1753488000,"endpoints":[{"type":"lan","host":"192.168.1.50","port":8096}]}`)

	plaintext, err := MarshalPlaintext(ik, body)
	if err != nil {
		t.Fatal(err)
	}
	goodBody, goodSig, err := ParsePlaintext(plaintext)
	if err != nil {
		t.Fatal(err)
	}

	// A different identity key must not verify. This is what makes a malicious
	// paired client able to pollute but not impersonate (§8.1) — it holds S_dir
	// and can therefore write a valid envelope, but never holds IK_priv.
	otherPub := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x21}, ed25519.SeedSize)).
		Public().(ed25519.PublicKey)

	tests := []struct {
		name   string
		ikPub  ed25519.PublicKey
		body   []byte
		sig    []byte
		wantOK bool
	}{
		{"valid", ikPub, goodBody, goodSig, true},
		{"different ik_pub", otherPub, goodBody, goodSig, false},
		{"tampered body", ikPub, flip(goodBody, 5), goodSig, false},
		{"body truncated", ikPub, goodBody[:len(goodBody)-1], goodSig, false},
		{"body extended", ikPub, append(bytes.Clone(goodBody), ' '), goodSig, false},
		{"tampered signature", ikPub, goodBody, flip(goodSig, 0), false},
		{"signature too short", ikPub, goodBody, goodSig[:63], false},
		{"empty signature", ikPub, goodBody, nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyPayload(tt.ikPub, tt.body, tt.sig)
			if tt.wantOK != (err == nil) {
				t.Errorf("VerifyPayload err = %v, wantOK %v", err, tt.wantOK)
			}
			if !tt.wantOK && !errors.Is(err, ErrPayloadSignature) {
				t.Errorf("err = %v, want ErrPayloadSignature", err)
			}
		})
	}
}

// TestParsePlaintextRejections. The framing must determine exactly what was
// signed; a parser that tolerates slack turns into an attack surface.
func TestParsePlaintextRejections(t *testing.T) {
	ik, _ := testIK(t)
	body := []byte(`{"v":1}`)
	good, err := MarshalPlaintext(ik, body)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		in   []byte
	}{
		{"empty", nil},
		{"framing only", make([]byte, BodyLenSize+PayloadSigLen-1)},
		{"declared length too long", append([]byte{0xff, 0xff}, good[BodyLenSize:]...)},
		{"declared length too short", append([]byte{0x00, 0x01}, good[BodyLenSize:]...)},
		{"trailing bytes after the signature", append(bytes.Clone(good), 0x00)},
		{"truncated signature", good[:len(good)-1]},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, _, err := ParsePlaintext(tt.in); !errors.Is(err, ErrPayloadFormat) {
				t.Errorf("ParsePlaintext err = %v, want ErrPayloadFormat", err)
			}
		})
	}

	// A zero-length body is well formed: the framing still determines it.
	empty, err := MarshalPlaintext(ik, nil)
	if err != nil {
		t.Fatal(err)
	}
	if b, _, err := ParsePlaintext(empty); err != nil || len(b) != 0 {
		t.Errorf("zero-length body: body = %q, err = %v", b, err)
	}
}

func TestMarshalPlaintextRejectsOversizedBody(t *testing.T) {
	ik, _ := testIK(t)
	if _, err := MarshalPlaintext(ik, make([]byte, MaxBodyLen+1)); !errors.Is(err, ErrBodyTooLarge) {
		t.Errorf("err = %v, want ErrBodyTooLarge", err)
	}
}

func flip(b []byte, i int) []byte {
	out := bytes.Clone(b)
	out[i] ^= 0x01
	return out
}
