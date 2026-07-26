// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Simon Wright

package vectors

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/trigstation/trigstationd/internal/b64"
	"github.com/trigstation/trigstationd/internal/derive"
	"github.com/trigstation/trigstationd/internal/pow"
	"github.com/trigstation/trigstationd/internal/record"
)

// committedPath resolves testdata/vectors.json from this package's directory.
func committedPath() string {
	return filepath.Join("..", "..", filepath.FromSlash(Path))
}

func load(t *testing.T) *File {
	t.Helper()
	raw, err := os.ReadFile(committedPath())
	if err != nil {
		t.Fatalf("read vectors: %v (run: go run ./cmd/gen-vectors -o %s)", err, Path)
	}
	var f File
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	return &f
}

// TestCommittedVectorsMatchGenerator is the guard that keeps the committed file
// honest. If a derivation changes, this fails rather than the vectors silently
// describing code that no longer exists.
//
// It also proves generation is deterministic, which is what allows an
// independent implementer to regenerate and diff rather than trust.
func TestCommittedVectorsMatchGenerator(t *testing.T) {
	committed, err := os.ReadFile(committedPath())
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}

	f, err := Generate(context.Background())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	regenerated, err := Marshal(f)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	if !bytes.Equal(committed, regenerated) {
		t.Errorf("testdata/%s is out of date with the code.\n"+
			"Regenerate with: go run ./cmd/gen-vectors -o %s", Path, Path)
	}
}

// TestVectorsAreUnpaddedBase64url enforces the §4.4 encoding rule across every
// binary field in the file, so a hand-edit that reintroduces padding is caught.
func TestVectorsAreUnpaddedBase64url(t *testing.T) {
	f := load(t)

	check := func(name, v string) {
		t.Helper()
		if v == "" {
			t.Errorf("%s is empty", name)
			return
		}
		for _, c := range v {
			if c == '=' || c == '+' || c == '/' {
				t.Errorf("%s = %q uses padding or the standard alphabet", name, v)
				return
			}
		}
		if _, err := b64.Decode(v); err != nil {
			t.Errorf("%s does not decode: %v", name, err)
		}
	}

	check("s_dir", f.SDir)
	check("s_pair", f.SPair)
	check("ik_seed", f.IKSeed)
	check("ik_pub", f.IKPub)

	for i, e := range f.Epochs {
		p := func(s string) string { return "epochs[" + itoa(i) + "]." + s }
		check(p("write_seed"), e.WriteSeed)
		check(p("wk_pub"), e.WKPub)
		check(p("wk_priv"), e.WKPriv)
		check(p("lookup_id"), e.LookupID)
		check(p("record_key"), e.RecordKey)
		check(p("mailbox_id"), e.MailboxID)
	}

	for i, p := range f.Pairing {
		q := func(s string) string { return "pairing[" + itoa(i) + "]." + s }
		check(q("pair_write_seed"), p.PairWriteSeed)
		check(q("pair_wk_pub"), p.PairWKPub)
		check(q("pair_wk_priv"), p.PairWKPriv)
		check(q("pair_lookup_id"), p.PairLookupID)
		check(q("pair_record_key"), p.PairRecordKey)
	}

	check("envelope.body", f.Envelope.Body)
	check("envelope.payload_sig", f.Envelope.PayloadSig)
	check("envelope.plaintext", f.Envelope.Plaintext)

	env := f.Envelope.Envelope
	check("envelope.lookup_id", env.LookupID)
	check("envelope.wk_pub", env.WKPub)
	check("envelope.ct", env.CT)
	check("envelope.nonce", env.Nonce)
	check("envelope.pow", env.PoW)
	check("envelope.sig", env.Sig)
	check("pow.value", f.PoW.Value)
	check("pow.digest", f.PoW.Digest)
}

// TestEpochVectors recomputes every derived value in the file from s_dir alone.
// This is the check an independent implementation performs to verify itself
// against the spec.
func TestEpochVectors(t *testing.T) {
	f := load(t)

	sDir, err := b64.DecodeFixed(f.SDir, derive.SDirLen)
	if err != nil {
		t.Fatalf("s_dir: %v", err)
	}

	if len(f.Epochs) < 3 {
		t.Fatalf("want at least three epochs, got %d", len(f.Epochs))
	}

	for i, want := range f.Epochs {
		t.Run(itoa(i)+"/epoch="+itoa64(want.Epoch), func(t *testing.T) {
			if got := derive.Epoch(want.UnixTime); got != want.Epoch {
				t.Errorf("Epoch(%d) = %d, want %d", want.UnixTime, got, want.Epoch)
			}
			if got := derive.EpochStart(want.Epoch); got != want.EpochStart {
				t.Errorf("EpochStart(%d) = %d, want %d", want.Epoch, got, want.EpochStart)
			}

			seed, err := derive.WriteSeed(sDir, want.Epoch)
			if err != nil {
				t.Fatal(err)
			}
			eq(t, "write_seed", seed, want.WriteSeed)

			wk, err := derive.WriteKey(sDir, want.Epoch)
			if err != nil {
				t.Fatal(err)
			}
			wkPub := wk.Public().(ed25519.PublicKey)
			eq(t, "wk_pub", wkPub, want.WKPub)
			eq(t, "wk_priv", wk, want.WKPriv)
			eq(t, "lookup_id", derive.LookupID(wkPub), want.LookupID)

			recKey, err := derive.RecordKey(sDir, want.Epoch)
			if err != nil {
				t.Fatal(err)
			}
			eq(t, "record_key", recKey, want.RecordKey)

			mailbox, err := derive.MailboxID(sDir, want.Epoch)
			if err != nil {
				t.Fatal(err)
			}
			eq(t, "mailbox_id", mailbox, want.MailboxID)

			// The 64-byte private key must begin with the seed, which is the
			// convention note in the vectors file.
			priv, err := b64.DecodeFixed(want.WKPriv, ed25519.PrivateKeySize)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(priv[:ed25519.SeedSize], seed) {
				t.Error("the first 32 bytes of wk_priv do not equal write_seed")
			}
		})
	}
}

// TestEpochVectorsCoverABoundary checks the file actually exercises what it
// claims to: consecutive sample times that straddle an epoch change, and at
// least one sample landing exactly on a boundary.
func TestEpochVectorsCoverABoundary(t *testing.T) {
	f := load(t)

	var boundaries, exact int
	for i, e := range f.Epochs {
		if e.UnixTime == e.EpochStart {
			exact++
		}
		if i > 0 && f.Epochs[i-1].Epoch != e.Epoch {
			boundaries++
			if f.Epochs[i-1].LookupID == e.LookupID {
				t.Error("lookup_id did not change across an epoch boundary")
			}
			if f.Epochs[i-1].RecordKey == e.RecordKey {
				t.Error("record_key did not change across an epoch boundary")
			}
		}
	}
	if boundaries == 0 {
		t.Error("no sample times straddle an epoch boundary")
	}
	if exact == 0 {
		t.Error("no sample time lands exactly on an epoch boundary")
	}

	distinct := map[int64]bool{}
	for _, e := range f.Epochs {
		distinct[e.Epoch] = true
	}
	if len(distinct) < 3 {
		t.Errorf("vectors cover %d distinct epochs, want at least 3", len(distinct))
	}
}

// TestEnvelopeVector verifies the sample record end to end: the envelope
// signature, the lookup_id binding, the proof of work, the payload decryption,
// and the inner signature under ik_pub.
func TestEnvelopeVector(t *testing.T) {
	f := load(t)

	sDir, err := b64.DecodeFixed(f.SDir, derive.SDirLen)
	if err != nil {
		t.Fatal(err)
	}
	ikPub, err := b64.DecodeFixed(f.IKPub, ed25519.PublicKeySize)
	if err != nil {
		t.Fatal(err)
	}

	d, err := f.Envelope.Envelope.Decode()
	if err != nil {
		t.Fatalf("decode envelope: %v", err)
	}

	// Signature and lookup_id binding — the two checks §5.2 gives the directory.
	if err := d.Verify(); err != nil {
		t.Fatalf("envelope does not verify: %v", err)
	}

	// The write key must be the one derived from s_dir for the stated epoch,
	// not an unrelated keypair that merely signs consistently.
	wk, err := derive.WriteKey(sDir, f.Envelope.Epoch)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(d.WKPub, wk.Public().(ed25519.PublicKey)) {
		t.Error("envelope wk_pub is not the derived write key for this epoch")
	}

	eq(t, "envelope signing input", d.SigningBytes(), f.Envelope.EnvelopeSigningInput)

	// Proof of work at the full default difficulty.
	if !pow.Verify(d.LookupID, d.ExpiresAt, d.PoW, pow.DefaultBits) {
		t.Errorf("proof of work does not satisfy %d bits", pow.DefaultBits)
	}
	powInput := pow.Input(d.LookupID, d.ExpiresAt, d.PoW)
	eq(t, "pow.input", powInput, f.PoW.Input)
	digest := sha256.Sum256(powInput)
	eq(t, "pow.digest", digest[:], f.PoW.Digest)
	if got := pow.LeadingZeroBits(digest[:]); got != f.PoW.LeadingZeroBits {
		t.Errorf("pow leading zero bits = %d, want %d", got, f.PoW.LeadingZeroBits)
	}

	// Envelope must fit the §4.3 size cap as encoded on the wire.
	encoded, err := json.Marshal(f.Envelope.Envelope)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) > record.MaxEnvelopeBytes {
		t.Errorf("encoded envelope is %d bytes, over the %d cap", len(encoded), record.MaxEnvelopeBytes)
	}

	// Payload: decrypt under the derived RecordKey and check it is exactly the
	// plaintext the file records.
	recKey, err := derive.RecordKey(sDir, f.Envelope.Epoch)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := record.Open(recKey, d.Nonce, d.CT)
	if err != nil {
		t.Fatalf("payload did not decrypt under the derived RecordKey: %v", err)
	}
	eq(t, "plaintext", plaintext, f.Envelope.Plaintext)

	// §4.2 framing: body_len || body || sig.
	body, sig, err := record.ParsePlaintext(plaintext)
	if err != nil {
		t.Fatalf("plaintext framing is malformed: %v", err)
	}
	eq(t, "body", body, f.Envelope.Body)
	eq(t, "payload_sig", sig, f.Envelope.PayloadSig)
	if len(body) != f.Envelope.BodyLen {
		t.Errorf("body_len = %d, want %d", f.Envelope.BodyLen, len(body))
	}
	if string(body) != f.Envelope.BodyUTF8 {
		t.Error("body_utf8 does not match the body bytes")
	}

	// The detached signature — the check that establishes authenticity (§4.2).
	// Verified over the bytes as received, never over a re-serialisation.
	if err := record.VerifyPayload(ikPub, body, sig); err != nil {
		t.Fatalf("payload signature does not verify under ik_pub: %v", err)
	}

	// TTL must be within the §4.3 maximum, measured from the body's ts.
	var b record.Body
	if err := json.Unmarshal(body, &b); err != nil {
		t.Fatalf("body is not valid JSON: %v", err)
	}
	if ttl := d.ExpiresAt - b.TS; ttl <= 0 || ttl > record.MaxTTL {
		t.Errorf("envelope TTL = %d seconds, want 0 < ttl <= %d", ttl, record.MaxTTL)
	}

	// A record that decrypts under a different epoch's key would mean the
	// derivations are not actually epoch-separated.
	otherKey, err := derive.RecordKey(sDir, f.Envelope.Epoch+1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := record.Open(otherKey, d.Nonce, d.CT); err == nil {
		t.Error("payload decrypted under the next epoch's RecordKey")
	}
}

// TestVectorsAreMarkedTestOnly. These vectors contain a working s_dir. If the
// warnings were ever dropped, someone would eventually paste them into a real
// server.
func TestVectorsAreMarkedTestOnly(t *testing.T) {
	f := load(t)

	if len(f.Warning) == 0 {
		t.Fatal("_warning is empty")
	}
	joined := ""
	for _, w := range f.Warning {
		joined += w + "\n"
	}
	for _, want := range []string{"TEST ONLY", "nonce", "re-serialise"} {
		if !contains(joined, want) {
			t.Errorf("_warning does not mention %q", want)
		}
	}

	c := f.Conventions
	for name, v := range map[string]string{
		"integer_encoding":   c.IntegerEncoding,
		"hkdf_construction":  c.HKDFConstruction,
		"ed25519_seed":       c.Ed25519Seed,
		"envelope_signature": c.EnvelopeSignature,
		"payload_signature":  c.PayloadSignature,
		"pow_input":          c.PoWInput,
	} {
		if v == "" {
			t.Errorf("conventions.%s is empty", name)
		}
	}

	// §4.4 keeps the two signatures distinct and §4.2 defines no
	// canonicalisation for the payload. The file must describe the payload
	// signature as detached and over literal bytes, so that an implementer
	// reading only the vectors cannot conclude a canonical form exists.
	for _, want := range []string{"detached", "literal"} {
		if !contains(strings.ToLower(c.PayloadSignature), want) {
			t.Errorf("conventions.payload_signature does not describe the signature as %q", want)
		}
	}
	if !contains(strings.ToLower(c.EnvelopeSignature), "concatenation") {
		t.Error("conventions.envelope_signature does not describe the concatenated signing input")
	}
}

// TestPairingVectors recomputes the PAIRING-SPEC.md §3.1 schedule from s_pair.
func TestPairingVectors(t *testing.T) {
	f := load(t)

	sPair, err := b64.DecodeFixed(f.SPair, derive.SDirLen)
	if err != nil {
		t.Fatalf("s_pair: %v", err)
	}
	sDir, err := b64.DecodeFixed(f.SDir, derive.SDirLen)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Pairing) == 0 {
		t.Fatal("no pairing vectors")
	}

	for i, want := range f.Pairing {
		t.Run(itoa(i)+"/epoch="+itoa64(want.Epoch), func(t *testing.T) {
			seed, err := derive.PairWriteSeed(sPair, want.Epoch)
			if err != nil {
				t.Fatal(err)
			}
			eq(t, "pair_write_seed", seed, want.PairWriteSeed)

			wk, err := derive.PairWriteKey(sPair, want.Epoch)
			if err != nil {
				t.Fatal(err)
			}
			wkPub := wk.Public().(ed25519.PublicKey)
			eq(t, "pair_wk_pub", wkPub, want.PairWKPub)
			eq(t, "pair_wk_priv", wk, want.PairWKPriv)
			eq(t, "pair_lookup_id", derive.LookupID(wkPub), want.PairLookupID)

			recKey, err := derive.PairRecordKey(sPair, want.Epoch)
			if err != nil {
				t.Fatal(err)
			}
			eq(t, "pair_record_key", recKey, want.PairRecordKey)

			// The two schedules must not collide even for the same epoch.
			// §3.1 relies on the info strings alone to separate them.
			dirSeed, err := derive.WriteSeed(sDir, want.Epoch)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(seed, dirSeed) {
				t.Error("PairWriteSeed collides with WriteSeed")
			}

			// Applying the pairing label to s_dir must also differ, proving the
			// separation comes from the label and not merely from the secret.
			crossed, err := derive.PairWriteSeed(sDir, want.Epoch)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(crossed, dirSeed) {
				t.Error("the trig-pair-write-v1 label does not separate the schedules")
			}
		})
	}
}

func eq(t *testing.T, name string, got []byte, wantB64 string) {
	t.Helper()
	want, err := b64.Decode(wantB64)
	if err != nil {
		t.Errorf("%s: vector value does not decode: %v", name, err)
		return
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s mismatch:\n got  %x\n want %x", name, got, want)
	}
}

func contains(haystack, needle string) bool {
	return strings.Contains(haystack, needle)
}

func itoa(i int) string { return strconv.Itoa(i) }

func itoa64(i int64) string { return strconv.FormatInt(i, 10) }
