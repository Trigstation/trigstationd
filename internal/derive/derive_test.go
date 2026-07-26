// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Simon Wright

package derive

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"testing"
)

func testSDir() []byte {
	b := make([]byte, SDirLen)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

// TestEpoch covers the boundary arithmetic of DIRECTORY-SPEC.md §3.3. The
// interesting cases are the exact multiples of 86400 and the second either
// side, because an off-by-one there means a server and a client derive
// different keys for the same instant and the lookup silently returns nothing.
func TestEpoch(t *testing.T) {
	tests := []struct {
		name     string
		unixTime int64
		want     int64
	}{
		{"unix zero", 0, 0},
		{"first second of epoch 0", 1, 0},
		{"last second of epoch 0", 86399, 0},
		{"first second of epoch 1", 86400, 1},
		{"second second of epoch 1", 86401, 1},
		{"last second of epoch 20294", 1753487999, 20294},
		{"first second of epoch 20295", 1753488000, 20295},
		{"last second of epoch 20295", 1753574399, 20295},
		{"first second of epoch 20296", 1753574400, 20296},

		// Pre-1970 timestamps cannot occur in practice, but floor() and Go's
		// truncating division disagree here, and silently deriving a different
		// key would be an unpleasant way to discover that.
		{"one second before unix zero", -1, -1},
		{"one whole epoch before unix zero", -86400, -1},
		{"one second before that", -86401, -2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Epoch(tt.unixTime); got != tt.want {
				t.Errorf("Epoch(%d) = %d, want %d", tt.unixTime, got, tt.want)
			}
		})
	}
}

func TestEpochStartRoundTrip(t *testing.T) {
	for _, ep := range []int64{0, 1, 20294, 20295, 20296, 100000} {
		start := EpochStart(ep)
		if got := Epoch(start); got != ep {
			t.Errorf("Epoch(EpochStart(%d)) = %d, want %d", ep, got, ep)
		}
		if got := Epoch(start - 1); got != ep-1 {
			t.Errorf("Epoch(EpochStart(%d)-1) = %d, want %d", ep, got, ep-1)
		}
		if got := Epoch(start + EpochSeconds - 1); got != ep {
			t.Errorf("last second of epoch %d resolved to %d", ep, got)
		}
	}
}

// TestDerivationsAreDistinct is the property that stops a bug in the info
// string from going unnoticed. The three derivations share an input key and
// differ only by label, so if a label were duplicated or dropped the outputs
// would collide — and RecordKey colliding with MailboxID would publish the
// decryption key as a channel identifier.
func TestDerivationsAreDistinct(t *testing.T) {
	sDir := testSDir()
	const epoch = 20295

	seed, err := WriteSeed(sDir, epoch)
	if err != nil {
		t.Fatalf("WriteSeed: %v", err)
	}
	recKey, err := RecordKey(sDir, epoch)
	if err != nil {
		t.Fatalf("RecordKey: %v", err)
	}
	mailbox, err := MailboxID(sDir, epoch)
	if err != nil {
		t.Fatalf("MailboxID: %v", err)
	}

	values := map[string][]byte{"WriteSeed": seed, "RecordKey": recKey, "MailboxID": mailbox}
	for name, v := range values {
		if len(v) != KeyLen {
			t.Errorf("%s length = %d, want %d", name, len(v), KeyLen)
		}
		if bytes.Equal(v, make([]byte, KeyLen)) {
			t.Errorf("%s is all zeroes", name)
		}
	}
	for a, va := range values {
		for b, vb := range values {
			if a < b && bytes.Equal(va, vb) {
				t.Errorf("%s and %s collide", a, b)
			}
		}
	}
}

// TestDerivationsRotatePerEpoch is the correlation-resistance property from
// DIRECTORY-SPEC.md §3.3: every identifier must change when the epoch does.
func TestDerivationsRotatePerEpoch(t *testing.T) {
	sDir := testSDir()

	for _, fn := range []struct {
		name string
		f    func([]byte, int64) ([]byte, error)
	}{
		{"WriteSeed", WriteSeed},
		{"RecordKey", RecordKey},
		{"MailboxID", MailboxID},
	} {
		t.Run(fn.name, func(t *testing.T) {
			a, err := fn.f(sDir, 20295)
			if err != nil {
				t.Fatal(err)
			}
			b, err := fn.f(sDir, 20296)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(a, b) {
				t.Errorf("%s did not change across the epoch boundary", fn.name)
			}
		})
	}
}

// TestDerivationsAreDeterministic guards the property the whole scheme rests
// on: server and client derive the same values independently, with no round
// trip.
func TestDerivationsAreDeterministic(t *testing.T) {
	sDir := testSDir()
	for i := 0; i < 4; i++ {
		a, err := RecordKey(sDir, 20295)
		if err != nil {
			t.Fatal(err)
		}
		b, err := RecordKey(testSDir(), 20295)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(a, b) {
			t.Fatal("RecordKey is not deterministic")
		}
	}
}

func TestDeriveRejectsBadSDirLength(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33, 64} {
		if _, err := RecordKey(make([]byte, n), 20295); !errors.Is(err, ErrSDirLen) {
			t.Errorf("RecordKey with %d-byte S_dir: err = %v, want ErrSDirLen", n, err)
		}
	}
}

// TestWriteKeyMatchesWriteSeed pins the reading of "Ed25519 keypair from
// WriteSeed" as RFC 8032 seed-based generation.
func TestWriteKeyMatchesWriteSeed(t *testing.T) {
	sDir := testSDir()
	const epoch = 20295

	seed, err := WriteSeed(sDir, epoch)
	if err != nil {
		t.Fatal(err)
	}
	wk, err := WriteKey(sDir, epoch)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(wk.Seed(), seed) {
		t.Error("WriteKey's seed does not equal WriteSeed")
	}
	if !bytes.Equal(wk[:ed25519.SeedSize], seed) {
		t.Error("the first 32 bytes of the private key do not equal WriteSeed")
	}

	// The keypair must actually work; a seed that produced a malformed key
	// would still satisfy the checks above.
	msg := []byte("trigstation")
	if !ed25519.Verify(wk.Public().(ed25519.PublicKey), msg, ed25519.Sign(wk, msg)) {
		t.Error("WriteKey did not produce a usable keypair")
	}
}

// TestLookupIDIsSHA256OfWKPub is the binding the directory checks on publish
// (DIRECTORY-SPEC.md §5.2).
func TestLookupIDIsSHA256OfWKPub(t *testing.T) {
	wk, err := WriteKey(testSDir(), 20295)
	if err != nil {
		t.Fatal(err)
	}
	pub := wk.Public().(ed25519.PublicKey)

	want := sha256.Sum256(pub)
	got := LookupID(pub)

	if !bytes.Equal(got, want[:]) {
		t.Errorf("LookupID = %x, want %x", got, want)
	}
	if len(got) != 32 {
		t.Errorf("LookupID length = %d, want 32", len(got))
	}
}

// TestPairDerivationsDoNotCollide is the property PAIRING-SPEC.md §3.1 relies
// on: the pairing schedule mirrors the S_dir one exactly, so only the distinct
// info strings stop a pairing record and a normal record colliding. If the
// labels were ever confused, the same secret would derive the same identifiers
// under both schedules.
func TestPairDerivationsDoNotCollide(t *testing.T) {
	secret := testSDir()
	const epoch = 20295

	writeSeed, err := WriteSeed(secret, epoch)
	if err != nil {
		t.Fatal(err)
	}
	pairWriteSeed, err := PairWriteSeed(secret, epoch)
	if err != nil {
		t.Fatal(err)
	}
	recKey, err := RecordKey(secret, epoch)
	if err != nil {
		t.Fatal(err)
	}
	pairRecKey, err := PairRecordKey(secret, epoch)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(writeSeed, pairWriteSeed) {
		t.Error("WriteSeed and PairWriteSeed collide for the same secret and epoch")
	}
	if bytes.Equal(recKey, pairRecKey) {
		t.Error("RecordKey and PairRecordKey collide for the same secret and epoch")
	}

	// PairLookupID is SHA-256(PairWK_pub), the same function as LookupID —
	// a directory cannot tell the two kinds of record apart, by design.
	pairWK, err := PairWriteKey(secret, epoch)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pairWK.Seed(), pairWriteSeed) {
		t.Error("PairWriteKey's seed does not equal PairWriteSeed")
	}
	wk, err := WriteKey(secret, epoch)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(
		LookupID(pairWK.Public().(ed25519.PublicKey)),
		LookupID(wk.Public().(ed25519.PublicKey)),
	) {
		t.Error("PairLookupID and LookupID collide")
	}
}

func TestPairInfoStringsAreUnchanged(t *testing.T) {
	if InfoPairWrite != "trig-pair-write-v1" {
		t.Errorf("InfoPairWrite = %q", InfoPairWrite)
	}
	if InfoPairRecord != "trig-pair-record-v1" {
		t.Errorf("InfoPairRecord = %q", InfoPairRecord)
	}
}

// TestEpochInfoEncoding pins the §0.1 integer encoding — the epoch as an 8-byte
// big-endian unsigned integer — so that a change to it is a deliberate act with
// a failing test attached, rather than a silent break of every deployed client.
func TestEpochInfoEncoding(t *testing.T) {
	got := epochInfo("trig-write-v1", 20294)
	want := "trig-write-v1" + string([]byte{0, 0, 0, 0, 0, 0, 0x4f, 0x46})
	if got != want {
		t.Errorf("epochInfo = %x, want %x", got, want)
	}
}

// TestInfoStringsAreUnchanged. These are byte-exact wire format
// (DIRECTORY-SPEC.md §0). A typo here breaks every other implementation and
// nothing else in the test suite would notice.
func TestInfoStringsAreUnchanged(t *testing.T) {
	tests := []struct{ got, want string }{
		{InfoWrite, "trig-write-v1"},
		{InfoRecord, "trig-record-v1"},
		{InfoMailbox, "trig-mailbox-v1"},
	}
	for _, tt := range tests {
		if tt.got != tt.want {
			t.Errorf("info string = %q, want %q", tt.got, tt.want)
		}
	}
	if EpochSeconds != 86400 {
		t.Errorf("EpochSeconds = %d, want 86400", EpochSeconds)
	}
}
