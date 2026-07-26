// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Simon Wright

package pow

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"testing"
)

func testLookupID() []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

func TestLeadingZeroBits(t *testing.T) {
	tests := []struct {
		name   string
		digest []byte
		want   int
	}{
		{"all zero", make([]byte, 32), 256},
		{"first bit set", append([]byte{0x80}, make([]byte, 31)...), 0},
		{"one leading zero", append([]byte{0x40}, make([]byte, 31)...), 1},
		{"seven leading zeros", append([]byte{0x01}, make([]byte, 31)...), 7},
		{"eight leading zeros", append([]byte{0x00, 0x80}, make([]byte, 30)...), 8},
		{"twenty leading zeros", append([]byte{0x00, 0x00, 0x08}, make([]byte, 29)...), 20},
		{"nineteen leading zeros", append([]byte{0x00, 0x00, 0x10}, make([]byte, 29)...), 19},
		{"empty", nil, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := LeadingZeroBits(tt.digest); got != tt.want {
				t.Errorf("LeadingZeroBits = %d, want %d", got, tt.want)
			}
		})
	}
}

// TestInputLayout pins the byte layout of the hashed preimage, including the
// expires_at width that §6.1 leaves unstated.
func TestInputLayout(t *testing.T) {
	lookupID := bytes.Repeat([]byte{0x11}, 32)
	powVal := []byte{1, 2, 3, 4, 5, 6, 7, 8}

	got := Input(lookupID, 1753574400, powVal)

	var want []byte
	want = append(want, "trig-pow-v1"...)
	want = append(want, lookupID...)
	want = append(want, 0x00, 0x00, 0x00, 0x00, 0x68, 0x85, 0x6c, 0x00) // 1753574400 big-endian
	want = append(want, powVal...)

	if !bytes.Equal(got, want) {
		t.Errorf("Input =\n%x\nwant\n%x", got, want)
	}
	if !bytes.HasPrefix(got, []byte(Prefix)) {
		t.Error("Input does not begin with the domain separation prefix")
	}
}

// TestPrefixIsUnchanged. Byte-exact wire format, DIRECTORY-SPEC.md §0.
func TestPrefixIsUnchanged(t *testing.T) {
	if Prefix != "trig-pow-v1" {
		t.Errorf("Prefix = %q, want %q", Prefix, "trig-pow-v1")
	}
	if Len != 8 {
		t.Errorf("Len = %d, want 8", Len)
	}
	if DefaultBits != 20 {
		t.Errorf("DefaultBits = %d, want 20", DefaultBits)
	}
}

// TestSolveThenVerify runs the real search at a low difficulty. Twenty bits is
// exercised once, in the vector test, because a million hashes per case would
// dominate the suite.
func TestSolveThenVerify(t *testing.T) {
	lookupID := testLookupID()
	const expiresAt = 1753574400

	for _, bits := range []int{0, 1, 8, 12, 16} {
		t.Run(bitsName(bits), func(t *testing.T) {
			got, err := Solve(context.Background(), lookupID, expiresAt, bits)
			if err != nil {
				t.Fatalf("Solve: %v", err)
			}
			if len(got) != Len {
				t.Fatalf("pow length = %d, want %d", len(got), Len)
			}
			if !Verify(lookupID, expiresAt, got, bits) {
				t.Errorf("Verify rejected the solution Solve returned")
			}

			// Confirm independently rather than trusting Verify.
			sum := sha256.Sum256(Input(lookupID, expiresAt, got))
			if n := LeadingZeroBits(sum[:]); n < bits {
				t.Errorf("digest has %d leading zero bits, want at least %d", n, bits)
			}
		})
	}
}

// TestSolveIsDeterministic matters because the committed vectors must be
// reproducible by anyone running the generator.
func TestSolveIsDeterministic(t *testing.T) {
	lookupID := testLookupID()
	a, err := Solve(context.Background(), lookupID, 1753574400, 12)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Solve(context.Background(), lookupID, 1753574400, 12)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Errorf("Solve returned %x then %x", a, b)
	}
}

// TestSolveFindsTheLowestCounter. Not a protocol requirement — search order is
// free — but it confirms the search starts at zero and misses nothing, which is
// what makes the vectors reproducible across implementations that also count up.
func TestSolveFindsTheLowestCounter(t *testing.T) {
	lookupID := testLookupID()
	const expiresAt = 1753574400
	const bits = 12

	got, err := Solve(context.Background(), lookupID, expiresAt, bits)
	if err != nil {
		t.Fatal(err)
	}
	found := binary.BigEndian.Uint64(got)

	buf := make([]byte, Len)
	for i := uint64(0); i < found; i++ {
		binary.BigEndian.PutUint64(buf, i)
		sum := sha256.Sum256(Input(lookupID, expiresAt, buf))
		if LeadingZeroBits(sum[:]) >= bits {
			t.Fatalf("counter %d also solves the challenge but Solve returned %d", i, found)
		}
	}
}

func TestVerifyRejections(t *testing.T) {
	lookupID := testLookupID()
	const expiresAt = 1753574400

	solution, err := Solve(context.Background(), lookupID, expiresAt, 12)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		lookupID  []byte
		expiresAt int64
		pow       []byte
		bits      int
		want      bool
	}{
		{"valid", lookupID, expiresAt, solution, 12, true},
		{"difficulty raised above the solution", lookupID, expiresAt, solution, 32, false},
		{"different lookup_id", flip(lookupID, 0), expiresAt, solution, 12, false},
		{"different expires_at", lookupID, expiresAt + 1, solution, 12, false},
		{"tampered counter", lookupID, expiresAt, flip(solution, 7), 12, false},

		// A short or long pow must fail rather than being padded. Accepting a
		// 4-byte counter would let a publisher search a smaller space than the
		// difficulty was priced for.
		{"pow too short", lookupID, expiresAt, solution[:4], 12, false},
		{"pow too long", lookupID, expiresAt, append(bytes.Clone(solution), 0), 12, false},
		{"pow empty", lookupID, expiresAt, nil, 12, false},
		{"negative difficulty", lookupID, expiresAt, solution, -1, false},

		// Zero bits accepts anything of the right length, by construction.
		{"zero difficulty accepts any counter", lookupID, expiresAt, make([]byte, Len), 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Verify(tt.lookupID, tt.expiresAt, tt.pow, tt.bits); got != tt.want {
				t.Errorf("Verify = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSolveRejectsAbsurdDifficulty(t *testing.T) {
	for _, bits := range []int{-1, MaxBits + 1, 256} {
		if _, err := Solve(context.Background(), testLookupID(), 0, bits); err == nil {
			t.Errorf("Solve at %d bits returned no error", bits)
		}
	}
}

func TestSolveHonoursContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// 40 bits would take hours; a cancelled context must return promptly.
	if _, err := Solve(ctx, testLookupID(), 0, MaxBits); err == nil {
		t.Error("Solve ignored a cancelled context")
	}
}

func flip(b []byte, i int) []byte {
	out := bytes.Clone(b)
	out[i] ^= 0x01
	return out
}

func bitsName(b int) string {
	return fmt.Sprintf("bits=%d", b)
}
