// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Simon Wright

package b64

import (
	"bytes"
	"strings"
	"testing"
)

func TestEncodeNeverPads(t *testing.T) {
	// Lengths 1 and 2 mod 3 are the ones a padded encoder would pad.
	for n := 0; n <= 34; n++ {
		in := bytes.Repeat([]byte{0xff}, n)
		got := Encode(in)
		if strings.Contains(got, "=") {
			t.Errorf("Encode(%d bytes) emitted padding: %q", n, got)
		}
	}
}

func TestRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
	}{
		{"empty", []byte{}},
		{"one byte", []byte{0x00}},
		{"two bytes", []byte{0xff, 0x00}},
		{"three bytes", []byte{0x01, 0x02, 0x03}},
		{"all byte values", allBytes()},
		// 62 and 63 encode as '-' and '_' in base64url, not '+' and '/'.
		// Getting this wrong is a classic interoperability failure.
		{"url alphabet", []byte{0xfb, 0xff, 0xbf}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enc := Encode(tt.in)
			if strings.ContainsAny(enc, "+/=") {
				t.Errorf("Encode used standard-alphabet or padding characters: %q", enc)
			}
			got, err := Decode(enc)
			if err != nil {
				t.Fatalf("Decode(%q): %v", enc, err)
			}
			if !bytes.Equal(got, tt.in) {
				t.Errorf("round trip mismatch: got %x, want %x", got, tt.in)
			}
		})
	}
}

func TestDecode(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    []byte
		wantErr bool
	}{
		{"unpadded", "AQID", []byte{1, 2, 3}, false},
		// The spec mandates accepting unpadded input; padded input is tolerated
		// here as a courtesy to a peer that violates "MUST NOT emit padding".
		{"padded is tolerated", "AQI=", []byte{1, 2}, false},
		{"padded two chars", "AQ==", []byte{1}, false},
		{"url alphabet decodes", "-_8", []byte{0xfb, 0xff}, false},
		{"standard alphabet rejected", "+/8", nil, true},
		{"not base64", "!!!!", nil, true},
		{"empty", "", []byte{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Decode(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("Decode(%q) = %x, want error", tt.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("Decode(%q): %v", tt.in, err)
			}
			if !bytes.Equal(got, tt.want) {
				t.Errorf("Decode(%q) = %x, want %x", tt.in, got, tt.want)
			}
		})
	}
}

func TestDecodeFixed(t *testing.T) {
	thirtyTwo := Encode(bytes.Repeat([]byte{0xaa}, 32))

	tests := []struct {
		name    string
		in      string
		n       int
		wantErr bool
	}{
		{"exact length", thirtyTwo, 32, false},
		{"too short", Encode(bytes.Repeat([]byte{0xaa}, 31)), 32, true},
		{"too long", Encode(bytes.Repeat([]byte{0xaa}, 33)), 32, true},
		{"malformed", "!!!", 32, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecodeFixed(tt.in, tt.n)
			if tt.wantErr != (err != nil) {
				t.Fatalf("DecodeFixed(%d bytes wanted) error = %v, wantErr %v", tt.n, err, tt.wantErr)
			}
		})
	}
}

// TestDecodeFixedErrorOmitsValue guards the "no request logging" rule at the
// point where it is easiest to break: an error message that helpfully quotes
// the identifier that failed to parse.
func TestDecodeFixedErrorOmitsValue(t *testing.T) {
	secret := Encode([]byte("a-lookup-id-that-must-not-be-logged"))
	_, err := DecodeFixed(secret, 32)
	if err == nil {
		t.Fatal("want an error for the wrong length")
	}
	if strings.Contains(err.Error(), secret) {
		t.Errorf("error message leaked the offending value: %v", err)
	}
}

func allBytes() []byte {
	b := make([]byte, 256)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}
