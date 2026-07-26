// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Simon Wright

package store

import "testing"

// TestPrefix32 pins the width of the prefix column.
//
// The values above 2^31 are the point of the test. SQLite's INTEGER is signed
// 64-bit, so a 32-bit prefix fits comfortably — but only if it is never
// narrowed to int32 on the way through. Narrowing turns 0xFF000000 into a
// negative number, and every lookup_id whose first bit is set stops being
// findable by a range scan.
// The bit-alignment maths this file used to test — masking a query prefix and
// matching a candidate lookup_id — now lives in internal/query, which owns the
// §5.3 rule for the whole codebase. Its unit tests went with it. What remains
// here is the write side: deriving the prefix column value from a complete
// lookup_id, which is storage's own concern.
//
// The read side is still exercised end to end by TestByPrefixBitLengths in
// store_test.go, which is the test that matters — it runs through real SQL
// against real rows rather than against the maths in isolation.

func TestPrefix32(t *testing.T) {
	tests := []struct {
		name string
		id   []byte
		want int64
	}{
		{"all zero", lookupID(0x00, 0x00, 0x00, 0x00), 0},
		{"one", lookupID(0x00, 0x00, 0x00, 0x01), 1},
		{"just below the int32 boundary", lookupID(0x7f, 0xff, 0xff, 0xff), 2147483647},
		{"at the int32 boundary", lookupID(0x80, 0x00, 0x00, 0x00), 2147483648},
		{"top of the keyspace", lookupID(0xff, 0xff, 0xff, 0xff), 4294967295},
		{"leading 0xff", lookupID(0xff, 0x01, 0x02, 0x03), 4278256131},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := prefix32(tt.id); got != tt.want {
				t.Errorf("prefix32() = %d, want %d", got, tt.want)
			}
			if got := prefix32(tt.id); got < 0 {
				t.Errorf("prefix32() = %d, which is negative — the value has been narrowed to int32", got)
			}
		})
	}
}
