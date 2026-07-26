// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Simon Wright

package store

import (
	"encoding/binary"

	"github.com/trigstation/trigstationd/internal/query"
)

// PrefixBits is the width of the prefix column: the first 32 bits of a
// lookup_id, held as an integer so that a bit-prefix query becomes an indexed
// range scan (DIRECTORY-SPEC.md §9).
//
// It is an alias for the same constant in internal/query, which owns the
// §5.3 prefix maths. The column width and the width the query masks to are the
// same number by necessity, and declaring it twice would let them drift.
const PrefixBits = query.PrefixColumnBits

// prefix32 returns the first 32 bits of a lookup_id as an int64.
//
// This is the write side: the value stored in the prefix column when a record
// is put. The read side — masking a query prefix and matching a candidate row —
// belongs to internal/query, which implements the §5.3 alignment rule once for
// the whole codebase. Only the derivation of the column value from a complete
// lookup_id lives here, because nothing outside storage needs it.
//
// The result is deliberately int64 and not int32. SQLite's INTEGER is a signed
// 64-bit value, and a 32-bit prefix runs to 4294967295, so half the keyspace —
// every lookup_id whose first byte is 0x80 or above — becomes unreachable if
// the value is ever narrowed to int32 on the way in or out.
//
// The caller must have checked the length; see Put.
func prefix32(lookupID []byte) int64 {
	return int64(binary.BigEndian.Uint32(lookupID[:4]))
}
