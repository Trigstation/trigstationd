// Trigstation directory service — a zero-knowledge coordination service
// for self-hosted media servers.
// Copyright (C) 2026  Simon Wright
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or (at your
// option) any later version.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Affero General Public
// License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

// Command trigstationd is the reference implementation of the Trigstation
// directory service, specified in DIRECTORY-SPEC.md.
//
// The service stores encrypted address records on behalf of self-hosted media
// servers and brokers short-lived rendezvous channels between paired clients.
// It never carries media, holds no accounts, and cannot read what it stores.
//
// The HTTP service is not implemented yet. Phase 1 delivered the cryptographic
// core in internal/ and the test vectors in testdata/vectors.json; the four
// operations of DIRECTORY-SPEC.md §5 arrive in phase 2.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "trigstationd: the HTTP service is not implemented yet (phase 2).")
	fmt.Fprintln(os.Stderr, "Phase 1 delivers the derivations, record format and test vectors.")
	fmt.Fprintln(os.Stderr, "Run 'go test ./...' to exercise them.")
	os.Exit(1)
}
