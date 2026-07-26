// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Simon Wright

// Command gen-api-vectors regenerates testdata/api-vectors.json.
//
// DIRECTORY-SPEC.md §9 makes two vector sets a shipped artefact: derivation
// vectors, produced by cmd/gen-vectors, and these API vectors, which cover the
// status tables of §5.2 and §5.4, the evaluation order §5.2 mandates, and the
// verbatim-storage requirement. Both are generated rather than maintained by
// hand, and both are self-checking, so a value that no longer matches the code
// fails a build instead of quietly misleading a reader.
//
// Generation is deterministic: running this twice produces byte-identical
// output, and internal/apivectors' tests fail if the committed file does not
// match what the current code produces.
//
//	go run ./cmd/gen-api-vectors -o testdata/api-vectors.json
//
// This is a build-time tool. It is not part of the service and adds no
// endpoint — §10 keeps the API at four operations, and a generator that could
// be reached over the network would be a fifth.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"

	"github.com/trigstation/trigstationd/internal/apivectors"
)

func main() {
	out := flag.String("o", "testdata/api-vectors.json", "output path")
	flag.Parse()

	if err := run(*out); err != nil {
		fmt.Fprintf(os.Stderr, "gen-api-vectors: %v\n", err)
		os.Exit(1)
	}
}

func run(out string) error {
	// The proof-of-work searches are the slow step; make them interruptible.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	f, err := apivectors.Generate(ctx)
	if err != nil {
		return err
	}

	b, err := apivectors.Marshal(f)
	if err != nil {
		return err
	}

	return os.WriteFile(out, b, 0o644)
}
