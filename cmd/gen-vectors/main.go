// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Simon Wright

// Command gen-vectors regenerates testdata/vectors.json.
//
// DIRECTORY-SPEC.md §9 makes the vectors a shipped artefact, so they need to be
// regenerable rather than hand-maintained. Generation is deterministic: running
// this twice produces byte-identical output, and vectors_test.go fails if the
// committed file does not match what the current code produces.
//
//	go run ./cmd/gen-vectors -o testdata/vectors.json
//
// This is a build-time tool. It is not part of the service and adds no endpoint.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"

	"github.com/trigstation/trigstationd/internal/vectors"
)

func main() {
	out := flag.String("o", "testdata/vectors.json", "output path")
	flag.Parse()

	if err := run(*out); err != nil {
		fmt.Fprintf(os.Stderr, "gen-vectors: %v\n", err)
		os.Exit(1)
	}
}

func run(out string) error {
	// The proof-of-work search is the slow step; make it interruptible.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	f, err := vectors.Generate(ctx)
	if err != nil {
		return err
	}

	b, err := vectors.Marshal(f)
	if err != nil {
		return err
	}

	return os.WriteFile(out, b, 0o644)
}
