// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Simon Wright

package query

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// TestNoLoggingImports scans this package's own sources and fails if any of them
// imports a logging package.
//
// The requirement is not that logging is disabled or gated behind a flag: the
// code to log a request path, a client address or a lookup prefix must not
// exist. A directory operator who cannot log is one who cannot be compelled to
// produce logs, and that property is only credible if it is structural.
//
// This package is where it matters most. A lookup prefix is the one identifier
// §5.3 is built to withhold — the whole of the anonymity argument in §8 is that
// the directory learns only which bucket was asked about, and a log of prefixes
// is a record of exactly that, retained.
//
// The scan is over the package directory rather than the whole tree, so each
// package carries its own copy of this test and none of them can be deleted
// silently by moving a file.
func TestNoLoggingImports(t *testing.T) {
	forbidden := map[string]bool{
		"log":        true,
		"log/slog":   true,
		"log/syslog": true,
	}

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading the package directory: %v", err)
	}

	scanned := 0
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".go" {
			continue
		}
		scanned++

		file, err := parser.ParseFile(token.NewFileSet(), e.Name(), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("%s: %v", e.Name(), err)
		}
		for _, imp := range file.Imports {
			path, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				t.Fatalf("%s: malformed import path", e.Name())
			}
			if forbidden[path] {
				t.Errorf("%s imports %q — the code to log must not exist, not merely be unused", e.Name(), path)
			}
		}
	}

	if scanned == 0 {
		t.Fatal("scanned no files; the test is not looking where it thinks it is")
	}
}
