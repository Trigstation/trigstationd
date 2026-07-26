// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Simon Wright

package store

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The "no request logging" rule of CLAUDE.md is a property of the source, not
// of the configuration: the code to log a request path, a client address, a
// lookup prefix or a channel identifier must not exist. Not disabled, not
// behind a flag, not at debug level — absent. A directory operator who cannot
// log is one who cannot be compelled to produce logs, and that is the property
// the service is credible on.
//
// This package sits directly on the identifiers that must never be written
// down, so the rule is asserted here against the source itself rather than left
// to review. The tests below read the package's own .go files.

// loggingPackages are import paths this package must never carry.
var loggingPackages = map[string]bool{
	"log":                        true,
	"log/slog":                   true,
	"log/syslog":                 true,
	"github.com/sirupsen/logrus": true,
	"go.uber.org/zap":            true,
	"github.com/rs/zerolog":      true,
}

// identifierBearing names variables that hold, or are named after, a value that
// must never reach an error message or an output stream. The check is on the
// name because that is what survives a refactor: a variable called lookupID is
// a lookup_id whatever its type becomes.
var identifierBearing = map[string]bool{
	"lookupid":   true,
	"lookup_id":  true,
	"wkpub":      true,
	"wk_pub":     true,
	"envelope":   true,
	"envelopes":  true,
	"prefix":     true,
	"rec":        true,
	"id":         true,
	"ct":         true,
	"nonce":      true,
	"sig":        true,
	"pow":        true,
	"addr":       true,
	"address":    true,
	"remoteaddr": true,
	"channelid":  true,
	"blob":       true,
	"secret":     true,
}

// formatters are the calls that turn a value into text.
var formatters = map[string]bool{
	"Errorf": true, "Sprintf": true, "Sprint": true, "Sprintln": true,
	"Printf": true, "Print": true, "Println": true,
	"Fprintf": true, "Fprint": true, "Fprintln": true,
}

// TestNoLoggingPackageIsImported fails if any file in this package imports a
// logging package, test files included. Nothing here has a use for one, and an
// import that exists only in a test today is an import that is available to
// production code tomorrow.
func TestNoLoggingPackageIsImported(t *testing.T) {
	for _, file := range parsePackage(t, true) {
		for _, imp := range file.f.Imports {
			path, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				t.Fatalf("%s: unquoting an import path: %v", file.name, err)
			}
			if loggingPackages[path] {
				t.Errorf("%s imports %q: the code to log must not exist", file.name, path)
			}
			base := path
			if i := strings.LastIndexByte(base, '/'); i >= 0 {
				base = base[i+1:]
			}
			if base == "log" || base == "slog" {
				t.Errorf("%s imports %q, which appears to be a logging package", file.name, path)
			}
		}
	}
}

// TestNoIdentifierIsFormatted fails if a formatting call in this package's
// production source is handed a value that carries an identifier.
//
// Error logs must name the failure mode, never the value that caused it. The
// helpful version of an error — the one that quotes the lookup_id it could not
// parse — is exactly the logging this service must not be able to do, and it
// arrives as a small readability improvement rather than as a decision anyone
// would notice making.
//
// Test files are excluded. They run against synthetic identifiers that were
// invented in the test and never left the process, and they need to be able to
// print them to be diagnosable at all.
func TestNoIdentifierIsFormatted(t *testing.T) {
	for _, file := range parsePackage(t, false) {
		ast.Inspect(file.f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || !formatters[sel.Sel.Name] {
				return true
			}
			for _, arg := range call.Args {
				if name, found := identifierArg(arg); found {
					t.Errorf("%s: %s is passed %q — log the failure mode, never the value that caused it",
						file.name, sel.Sel.Name, name)
				}
			}
			return true
		})
	}
}

// TestNoDirectOutput fails on a write to a process output stream. There is no
// legitimate reason for storage to write to stdout or stderr, and a stray
// diagnostic there is logging by another name.
func TestNoDirectOutput(t *testing.T) {
	for _, file := range parsePackage(t, false) {
		ast.Inspect(file.f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || pkg.Name != "os" {
				return true
			}
			if sel.Sel.Name == "Stdout" || sel.Sel.Name == "Stderr" {
				t.Errorf("%s writes to os.%s: this package produces no output", file.name, sel.Sel.Name)
			}
			return true
		})
	}
}

// identifierArg reports whether an argument to a formatting call names, or
// selects, a value that carries an identifier.
func identifierArg(arg ast.Expr) (string, bool) {
	var name string
	var found bool

	ast.Inspect(arg, func(n ast.Node) bool {
		if found {
			return false
		}
		switch e := n.(type) {
		case *ast.SelectorExpr:
			if identifierBearing[strings.ToLower(e.Sel.Name)] {
				name, found = e.Sel.Name, true
				return false
			}
		case *ast.Ident:
			if identifierBearing[strings.ToLower(e.Name)] {
				name, found = e.Name, true
				return false
			}
		}
		return true
	})

	return name, found
}

type parsedFile struct {
	name string
	f    *ast.File
}

// parsePackage reads this package's own source from the directory the test runs
// in.
func parsePackage(t *testing.T, includeTests bool) []parsedFile {
	t.Helper()

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading the package directory: %v", err)
	}

	fset := token.NewFileSet()
	var files []parsedFile
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || filepath.Ext(name) != ".go" {
			continue
		}
		if !includeTests && strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		files = append(files, parsedFile{name: name, f: f})
	}

	if len(files) == 0 {
		t.Fatal("no source files found: the guard would pass vacuously")
	}
	return files
}
