// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Simon Wright

package api

import (
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The "no request logging" rule of CLAUDE.md and DIRECTORY-SPEC.md §9 is a
// property of the source, not of the configuration: the code to log a request
// path, a client address, a lookup prefix or a channel identifier must not
// exist. Not disabled, not behind a flag, not at debug level — absent. A
// directory operator who cannot log is one who cannot be compelled to produce
// logs, and that is the property the service is credible on.
//
// This package is where the rule is most at risk. It is the only one that sees a
// request path, a client address, a lookup prefix and a channel identifier
// together, and it is the one where a diagnostic would arrive as an obvious
// convenience rather than as a decision anybody noticed making. The checks below
// read this package's own source, so the rule survives a reviewer having a busy
// week.
//
// The same guards exist in internal/store, internal/query and internal/ratelimit.
// They are duplicated rather than shared because a test helper package would be
// one import away from being disabled everywhere at once.

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
// name because that is what survives a refactor: a variable called lookupID is a
// lookup_id whatever its type becomes.
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
	"channelid":  true,
	"channel_id": true,
	"ct":         true,
	"nonce":      true,
	"sig":        true,
	"pow":        true,
	"addr":       true,
	"address":    true,
	"remoteaddr": true,
	"peer":       true,
	"xff":        true,
	"forwarded":  true,
	"blob":       true,
	"body":       true,
	"secret":     true,
	"path":       true,
	"url":        true,
	"query":      true,
	"request":    true,
	"req":        true,
	"r":          true,
}

// formatters are the calls that turn a value into text.
var formatters = map[string]bool{
	"Errorf": true, "Sprintf": true, "Sprint": true, "Sprintln": true,
	"Printf": true, "Print": true, "Println": true,
	"Fprintf": true, "Fprint": true, "Fprintln": true,
}

// TestNoLoggingPackageIsImported fails if any file in this package imports a
// logging package, test files included. An import that exists only in a test
// today is an import that is available to production code tomorrow.
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
// production source is handed a value that carries request data.
//
// The helpful version of an error — the one that quotes the path it could not
// route or the channel it could not parse — is exactly the logging this service
// must not be able to do, and it arrives as a small readability improvement.
//
// Test files are excluded. They run against synthetic identifiers invented in
// the test and never sent anywhere, and they need to print them to be
// diagnosable at all.
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

// TestNoDirectOutput fails on a write to a process output stream.
//
// The handlers have no legitimate reason to write to stdout or stderr, and a
// stray diagnostic there is request logging by another name. Startup and
// fatal-error messages belong in main, which serves no requests and so has
// nothing from one to disclose.
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
				t.Errorf("%s writes to os.%s: the HTTP layer produces no output", file.name, sel.Sel.Name)
			}
			return true
		})
	}
}

// TestNoErrorLoggerIsConfigured guards the one leak that is not this package's
// own doing.
//
// net/http, with no ErrorLog set, reports a handler panic through the standard
// logger as "http: panic serving <client address>: …", which puts a client
// address on stderr. The fix taken in ServeHTTP is to recover before net/http
// can see the panic — deliberately, rather than by configuring a discarding
// logger, because that would require importing log and the requirement is that
// the code to log must not exist.
//
// This test fails if the recovery is removed, by driving a handler that panics
// through the router and checking the response is produced rather than the
// connection torn down.
func TestNoErrorLoggerIsConfigured(t *testing.T) {
	h := newHarness(t, options{})

	// Reach past the router to the wrapper, since no registered handler panics.
	h.api.mux.HandleFunc("GET /panic-fixture", func(w http.ResponseWriter, r *http.Request) {
		panic("a fixture panic that must not reach net/http's error logger")
	})

	status, read, err := h.get("/panic-fixture")
	if err != nil {
		t.Fatalf("a panicking handler tore down the connection: %v", err)
	}
	if status != http.StatusInternalServerError {
		t.Errorf("a panicking handler returned %d, want 500", status)
	}
	if len(read) != 0 {
		t.Errorf("the response carries a body of %d bytes", len(read))
	}
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

// identifierArg reports whether an argument to a formatting call names, or
// selects, a value that carries request data.
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
