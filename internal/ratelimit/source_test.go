// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Simon Wright

package ratelimit

// This file tests the package's source rather than its behaviour.
//
// DIRECTORY-SPEC.md §6.4 requires that no code path exists which emits either
// the limiter key or the untruncated address — a property of what is written,
// not of what happens to run. A behavioural test cannot establish it, because
// the disclosure that matters is the one somebody adds in six months while
// chasing an unrelated bug. So the checks below parse every .go file in the
// package and fail on the constructs that would make disclosure possible:
//
//   - an import of log or log/slog, anywhere;
//   - any import at all outside a three-package allowlist in the implementation
//     files, which is what keeps fmt — and with it every format verb — out of
//     reach;
//   - a String, Error or Marshal method on any type declared here;
//   - a rendering call applied to a value that holds address material;
//   - a function in the implementation returning an error, since an error is a
//     string that travels.
//
// The checkers are self-tested against deliberately bad sources at the bottom
// of the file, so that a checker which has stopped detecting anything fails
// rather than passing quietly.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// allowedImports is the whole of what the implementation may depend on.
//
// It is an allowlist rather than a denylist on purpose. A denylist naming fmt
// and log is one import away from being wrong — encoding/json, os, io, net/http
// and expvar would each do just as well at putting an address on an output
// stream. Adding to this set has to be a deliberate act with a reason attached.
var allowedImports = map[string]bool{
	"net/netip": true,
	"sync":      true,
	"time":      true,
}

// forbiddenImports may not appear in any file of the package, tests included.
// §9 requires that the code to log "must not exist", and a test that logs is
// still code that logs.
var forbiddenImports = map[string]bool{
	"log":      true,
	"log/slog": true,
	"syslog":   true,
}

// forbiddenMethods are the names by which a value renders or serialises itself.
// The ban is blanket rather than restricted to the address-bearing types: a
// String method on Class would be harmless, but "harmless" is a judgement that
// has to be made again at every review, whereas "this package declares no such
// method" is checkable.
var forbiddenMethods = map[string]bool{
	"String":        true,
	"GoString":      true,
	"Error":         true,
	"Format":        true,
	"MarshalText":   true,
	"MarshalJSON":   true,
	"MarshalBinary": true,
	"AppendText":    true,
	"AppendFormat":  true,
	"GobEncode":     true,
	"WriteTo":       true,
	"Text":          true,
}

// renderingFuncs are the call names that turn a value into text. Anything in
// this set applied to an address-bearing value is a disclosure.
var renderingFuncs = map[string]bool{
	"Sprintf": true, "Sprint": true, "Sprintln": true,
	"Printf": true, "Print": true, "Println": true,
	"Fprintf": true, "Fprint": true, "Fprintln": true,
	"Errorf": true, "Fatalf": true, "Logf": true, "Skipf": true, "Panicf": true,
	"Error": true, "Fatal": true, "Log": true, "Skip": true, "Panic": true,
	"String": true, "GoString": true, "Append": true, "Appendf": true,
}

// seedTaintedTypes names the types that hold address material by construction
// rather than by mentioning a netip type. key is the whole of it: its net field
// is [16]byte because it is a truncated address, which no type checker can see.
var seedTaintedTypes = []string{"key"}

// netipAddressTypes are the netip types that carry an address.
var netipAddressTypes = map[string]bool{"Addr": true, "Prefix": true, "AddrPort": true}

// netipConstructors return one.
var netipConstructors = map[string]bool{
	"ParseAddr": true, "MustParseAddr": true,
	"AddrFrom4": true, "AddrFrom16": true, "AddrFromSlice": true,
	"ParsePrefix": true, "MustParsePrefix": true, "PrefixFrom": true,
	"ParseAddrPort": true, "MustParseAddrPort": true, "AddrPortFrom": true,
}

type sourceFile struct {
	name string
	ast  *ast.File
	test bool
}

func packageSources(t *testing.T) (*token.FileSet, []sourceFile) {
	t.Helper()

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading the package directory: %v", err)
	}
	fset := token.NewFileSet()
	var files []sourceFile
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".go" {
			continue
		}
		f, err := parser.ParseFile(fset, e.Name(), nil, parser.ParseComments)
		if err != nil {
			t.Fatalf("parsing %s: %v", e.Name(), err)
		}
		files = append(files, sourceFile{
			name: e.Name(),
			ast:  f,
			test: strings.HasSuffix(e.Name(), "_test.go"),
		})
	}

	// A scan that found nothing must not pass. This has been the failure mode
	// of every source-checking test that ever stopped working.
	impl := 0
	for _, f := range files {
		if !f.test {
			impl++
		}
	}
	if impl == 0 {
		t.Fatalf("found no implementation files to check")
	}
	return fset, files
}

// TestNoLoggingImports is the "no request logging" requirement of CLAUDE.md and
// DIRECTORY-SPEC.md §9, checked rather than asserted.
func TestNoLoggingImports(t *testing.T) {
	_, files := packageSources(t)
	for _, f := range files {
		t.Run(f.name, func(t *testing.T) {
			for _, path := range importPaths(f.ast) {
				if forbiddenImports[path] || strings.HasPrefix(path, "log/") {
					t.Errorf("imports %q: the code to log must not exist, at any severity, under any configuration", path)
				}
			}
		})
	}
}

// TestImportsAreAllowlisted keeps every rendering and output facility out of
// the implementation. With no fmt there is no format verb; with no os and no io
// there is no stream to write to.
func TestImportsAreAllowlisted(t *testing.T) {
	_, files := packageSources(t)
	for _, f := range files {
		if f.test {
			continue
		}
		t.Run(f.name, func(t *testing.T) {
			for _, path := range importPaths(f.ast) {
				if !allowedImports[path] {
					t.Errorf("imports %q, which is not in the allowlist %v", path, sortedKeys(allowedImports))
				}
			}
		})
	}
}

// TestNoSelfRenderingMethods: no type declared here renders itself.
func TestNoSelfRenderingMethods(t *testing.T) {
	fset, files := packageSources(t)
	for _, f := range files {
		t.Run(f.name, func(t *testing.T) {
			for _, v := range checkMethods(fset, f.ast) {
				t.Error(v)
			}
		})
	}
}

// TestNoErrorConstruction: the implementation returns no errors, so there is no
// value it could hand a caller that might carry an address into that caller's
// error log.
func TestNoErrorConstruction(t *testing.T) {
	fset, files := packageSources(t)
	for _, f := range files {
		if f.test {
			continue
		}
		t.Run(f.name, func(t *testing.T) {
			for _, v := range checkErrorReturns(fset, f.ast) {
				t.Error(v)
			}
		})
	}
}

// TestNoRenderingOfAddresses is the format-verb check: no call that turns a
// value into text may be applied to a value holding an address or a key.
//
// It applies to the test files as much as the implementation, because a
// t.Errorf that prints the address of a failing case is exactly the disclosure
// §6.4 forbids — and it is the one a person under time pressure writes without
// thinking. Report the case name instead.
//
// The analysis is syntactic and errs towards over-flagging: a name bound
// anywhere in a file to an address, a key, a container of either, or the result
// of a netip constructor taints that name for the whole file. Over-flagging is
// the right direction of error here; the remedy is always to print something
// else.
func TestNoRenderingOfAddresses(t *testing.T) {
	fset, files := packageSources(t)
	tainted := taintedTypes(files)
	for _, f := range files {
		t.Run(f.name, func(t *testing.T) {
			for _, v := range checkRendering(fset, f.ast, tainted) {
				t.Error(v)
			}
		})
	}
}

// TestLicenceHeaders: every file carries the SPDX notice, so that the terms
// travel if a file is copied out of the repository (§12).
func TestLicenceHeaders(t *testing.T) {
	_, files := packageSources(t)
	for _, f := range files {
		t.Run(f.name, func(t *testing.T) {
			b, err := os.ReadFile(f.name)
			if err != nil {
				t.Fatalf("reading the file: %v", err)
			}
			want := "// SPDX-License-Identifier: AGPL-3.0-or-later\n// Copyright (C) 2026 Simon Wright\n"
			if !strings.HasPrefix(string(b), want) {
				t.Errorf("does not begin with the SPDX header")
			}
		})
	}
}

// --- checkers -------------------------------------------------------------

func importPaths(f *ast.File) []string {
	var out []string
	for _, spec := range f.Imports {
		path, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			continue
		}
		out = append(out, path)
	}
	return out
}

func checkMethods(fset *token.FileSet, f *ast.File) []string {
	var out []string
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv == nil || len(fn.Recv.List) == 0 {
			continue
		}
		if forbiddenMethods[fn.Name.Name] {
			out = append(out, fmt.Sprintf("%s: method %s on %s renders or serialises the receiver; no type in this package may",
				pos(fset, fn.Pos()), fn.Name.Name, receiverName(fn)))
		}
	}
	return out
}

func checkErrorReturns(fset *token.FileSet, f *ast.File) []string {
	var out []string
	ast.Inspect(f, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Type.Results == nil {
			return true
		}
		for _, res := range fn.Type.Results.List {
			if id, ok := res.Type.(*ast.Ident); ok && id.Name == "error" {
				out = append(out, fmt.Sprintf("%s: %s returns an error; this package answers with a bool so that nothing it produces can carry an address",
					pos(fset, fn.Pos()), fn.Name.Name))
			}
		}
		return true
	})
	return out
}

// taintedTypes returns the names of package types that fmt would traverse into
// address material.
//
// The traversal rule mirrors fmt's own: a pointer field is not followed, which
// is precisely why the limiter holds its keys behind one. A type is tainted if
// it reaches a netip address type or an already-tainted type without passing
// through a pointer.
func taintedTypes(files []sourceFile) map[string]bool {
	tainted := map[string]bool{}
	for _, name := range seedTaintedTypes {
		tainted[name] = true
	}

	var specs []*ast.TypeSpec
	for _, f := range files {
		for _, decl := range f.ast.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.TYPE {
				continue
			}
			for _, s := range gen.Specs {
				if ts, ok := s.(*ast.TypeSpec); ok {
					specs = append(specs, ts)
				}
			}
		}
	}

	for changed := true; changed; {
		changed = false
		for _, ts := range specs {
			if tainted[ts.Name.Name] {
				continue
			}
			if reachesAddress(ts.Type, tainted) {
				tainted[ts.Name.Name] = true
				changed = true
			}
		}
	}
	return tainted
}

// reachesAddress reports whether fmt, printing a value of this type expression,
// would reach address material. Pointers stop the walk.
func reachesAddress(e ast.Expr, tainted map[string]bool) bool {
	found := false
	var walk func(ast.Expr)
	walk = func(e ast.Expr) {
		if e == nil || found {
			return
		}
		switch x := e.(type) {
		case *ast.StarExpr:
			return // fmt does not follow a nested pointer
		case *ast.Ident:
			if tainted[x.Name] {
				found = true
			}
		case *ast.SelectorExpr:
			if pkg, ok := x.X.(*ast.Ident); ok && pkg.Name == "netip" && netipAddressTypes[x.Sel.Name] {
				found = true
			}
		case *ast.ArrayType:
			walk(x.Elt)
		case *ast.MapType:
			walk(x.Key)
			walk(x.Value)
		case *ast.ChanType:
			walk(x.Value)
		case *ast.StructType:
			if x.Fields != nil {
				for _, fld := range x.Fields.List {
					walk(fld.Type)
				}
			}
		case *ast.ParenExpr:
			walk(x.X)
		}
	}
	walk(e)
	return found
}

// taintedForValue is reachesAddress with one top-level pointer unwrapped, since
// fmt does dereference the argument it is handed.
func taintedForValue(e ast.Expr, tainted map[string]bool) bool {
	for {
		switch x := e.(type) {
		case *ast.ParenExpr:
			e = x.X
			continue
		case *ast.StarExpr:
			e = x.X
			continue
		}
		break
	}
	return reachesAddress(e, tainted)
}

// checkRendering finds rendering calls applied to tainted values.
func checkRendering(fset *token.FileSet, f *ast.File, tainted map[string]bool) []string {
	names := taintedNames(f, tainted)

	var out []string
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || !isRenderingCall(call) {
			return true
		}
		// The receiver counts as much as the arguments: a.String() renders an
		// address without passing one to anything.
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
			if name, ok := mentionsTainted(sel.X, names); ok {
				out = append(out, fmt.Sprintf("%s: %s renders itself through %s; no address or key may reach text",
					pos(fset, sel.Pos()), name, sel.Sel.Name))
			}
		}
		for _, arg := range call.Args {
			if name, ok := mentionsTainted(arg, names); ok {
				out = append(out, fmt.Sprintf("%s: a rendering call is applied to %s, which holds address or key material; report the case name instead",
					pos(fset, arg.Pos()), name))
			}
		}
		return true
	})
	return out
}

func isRenderingCall(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "fmt" {
		return true
	}
	return renderingFuncs[sel.Sel.Name]
}

// taintedNames collects, for one file, every identifier bound to address or key
// material. The analysis is per file rather than per scope: a name that means an
// address anywhere in a file is treated as meaning one everywhere in it.
func taintedNames(f *ast.File, tainted map[string]bool) map[string]bool {
	names := map[string]bool{}

	// Functions whose results carry address material, so that calls to them can
	// be recognised. Two passes, since a helper may be declared after its use.
	funcs := map[string]bool{}
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Type.Results == nil {
			continue
		}
		for _, res := range fn.Type.Results.List {
			if taintedForValue(res.Type, tainted) {
				funcs[fn.Name.Name] = true
			}
		}
	}

	// A function whose result carries address material makes its own name
	// address material: fmt.Sprintf("%v", addr(t, s)) discloses just as much as
	// fmt.Sprintf("%v", a).
	for name := range funcs {
		names[name] = true
	}

	var produces func(ast.Expr) bool
	produces = func(e ast.Expr) bool {
		switch x := e.(type) {
		case *ast.CallExpr:
			switch fn := x.Fun.(type) {
			case *ast.Ident:
				return funcs[fn.Name] || tainted[fn.Name] // call or conversion
			case *ast.SelectorExpr:
				if pkg, ok := fn.X.(*ast.Ident); ok && pkg.Name == "netip" {
					return netipConstructors[fn.Sel.Name] || netipAddressTypes[fn.Sel.Name]
				}
			}
		case *ast.CompositeLit:
			return x.Type != nil && taintedForValue(x.Type, tainted)
		case *ast.UnaryExpr:
			return produces(x.X)
		case *ast.ParenExpr:
			return produces(x.X)
		}
		return false
	}

	add := func(e ast.Expr) {
		if id, ok := e.(*ast.Ident); ok && id.Name != "_" {
			names[id.Name] = true
		}
	}

	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.Field: // parameters, results, receivers and struct fields
			if taintedForValue(x.Type, tainted) {
				for _, id := range x.Names {
					names[id.Name] = true
				}
			}
		case *ast.ValueSpec:
			if x.Type != nil && taintedForValue(x.Type, tainted) {
				for _, id := range x.Names {
					names[id.Name] = true
				}
			}
			for i, v := range x.Values {
				if produces(v) && i < len(x.Names) {
					names[x.Names[i].Name] = true
				}
			}
		case *ast.AssignStmt:
			// A single call on the right taints every name on the left: an
			// error returned by netip.ParseAddr contains the text it failed to
			// parse, so err is address material too.
			if len(x.Rhs) == 1 && produces(x.Rhs[0]) {
				for _, lhs := range x.Lhs {
					add(lhs)
				}
			} else {
				for i, rhs := range x.Rhs {
					if produces(rhs) && i < len(x.Lhs) {
						add(x.Lhs[i])
					}
				}
			}
		case *ast.RangeStmt:
			if produces(x.X) || mentionsAny(x.X, names) {
				add(x.Key)
				add(x.Value)
			}
		}
		return true
	})
	return names
}

// mentionsTainted reports whether an expression mentions a tainted name,
// including as the base of a selector: a field of a key is the network bits
// themselves.
func mentionsTainted(e ast.Expr, names map[string]bool) (string, bool) {
	var found string
	ast.Inspect(e, func(n ast.Node) bool {
		if found != "" {
			return false
		}
		if id, ok := n.(*ast.Ident); ok && names[id.Name] {
			found = id.Name
		}
		return true
	})
	return found, found != ""
}

func mentionsAny(e ast.Expr, names map[string]bool) bool {
	_, ok := mentionsTainted(e, names)
	return ok
}

func receiverName(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return "?"
	}
	switch t := fn.Recv.List[0].Type.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		if id, ok := t.X.(*ast.Ident); ok {
			return id.Name
		}
	}
	return "?"
}

func pos(fset *token.FileSet, p token.Pos) string {
	return fset.Position(p).String()
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// --- self-test of the checkers --------------------------------------------

// TestCheckersDetectViolations runs each checker against a source that violates
// it, and against one that does not.
//
// Without this, a checker that silently stopped matching would report a clean
// package for ever after, which is the failure mode that makes source-scanning
// tests worthless.
func TestCheckersDetectViolations(t *testing.T) {
	tests := []struct {
		name    string
		src     string
		check   func(t *testing.T, fset *token.FileSet, f *ast.File) int
		wantBad bool
	}{
		{
			name: "log import is caught",
			src: `package p
import "log"
func f() { _ = log.Println }`,
			check:   countForbiddenImports,
			wantBad: true,
		},
		{
			name: "log/slog import is caught",
			src: `package p
import "log/slog"
var _ = slog.Default`,
			check:   countForbiddenImports,
			wantBad: true,
		},
		{
			name: "an allowed import is not flagged",
			src: `package p
import "time"
var _ = time.Hour`,
			check:   countForbiddenImports,
			wantBad: false,
		},
		{
			name: "fmt in the implementation is caught by the allowlist",
			src: `package p
import "fmt"
var _ = fmt.Sprintf`,
			check:   countDisallowedImports,
			wantBad: true,
		},
		{
			name: "the allowlist passes netip, sync and time",
			src: `package p
import (
	"net/netip"
	"sync"
	"time"
)
var _ = netip.Addr{}
var _ sync.Mutex
var _ = time.Hour`,
			check:   countDisallowedImports,
			wantBad: false,
		},
		{
			name: "a String method on the key type is caught",
			src: `package p
type key struct{ net [16]byte }
func (k key) String() string { return "" }`,
			check:   countMethods,
			wantBad: true,
		},
		{
			name: "an Error method is caught",
			src: `package p
type e struct{}
func (e) Error() string { return "" }`,
			check:   countMethods,
			wantBad: true,
		},
		{
			name: "an ordinary method is not flagged",
			src: `package p
type key struct{ net [16]byte }
func (k key) valid() bool { return true }`,
			check:   countMethods,
			wantBad: false,
		},
		{
			name: "an error return is caught",
			src: `package p
func f() error { return nil }`,
			check:   countErrorReturns,
			wantBad: true,
		},
		{
			name: "a bool return is not flagged",
			src: `package p
func f() bool { return true }`,
			check:   countErrorReturns,
			wantBad: false,
		},
		{
			name: "formatting a parsed address is caught",
			src: `package p
import (
	"fmt"
	"net/netip"
)
func f(s string) {
	a := netip.MustParseAddr(s)
	fmt.Sprintf("%v", a)
}`,
			check:   countRendering,
			wantBad: true,
		},
		{
			name: "formatting an address parameter is caught",
			src: `package p
import (
	"fmt"
	"net/netip"
)
func f(addr netip.Addr) { fmt.Println(addr) }`,
			check:   countRendering,
			wantBad: true,
		},
		{
			name: "formatting a key is caught",
			src: `package p
import "fmt"
type key struct{ net [16]byte }
func f(k key) { fmt.Printf("%v", k) }`,
			check:   countRendering,
			wantBad: true,
		},
		{
			name: "formatting a field of a key is caught",
			src: `package p
import "fmt"
type key struct{ net [16]byte }
func f(k key) { fmt.Printf("%v", k.net) }`,
			check:   countRendering,
			wantBad: true,
		},
		{
			name: "a t.Errorf naming an address is caught",
			src: `package p
import (
	"net/netip"
	"testing"
)
func f(t *testing.T, a netip.Addr) { t.Errorf("refused %v", a) }`,
			check:   countRendering,
			wantBad: true,
		},
		{
			name: "the String method of an address is caught",
			src: `package p
import (
	"net/netip"
	"testing"
)
func f(t *testing.T, a netip.Addr) { t.Log(a.String()) }`,
			check:   countRendering,
			wantBad: true,
		},
		{
			name: "an address error is caught, because it carries the input",
			src: `package p
import (
	"net/netip"
	"testing"
)
func f(t *testing.T, s string) {
	a, err := netip.ParseAddr(s)
	_ = a
	t.Fatalf("%v", err)
}`,
			check:   countRendering,
			wantBad: true,
		},
		{
			name: "an address ranged over is caught",
			src: `package p
import (
	"net/netip"
	"testing"
)
func f(t *testing.T) {
	for _, a := range []netip.Addr{} {
		t.Logf("%v", a)
	}
}`,
			check:   countRendering,
			wantBad: true,
		},
		{
			name: "reporting a case name is not flagged",
			src: `package p
import (
	"net/netip"
	"testing"
)
func f(t *testing.T, name string, a netip.Addr) {
	_ = a
	t.Errorf("case %s refused, want allowed", name)
}`,
			check:   countRendering,
			wantBad: false,
		},
		{
			name: "counting without naming is not flagged",
			src: `package p
import (
	"net/netip"
	"testing"
)
func f(t *testing.T, a netip.Addr, n int) {
	_ = a
	t.Errorf("admitted %d, want 0", n)
}`,
			check:   countRendering,
			wantBad: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, "bad.go", tt.src, parser.ParseComments)
			if err != nil {
				t.Fatalf("parsing the fixture: %v", err)
			}
			n := tt.check(t, fset, f)
			if tt.wantBad && n == 0 {
				t.Errorf("the checker found nothing, want at least one violation")
			}
			if !tt.wantBad && n != 0 {
				t.Errorf("the checker found %d violations, want none", n)
			}
		})
	}
}

func countForbiddenImports(t *testing.T, fset *token.FileSet, f *ast.File) int {
	t.Helper()
	n := 0
	for _, path := range importPaths(f) {
		if forbiddenImports[path] || strings.HasPrefix(path, "log/") {
			n++
		}
	}
	return n
}

func countDisallowedImports(t *testing.T, fset *token.FileSet, f *ast.File) int {
	t.Helper()
	n := 0
	for _, path := range importPaths(f) {
		if !allowedImports[path] {
			n++
		}
	}
	return n
}

func countMethods(t *testing.T, fset *token.FileSet, f *ast.File) int {
	t.Helper()
	return len(checkMethods(fset, f))
}

func countErrorReturns(t *testing.T, fset *token.FileSet, f *ast.File) int {
	t.Helper()
	return len(checkErrorReturns(fset, f))
}

func countRendering(t *testing.T, fset *token.FileSet, f *ast.File) int {
	t.Helper()
	tainted := taintedTypes([]sourceFile{{name: "bad.go", ast: f}})
	return len(checkRendering(fset, f, tainted))
}
