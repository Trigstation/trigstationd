// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Simon Wright

package clientaddr

// This file tests the package's source rather than its behaviour, in the same
// way internal/ratelimit/source_test.go does and for the same reason.
//
// DIRECTORY-SPEC.md §6.4 requires that no code path exists which emits a client
// address — a property of what is written, not of what happens to run. A
// behavioural test cannot establish it, because the disclosure that matters is
// the one somebody adds in six months while chasing an unrelated bug. The bar is
// higher here than in internal/ratelimit: that package sees an address only long
// enough to discard its host bits, whereas this one handles the untruncated
// address and the header text it arrived in, which is the most disclosable form
// there is.
//
// So the checks below parse every .go file in the package and fail on the
// constructs that would make disclosure possible:
//
//   - an import of log or log/slog, anywhere;
//   - any import at all outside a three-package allowlist in the implementation
//     files, which is what keeps fmt — and with it every format verb — out of
//     reach;
//   - a String, Error or Marshal method on any type declared here;
//   - a rendering call applied to a value that holds address material, header
//     text included;
//   - an error return from any function but ParsePrefixes, and error text that is
//     anything other than a literal;
//   - an Addr method that answers with anything but a single netip.Addr.
//
// The checkers are self-tested against deliberately bad and good sources at the
// bottom of the file, so that a checker which has stopped detecting anything
// fails rather than passing quietly.

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
//
// net/http is absent by design as well as by omission: this package takes a peer
// address and a header string, so the trust decision can be tested without a
// server and cannot drift into middleware.
//
// errors buys exactly two package-level sentinels for ParsePrefixes. errors.New
// with a literal cannot carry input, and TestErrorTextIsLiteral holds that.
var allowedImports = map[string]bool{
	"errors":    true,
	"net/netip": true,
	"strings":   true,
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
// String method on some future enum would be harmless, but "harmless" is a
// judgement that has to be made again at every review, whereas "this package
// declares no such method" is checkable.
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

// seedTaintedNames are identifiers that hold address material in a form no type
// checker can see.
//
// The header value is the case this package adds over internal/ratelimit: xff is
// a plain string, and a plain string holding "203.0.113.9" renders itself
// without any help. The names below are the ones this package binds it to, plus
// got, which is what a test binds a resolved address to.
//
// A name added here taints it for the whole package, tests included. Choose
// names that mean address material everywhere, and rename rather than widen.
var seedTaintedNames = map[string]bool{
	"xff":       true,
	"forwarded": true,
	"entry":     true,
	"rightmost": true,
	"got":       true,
}

// seedTaintedTypes names types that hold address material by construction rather
// than by mentioning a netip type. There are none at present — Extractor holds
// its prefixes in a plain slice field, so the walk below finds it unaided — but
// the mechanism stays, because the moment a truncated address is stored in a
// [16]byte here the way internal/ratelimit stores one, this is where it is
// declared.
var seedTaintedTypes []string

// errorReturnAllowed names the functions permitted to return an error.
//
// Everything else answers with a value or a bool. An error is a string that
// travels, and the string this package would most naturally put in one is the
// header it could not parse. Addr in particular must not gain an error return;
// its every failure resolves to "use the peer".
//
// ParsePrefixes is the single exception, and it is in the contract rather than a
// convenience: an operator's -trusted-proxies flag has to be able to fail at
// startup. It returns fixed sentinels that name nothing, which
// TestErrorTextIsLiteral holds.
var errorReturnAllowed = map[string]bool{
	"ParsePrefixes": true,
}

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

// TestImportsAreAllowlisted keeps every rendering and output facility out of the
// implementation. With no fmt there is no format verb; with no os and no io
// there is no stream to write to; with no net/http there is no request to be
// tempted into inspecting.
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

// TestNoHTTPImport states separately what the allowlist already implies, because
// net/http is the import somebody would reach for when wiring this into a
// handler, and a failure naming it is more use than one naming the allowlist.
func TestNoHTTPImport(t *testing.T) {
	_, files := packageSources(t)
	for _, f := range files {
		t.Run(f.name, func(t *testing.T) {
			for _, path := range importPaths(f.ast) {
				if path == "net/http" || strings.HasPrefix(path, "net/http/") {
					t.Errorf("imports %q: this package takes a peer address and a header string, so that the trust decision stays out of middleware and testable without a server", path)
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

// TestNoErrorConstruction: the implementation returns errors from ParsePrefixes
// and nowhere else, so there is no value it could hand a caller that might carry
// an address into that caller's error log.
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

// TestErrorTextIsLiteral: every error this package constructs says a fixed
// thing. An errors.New over a variable would be a way for the input to travel
// out through the one path that is allowed to return an error at all.
func TestErrorTextIsLiteral(t *testing.T) {
	fset, files := packageSources(t)
	for _, f := range files {
		t.Run(f.name, func(t *testing.T) {
			for _, v := range checkErrorText(fset, f.ast) {
				t.Error(v)
			}
		})
	}
}

// TestAddrSignature pins the contract of Addr: one result, a netip.Addr, and no
// error. Two other packages are written against this signature, and the absence
// of the error result is a §6.4 property rather than a matter of taste.
func TestAddrSignature(t *testing.T) {
	fset, files := packageSources(t)
	found := 0
	for _, f := range files {
		if f.test {
			continue
		}
		n, violations := checkAddrSignature(fset, f.ast)
		found += n
		for _, v := range violations {
			t.Error(v)
		}
	}
	if found != 1 {
		t.Errorf("found %d declarations of the Addr method, want exactly 1", found)
	}
}

// TestNoRenderingOfAddresses is the format-verb check: no call that turns a
// value into text may be applied to a value holding an address, a prefix or the
// forwarded header.
//
// It applies to the test files as much as the implementation, because a t.Errorf
// that prints the address of a failing case is exactly the disclosure §6.4
// forbids — and it is the one a person under time pressure writes without
// thinking. Report the case name instead.
//
// The analysis is syntactic and errs towards over-flagging: a name bound
// anywhere in a file to an address, a prefix, a container of either, the result
// of a netip constructor, or one of the seeded names, taints that name for the
// whole file. Over-flagging is the right direction of error here; the remedy is
// always to print something else.
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
		if errorReturnAllowed[fn.Name.Name] {
			return true
		}
		for _, res := range fn.Type.Results.List {
			if id, ok := res.Type.(*ast.Ident); ok && id.Name == "error" {
				out = append(out, fmt.Sprintf("%s: %s returns an error; only the functions in errorReturnAllowed may, so that nothing this package produces can carry a header value or an address",
					pos(fset, fn.Pos()), fn.Name.Name))
			}
		}
		return true
	})
	return out
}

// checkErrorText requires the argument of every errors.New to be a literal.
func checkErrorText(fset *token.FileSet, f *ast.File) []string {
	var out []string
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok || pkg.Name != "errors" || sel.Sel.Name != "New" {
			return true
		}
		for _, arg := range call.Args {
			if lit, ok := arg.(*ast.BasicLit); !ok || lit.Kind != token.STRING {
				out = append(out, fmt.Sprintf("%s: errors.New over something other than a string literal; an error built from input is a way for the input to travel",
					pos(fset, arg.Pos())))
			}
		}
		return true
	})
	return out
}

// checkAddrSignature reports how many Addr methods a file declares, and how each
// departs from "one result, a netip.Addr".
func checkAddrSignature(fset *token.FileSet, f *ast.File) (int, []string) {
	found := 0
	var out []string
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv == nil || fn.Name.Name != "Addr" {
			continue
		}
		found++

		n := 0
		if fn.Type.Results != nil {
			for _, res := range fn.Type.Results.List {
				if len(res.Names) == 0 {
					n++
				} else {
					n += len(res.Names)
				}
				if id, ok := res.Type.(*ast.Ident); ok && id.Name == "error" {
					out = append(out, fmt.Sprintf("%s: Addr returns an error; every failure here must resolve to \"use the peer\", because an error is a string that travels and the string it would carry is the header",
						pos(fset, res.Pos())))
				}
			}
		}
		if n != 1 {
			out = append(out, fmt.Sprintf("%s: Addr has %d results, want exactly 1", pos(fset, fn.Pos()), n))
			continue
		}
		res := fn.Type.Results.List[0].Type
		if !isNetipAddr(res) {
			out = append(out, fmt.Sprintf("%s: Addr does not return a netip.Addr", pos(fset, res.Pos())))
		}
	}
	return found, out
}

// isNetipAddr reports whether a type expression is exactly netip.Addr. Anything
// else as the result of Addr — a string, a bool, a named wrapper — is a
// departure from the contract two other packages are written against.
func isNetipAddr(e ast.Expr) bool {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "netip" && sel.Sel.Name == "Addr"
}

// taintedTypes returns the names of package types that fmt would traverse into
// address material.
//
// The traversal rule mirrors fmt's own: a pointer field is not followed. A type
// is tainted if it reaches a netip address type or an already-tainted type
// without passing through a pointer.
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
				out = append(out, fmt.Sprintf("%s: %s renders itself through %s; no address, prefix or header value may reach text",
					pos(fset, sel.Pos()), name, sel.Sel.Name))
			}
		}
		for _, arg := range call.Args {
			if name, ok := mentionsTainted(arg, names); ok {
				out = append(out, fmt.Sprintf("%s: a rendering call is applied to %s, which holds address material; report the case name instead",
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

// taintedNames collects, for one file, every identifier bound to address
// material. The analysis is per file rather than per scope: a name that means an
// address anywhere in a file is treated as meaning one everywhere in it.
func taintedNames(f *ast.File, tainted map[string]bool) map[string]bool {
	names := map[string]bool{}
	for name := range seedTaintedNames {
		names[name] = true
	}

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
// including as the base or the selector of a field access: a field of a tainted
// struct is the address itself.
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

// TestSeedsAreNotEmpty: a seed set that emptied out would quietly weaken every
// check built on it.
func TestSeedsAreNotEmpty(t *testing.T) {
	if len(seedTaintedNames) == 0 {
		t.Errorf("seedTaintedNames is empty, so the forwarded header is no longer treated as address material")
	}
	if len(allowedImports) == 0 {
		t.Errorf("allowedImports is empty, so the allowlist admits nothing and can never have flagged anything")
	}
	if len(forbiddenMethods) == 0 || len(renderingFuncs) == 0 || len(forbiddenImports) == 0 {
		t.Errorf("a checker's rule set is empty, so it cannot detect anything")
	}
}

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
import "strings"
var _ = strings.TrimSpace`,
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
			name: "net/http in the implementation is caught by the allowlist",
			src: `package p
import "net/http"
var _ http.Handler`,
			check:   countDisallowedImports,
			wantBad: true,
		},
		{
			name: "the allowlist passes errors, netip and strings",
			src: `package p
import (
	"errors"
	"net/netip"
	"strings"
)
var _ = errors.New
var _ = netip.Addr{}
var _ = strings.TrimSpace`,
			check:   countDisallowedImports,
			wantBad: false,
		},
		{
			name: "net/http is caught by the dedicated check",
			src: `package p
import "net/http"
func f(r *http.Request) { _ = r }`,
			check:   countHTTPImports,
			wantBad: true,
		},
		{
			name: "net/netip is not an HTTP import",
			src: `package p
import "net/netip"
var _ = netip.Addr{}`,
			check:   countHTTPImports,
			wantBad: false,
		},
		{
			name: "a String method on the Extractor is caught",
			src: `package p
type Extractor struct{}
func (e Extractor) String() string { return "" }`,
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
import "net/netip"
type Extractor struct{ trusted []netip.Prefix }
func (e *Extractor) trusts(a netip.Addr) bool { return false }`,
			check:   countMethods,
			wantBad: false,
		},
		{
			name: "an error return from an ordinary function is caught",
			src: `package p
func f() error { return nil }`,
			check:   countErrorReturns,
			wantBad: true,
		},
		{
			name: "an error return from Addr is caught",
			src: `package p
import "net/netip"
func (e *Extractor) Addr(peer netip.Addr, xff string) (netip.Addr, error) { return peer, nil }`,
			check:   countErrorReturns,
			wantBad: true,
		},
		{
			name: "the error return from ParsePrefixes is allowed",
			src: `package p
import "net/netip"
func ParsePrefixes(s string) ([]netip.Prefix, error) { return nil, nil }`,
			check:   countErrorReturns,
			wantBad: false,
		},
		{
			name: "a bool return is not flagged",
			src: `package p
func f() bool { return true }`,
			check:   countErrorReturns,
			wantBad: false,
		},
		{
			name: "errors.New over a variable is caught",
			src: `package p
import "errors"
func f(s string) error { return errors.New(s) }`,
			check:   countErrorText,
			wantBad: true,
		},
		{
			name: "errors.New over a concatenation is caught",
			src: `package p
import "errors"
func f(s string) error { return errors.New("bad entry: " + s) }`,
			check:   countErrorText,
			wantBad: true,
		},
		{
			name: "errors.New over a literal is not flagged",
			src: `package p
import "errors"
var ErrInvalidProxy = errors.New("trusted proxies: an entry is not valid")`,
			check:   countErrorText,
			wantBad: false,
		},
		{
			name: "an Addr returning an error is caught by the signature check",
			src: `package p
import "net/netip"
type Extractor struct{}
func (e *Extractor) Addr(peer netip.Addr, xff string) (netip.Addr, error) { return peer, nil }`,
			check:   countAddrSignature,
			wantBad: true,
		},
		{
			name: "an Addr returning a string is caught by the signature check",
			src: `package p
import "net/netip"
type Extractor struct{}
func (e *Extractor) Addr(peer netip.Addr, xff string) string { return "" }`,
			check:   countAddrSignature,
			wantBad: true,
		},
		{
			name: "the contracted Addr signature is not flagged",
			src: `package p
import "net/netip"
type Extractor struct{}
func (e *Extractor) Addr(peer netip.Addr, xff string) netip.Addr { return peer }`,
			check:   countAddrSignature,
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
func f(peer netip.Addr) { fmt.Println(peer) }`,
			check:   countRendering,
			wantBad: true,
		},
		{
			name: "formatting a prefix is caught",
			src: `package p
import (
	"fmt"
	"net/netip"
)
func f(p netip.Prefix) { fmt.Printf("%v", p) }`,
			check:   countRendering,
			wantBad: true,
		},
		{
			name: "formatting the Extractor is caught, because it holds prefixes",
			src: `package p
import (
	"fmt"
	"net/netip"
)
type Extractor struct{ trusted []netip.Prefix }
func f(e Extractor) { fmt.Printf("%v", e) }`,
			check:   countRendering,
			wantBad: true,
		},
		{
			name: "formatting the forwarded header string is caught",
			src: `package p
import "fmt"
func f(xff string) { fmt.Println(xff) }`,
			check:   countRendering,
			wantBad: true,
		},
		{
			name: "formatting a single header entry is caught",
			src: `package p
import "fmt"
func f(entry string) { fmt.Println(entry) }`,
			check:   countRendering,
			wantBad: true,
		},
		{
			name: "formatting a header field of a table case is caught",
			src: `package p
import "testing"
func f(t *testing.T, tt struct{ xff string }) { t.Errorf("header %s", tt.xff) }`,
			check:   countRendering,
			wantBad: true,
		},
		{
			name: "a t.Errorf naming a resolved address is caught",
			src: `package p
import (
	"net/netip"
	"testing"
)
func f(t *testing.T, got netip.Addr) { t.Errorf("resolved %v", got) }`,
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
func f(t *testing.T, peer netip.Addr) { t.Log(peer.String()) }`,
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
			name: "a prefix ranged over is caught",
			src: `package p
import (
	"net/netip"
	"testing"
)
func f(t *testing.T, trusted []netip.Prefix) {
	for _, p := range trusted {
		t.Logf("%v", p)
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
func f(t *testing.T, name string, peer netip.Addr) {
	_ = peer
	t.Errorf("case %s resolved wrongly", name)
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
func f(t *testing.T, trusted []netip.Prefix, n int) {
	_ = trusted
	t.Errorf("parsed %d prefixes, want 0", n)
}`,
			check:   countRendering,
			wantBad: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, "fixture.go", tt.src, parser.ParseComments)
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

func countHTTPImports(t *testing.T, fset *token.FileSet, f *ast.File) int {
	t.Helper()
	n := 0
	for _, path := range importPaths(f) {
		if path == "net/http" || strings.HasPrefix(path, "net/http/") {
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

func countErrorText(t *testing.T, fset *token.FileSet, f *ast.File) int {
	t.Helper()
	return len(checkErrorText(fset, f))
}

func countAddrSignature(t *testing.T, fset *token.FileSet, f *ast.File) int {
	t.Helper()
	found, violations := checkAddrSignature(fset, f)
	if found == 0 {
		t.Fatalf("the fixture declares no Addr method, so the checker had nothing to examine")
	}
	return len(violations)
}

func countRendering(t *testing.T, fset *token.FileSet, f *ast.File) int {
	t.Helper()
	tainted := taintedTypes([]sourceFile{{name: "fixture.go", ast: f}})
	return len(checkRendering(fset, f, tainted))
}
