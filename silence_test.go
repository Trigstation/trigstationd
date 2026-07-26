// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Simon Wright

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/trigstation/trigstationd/internal/b64"
	"github.com/trigstation/trigstationd/internal/derive"
	"github.com/trigstation/trigstationd/internal/pow"
	"github.com/trigstation/trigstationd/internal/record"
)

// TestTheServerSaysNothingAboutRequests builds the real binary, drives traffic
// through it, and asserts that everything it wrote to stdout and stderr is the
// startup banner and nothing else.
//
// # Why this exists as a test rather than as an observation
//
// The no-logging rule is enforced in three other ways already: CI rejects an
// import of log or log/slog anywhere in the tree, several packages parse their
// own source for rendering calls applied to identifier-bearing values, and
// internal/api permits exactly one function to touch a process output stream.
// All three are properties of the source.
//
// This one is a property of the running program, which is the only form of the
// claim an operator actually cares about. It would catch what the others cannot:
// a dependency that logs, the Go runtime reporting something request-shaped, a
// panic path that escapes the recovery in ServeHTTP, or output from a package
// that has no source check of its own. Those are exactly the routes by which
// this invariant would be lost quietly.
//
// It deliberately drives *rejections* as well as successes. A directory that
// stays silent when everything works and describes the failure when something
// does not is the common shape of this bug, and it is the shape that matters:
// the requests worth logging are the ones worth not logging.
func TestTheServerSaysNothingAboutRequests(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs the binary")
	}

	bin := buildBinary(t)
	dir := t.TempDir()
	port := freePort(t)
	addr := "127.0.0.1:" + strconv.Itoa(port)

	// A low difficulty keeps the test fast. The pipeline is identical.
	const powBits = 8

	cmd := exec.Command(bin,
		"-listen", addr,
		"-db", filepath.Join(dir, "records.db"),
		"-pow-bits", strconv.Itoa(powBits),
	)
	// exec.Cmd spawns a goroutine to copy each stream when Stdout is an
	// io.Writer rather than an *os.File, so the buffer must not be read while
	// the process is alive. Stopping the process and waiting for it joins those
	// goroutines, which is both race-free and the only way to be sure every byte
	// the server wrote has been captured.
	//
	// The first version of this test read the buffer with the process still
	// running. It passed locally and every time; the race detector caught it on
	// CI's first run, which is why the -race job exists.
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting the binary: %v", err)
	}

	stopped := false
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		_ = cmd.Process.Kill()
		// cmd.Wait, not cmd.Process.Wait. They are not interchangeable here:
		// os.Process.Wait reaps the process and returns, while exec.Cmd.Wait
		// additionally waits for the stream-copying goroutines to finish. Only
		// the latter makes the buffer safe to read, and using the former is why
		// the first attempt at this fix still raced.
		_ = cmd.Wait()
	}
	defer stop()

	waitForListener(t, addr)
	base := "http://" + addr

	// Traffic with something distinctive in every position an implementation
	// might be tempted to report: the path, the query, and the body.
	const marker = "cafebabecafebabe"

	drive(t, http.MethodGet, base+"/v1/meta", nil)
	drive(t, http.MethodGet, base+"/v1/record?prefix="+marker+"&bits=12", nil)
	drive(t, http.MethodGet, base+"/v1/record?bits=00", nil)               // 400
	drive(t, http.MethodGet, base+"/v1/record?bits=1&bits=2", nil)         // 400
	drive(t, http.MethodPut, base+"/v1/record", []byte("not json at all")) // 400
	drive(t, http.MethodPut, base+"/v1/record", []byte(`{"v":99}`))        // 400
	drive(t, http.MethodGet, base+"/v1/signal/"+marker, nil)               // 400
	drive(t, http.MethodGet, base+"/health", nil)                          // 404
	drive(t, http.MethodGet, base+"/"+marker, nil)                         // 404

	// A real publish and lookup, so the success path is covered too.
	env := signedEnvelope(t, powBits)
	drive(t, http.MethodPut, base+"/v1/record", env)
	drive(t, http.MethodGet, base+"/v1/record?bits=0", nil)

	// A replay, which is a 409 and the most "interesting" rejection there is.
	drive(t, http.MethodPut, base+"/v1/record", env)

	// Stop the server and join its output goroutines before reading a byte of
	// the buffer. Anything it was going to write about those requests has been
	// written by the time Wait returns.
	stop()
	got := out.String()

	// The startup banner is expected, and is the only expected line. It names
	// the listen address, which is the operator's own configuration rather than
	// anything about a client — the distinction matters, because the banner is
	// why the substring sweep below runs over the remainder rather than over
	// everything. An earlier version of this test swept the whole output and
	// failed on its own banner.
	banner := "trigstationd: listening on " + addr
	var unexpected []string
	sawBanner := false
	for _, line := range strings.Split(strings.TrimSpace(got), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "":
		case line == banner:
			sawBanner = true
		default:
			unexpected = append(unexpected, line)
		}
	}
	if !sawBanner {
		t.Errorf("the startup banner was not produced exactly as expected; got:\n%s", got)
	}
	if len(unexpected) > 0 {
		t.Errorf("the server wrote %d line(s) beyond the startup banner:\n%s",
			len(unexpected), strings.Join(unexpected, "\n"))
	}

	// Stated separately over the remainder, so that a future change to the
	// banner cannot smuggle a request identifier past the line check above.
	remainder := strings.Join(unexpected, "\n")
	for _, forbidden := range []string{
		marker, "/v1/record", "/v1/signal", "/health",
		"prefix=", "bits=", "lookup_id", "channel_id",
		"X-Forwarded-For", "User-Agent", "409", "404",
	} {
		if strings.Contains(remainder, forbidden) {
			t.Errorf("the server's output contains %q, which identifies a request", forbidden)
		}
	}
}

func buildBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "trigstationd")
	if os.PathSeparator == '\\' {
		bin += ".exe"
	}
	cmd := exec.Command("go", "build", "-o", bin, ".")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building the binary: %v\n%s", err, out)
	}
	return bin
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving a port: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func waitForListener(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			c.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("the server did not start listening")
}

// drive issues a request and discards everything about it. The status is not
// asserted: this test is about what the server writes, not what it answers, and
// the status tables are covered exhaustively in internal/api.
func drive(t *testing.T, method, url string, body []byte) {
	t.Helper()
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, url, r)
	if err != nil {
		t.Fatalf("building a request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("issuing a request: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
}

// signedEnvelope builds a genuine envelope that the pipeline will accept.
func signedEnvelope(t *testing.T, powBits int) []byte {
	t.Helper()

	sDir := make([]byte, derive.SDirLen)
	for i := range sDir {
		sDir[i] = byte(i + 1)
	}
	now := time.Now().Unix()
	ep := derive.Epoch(now)

	wk, err := derive.WriteKey(sDir, ep)
	if err != nil {
		t.Fatalf("derive.WriteKey: %v", err)
	}
	wkPub := wk.Public().(ed25519.PublicKey)
	lookupID := derive.LookupID(wkPub)

	rk, err := derive.RecordKey(sDir, ep)
	if err != nil {
		t.Fatalf("derive.RecordKey: %v", err)
	}
	nonce := make([]byte, record.NonceLen)
	for i := range nonce {
		nonce[i] = byte(0xa0 + i)
	}
	ct, err := record.SealWithNonce(rk, nonce, []byte(`{"v":1,"ts":1}`))
	if err != nil {
		t.Fatalf("record.SealWithNonce: %v", err)
	}

	expires := now + 3600
	p, err := pow.Solve(context.Background(), lookupID, expires, powBits)
	if err != nil {
		t.Fatalf("pow.Solve: %v", err)
	}
	sig := record.Sign(wk, record.Version, lookupID, wkPub, expires, nonce, ct)

	return []byte(fmt.Sprintf(
		`{"v":1,"lookup_id":%q,"wk_pub":%q,"expires_at":%d,"ct":%q,"nonce":%q,"pow":%q,"sig":%q}`,
		b64.Encode(lookupID), b64.Encode(wkPub), expires,
		b64.Encode(ct), b64.Encode(nonce), b64.Encode(p), b64.Encode(sig),
	))
}
