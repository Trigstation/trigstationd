// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Simon Wright

// Command trigpub publishes one record to a directory.
//
// It exists because every implementer needs to publish a record in order to
// test their own directory, and the alternative is that each writes their own
// and they diverge. It is also the only place the server side of the protocol
// is demonstrated end to end: derive the epoch keys (§3.3), build and sign the
// inner payload (§4.2), seal it, solve the proof of work (§6.1), sign the
// envelope (§4.1) and PUT it (§5.2).
//
//	go run ./cmd/trigpub \
//	    -url https://directory.example.com \
//	    -endpoint wan4:203.0.113.7:8920 \
//	    -s-dir <base64url> -ik <base64url>
//
// With no -s-dir or -ik it generates them, prints them, and publishes under
// them. That is what you want for a first-publish check against a new
// instance; it is not what you want for a real server, whose keys are
// generated once and kept (§3.1).
//
// This publishes once and exits. It is deliberately not a daemon: keepalive
// republishing and epoch rollover belong to a media server, which knows when
// its address changed and this does not.
//
// # This is a client, and the no-logging rule does not bind it
//
// DIRECTORY-SPEC.md §9.2 constrains what a *directory deployment* records about
// its clients. This program is the client. It prints its own identifiers to its
// own terminal, which is the operator reading their own key material, and it
// never sees anybody else's.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"github.com/trigstation/trigstationd/internal/b64"
	"github.com/trigstation/trigstationd/internal/derive"
	"github.com/trigstation/trigstationd/internal/pow"
	"github.com/trigstation/trigstationd/internal/record"
)

// httpTimeout bounds the whole PUT. The proof of work is solved before the
// request is made, so nothing slow happens inside it.
const httpTimeout = 30 * time.Second

func main() {
	if err := run(os.Args[0], os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "trigpub:", err)
		os.Exit(1)
	}
}

type config struct {
	url       string
	sDir      string
	ik        string
	endpoints endpointList
	ttl       int64
	powBits   int
	tlsMode   string
	caps      string
	out       string
	epochOff  int64
}

// endpointList collects repeated -endpoint flags, preserving order. §4.2 makes
// endpoints an ordered sequence rather than a set, and the signature is over
// the serialised bytes, so the order the operator gave is the order published.
type endpointList []record.Endpoint

func (l *endpointList) String() string { return fmt.Sprint(*l) }

func (l *endpointList) Set(v string) error {
	// type:host:port, where host may itself contain colons if bracketed.
	t, rest, ok := strings.Cut(v, ":")
	if !ok {
		return errors.New("want type:host:port")
	}
	i := strings.LastIndexByte(rest, ':')
	if i < 0 {
		return errors.New("want type:host:port")
	}
	host, portStr := rest[:i], rest[i+1:]
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return errors.New("port must be 1-65535")
	}
	switch t {
	case record.EndpointLAN, record.EndpointWAN4, record.EndpointWAN6, record.EndpointDNS:
	default:
		return fmt.Errorf("type must be one of %s, %s, %s, %s",
			record.EndpointLAN, record.EndpointWAN4, record.EndpointWAN6, record.EndpointDNS)
	}
	*l = append(*l, record.Endpoint{Type: t, Host: strings.Trim(host, "[]"), Port: port})
	return nil
}

func parseFlags(program string, args []string) (*config, error) {
	fs := flag.NewFlagSet(program, flag.ContinueOnError)
	c := &config{}

	fs.StringVar(&c.url, "url", "", "directory base URL, e.g. https://directory.example.com (required)")
	fs.StringVar(&c.sDir, "s-dir", "", "directory secret, 32 bytes as base64url. Generated and printed if unset")
	fs.StringVar(&c.ik, "ik", "", "server identity key seed, 32 bytes as base64url. Generated and printed if unset")
	fs.Var(&c.endpoints, "endpoint", "type:host:port, repeatable (lan, wan4, wan6, dns)")
	fs.Int64Var(&c.ttl, "ttl", record.MaxTTL, "record lifetime in seconds")
	fs.IntVar(&c.powBits, "pow-bits", pow.DefaultBits, "proof-of-work difficulty; must match the directory's")
	fs.StringVar(&c.tlsMode, "tls-mode", record.TLSModePKI, "tls mode: pki or pinned")
	fs.StringVar(&c.caps, "caps", "", "comma-separated capability strings")
	fs.StringVar(&c.out, "o", "", "write the published envelope here, exactly as transmitted")
	fs.Int64Var(&c.epochOff, "epoch-offset", 0, "publish under a neighbouring epoch (-1, 0, +1); for testing skew handling")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() > 0 {
		return nil, errors.New("unexpected arguments: this command takes flags only")
	}
	if c.url == "" {
		return nil, errors.New("-url is required")
	}
	if len(c.endpoints) == 0 {
		return nil, errors.New("at least one -endpoint is required")
	}
	if c.ttl < 1 || c.ttl > record.MaxTTL {
		return nil, fmt.Errorf("-ttl must be between 1 and %d", record.MaxTTL)
	}
	switch c.tlsMode {
	case record.TLSModePKI, record.TLSModePinned:
	default:
		return nil, errors.New("-tls-mode must be pki or pinned")
	}
	return c, nil
}

// secret returns 32 bytes from a base64url flag, generating them if the flag is
// empty and reporting whether it did.
func secret(flagVal, name string) (b []byte, generated bool, err error) {
	if flagVal != "" {
		b, err := b64.DecodeFixed(flagVal, derive.SDirLen)
		if err != nil {
			return nil, false, fmt.Errorf("-%s: must be %d bytes as base64url", name, derive.SDirLen)
		}
		return b, false, nil
	}
	b = make([]byte, derive.SDirLen)
	if _, err := rand.Read(b); err != nil {
		return nil, false, fmt.Errorf("generate %s: %w", name, err)
	}
	return b, true, nil
}

func run(program string, args []string) error {
	cfg, err := parseFlags(program, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	// The proof-of-work search is the slow step; make it interruptible.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	sDir, sDirGen, err := secret(cfg.sDir, "s-dir")
	if err != nil {
		return err
	}
	ikSeed, ikGen, err := secret(cfg.ik, "ik")
	if err != nil {
		return err
	}
	ik := ed25519.NewKeyFromSeed(ikSeed)

	// Keys the operator must keep to verify or republish. Printed before
	// anything can fail, so a generated secret is never lost to a later error.
	if sDirGen {
		fmt.Printf("s_dir       %s   (generated — keep this)\n", b64.Encode(sDir))
	}
	if ikGen {
		fmt.Printf("ik_seed     %s   (generated — keep this)\n", b64.Encode(ikSeed))
	}
	fmt.Printf("ik_pub      %s\n", b64.Encode(ik.Public().(ed25519.PublicKey)))

	now := time.Now().Unix()
	epoch := derive.Epoch(now) + cfg.epochOff

	env, err := build(ctx, sDir, ik, epoch, now, cfg)
	if err != nil {
		return err
	}

	body, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("marshal envelope: %w", err)
	}
	if len(body) > record.MaxEnvelopeBytes {
		return fmt.Errorf("envelope is %d bytes, over the %d-byte cap (§4.3)",
			len(body), record.MaxEnvelopeBytes)
	}

	// Written before the PUT: §5.2 requires verbatim storage, and checking that
	// means comparing against exactly these bytes whatever the directory
	// answers.
	if cfg.out != "" {
		if err := os.WriteFile(cfg.out, body, 0o644); err != nil {
			return fmt.Errorf("write %s: %w", cfg.out, err)
		}
		fmt.Printf("envelope    %s (%d bytes)\n", cfg.out, len(body))
	}

	fmt.Printf("lookup_id   %s\n", env.LookupID)
	fmt.Printf("epoch       %d\n", epoch)
	fmt.Printf("expires_at  %d (%s)\n", env.ExpiresAt,
		time.Unix(env.ExpiresAt, 0).UTC().Format(time.RFC3339))

	status, respBody, err := put(ctx, cfg.url, body)
	if err != nil {
		return err
	}
	fmt.Printf("status      %d %s\n", status, http.StatusText(status))
	if len(respBody) > 0 {
		fmt.Printf("response    %s\n", strings.TrimSpace(string(respBody)))
	}

	// §5.2 binds every outcome to exactly one code, and success is `204` alone —
	// not 200, and not 201, since a publish that replaces an existing record is
	// not distinguished from one that creates it. Anything else is a refusal the
	// operator needs as a non-zero exit. The code is the whole answer: §5.2 gives
	// response bodies no diagnostic detail, so there is nothing else to report.
	if status != http.StatusNoContent {
		return fmt.Errorf("directory refused the record: %d %s",
			status, http.StatusText(status))
	}
	return nil
}

// build assembles a complete envelope for the given epoch.
//
// The order is forced by the data: the payload must exist before it can be
// sealed, the sealed ciphertext and the expiry before the proof of work can be
// solved over them, and all of it before the envelope signature covers it.
func build(ctx context.Context, sDir []byte, ik ed25519.PrivateKey, epoch, now int64, cfg *config) (record.Envelope, error) {
	var zero record.Envelope

	wk, err := derive.WriteKey(sDir, epoch)
	if err != nil {
		return zero, fmt.Errorf("derive write key: %w", err)
	}
	wkPub := wk.Public().(ed25519.PublicKey)
	lookupID := derive.LookupID(wkPub)

	recordKey, err := derive.RecordKey(sDir, epoch)
	if err != nil {
		return zero, fmt.Errorf("derive record key: %w", err)
	}

	var caps []string
	if cfg.caps != "" {
		caps = strings.Split(cfg.caps, ",")
	}
	bodyJSON, err := json.Marshal(record.Body{
		V:         record.Version,
		TS:        now,
		Endpoints: cfg.endpoints,
		TLS:       record.TLSInfo{Mode: cfg.tlsMode},
		Caps:      caps,
	})
	if err != nil {
		return zero, fmt.Errorf("marshal payload body: %w", err)
	}

	// These exact bytes are what the detached signature covers (§4.2).
	plaintext, err := record.MarshalPlaintext(ik, bodyJSON)
	if err != nil {
		return zero, fmt.Errorf("frame payload: %w", err)
	}

	nonce, ct, err := record.Seal(recordKey, plaintext)
	if err != nil {
		return zero, fmt.Errorf("seal payload: %w", err)
	}

	expiresAt := now + cfg.ttl

	fmt.Fprintf(os.Stderr, "solving %d-bit proof of work...\n", cfg.powBits)
	solved, err := pow.Solve(ctx, lookupID, expiresAt, cfg.powBits)
	if err != nil {
		return zero, fmt.Errorf("solve proof of work: %w", err)
	}

	return record.Envelope{
		V:         record.Version,
		LookupID:  b64.Encode(lookupID),
		WKPub:     b64.Encode(wkPub),
		ExpiresAt: expiresAt,
		CT:        b64.Encode(ct),
		Nonce:     b64.Encode(nonce),
		PoW:       b64.Encode(solved),
		Sig: b64.Encode(record.Sign(wk, record.Version,
			lookupID, wkPub, expiresAt, nonce, ct)),
	}, nil
}

// put sends the envelope and returns the status and body.
func put(ctx context.Context, base string, body []byte) (int, []byte, error) {
	endpoint := strings.TrimSuffix(base, "/") + "/v1/record"

	ctx, cancel := context.WithTimeout(ctx, httpTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, endpoint, bytes.NewReader(body))
	if err != nil {
		return 0, nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("PUT %s: %w", endpoint, err)
	}
	defer resp.Body.Close()

	// Bounded: a directory answers with a small body or none, and an
	// unbounded read here would trust a server this tool exists to test.
	rb, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return resp.StatusCode, nil, fmt.Errorf("read response: %w", err)
	}
	return resp.StatusCode, rb, nil
}
