// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Simon Wright

// Command trigcheck publishes one record to a directory, and reads it back.
//
// It exists because a directory should be checkable on its own. An operator
// standing one up needs to confirm the round trip before trusting it, and
// requiring a client library to do that inverts the dependency — the directory
// is the thing with a specification and vectors, and waiting for a client in
// the operator's language means no directory can be verified until one exists.
//
// It is also the only place the server side of the protocol is demonstrated end
// to end. Publishing: derive the epoch keys (§3.3), sign and seal the inner
// payload (§4.2), solve the proof of work (§6.1), sign the envelope (§4.1) and
// PUT it (§5.2). Verifying: compute the prefix width from the advertised record
// count (§5.3), GET the bucket, trial-decrypt each envelope, and check the
// inner signature. That verification loop is where the subtle mistakes live,
// which is the argument for there being one reference version of it.
//
//	# publish, keeping what it generates
//	go run ./cmd/trigcheck -url https://directory.example.com \
//	    -endpoint wan4:203.0.113.7:8920 -o published.json
//
//	# read it back
//	go run ./cmd/trigcheck -verify -url https://directory.example.com \
//	    -s-dir <base64url> -ik-pub <base64url>
//
// # What this deliberately is not
//
// It is a conformance check, not a client. It does not implement §5.3's epoch
// fallback window, does not race the endpoints it finds, does not connect to
// any of them, and persists nothing. Those are client behaviours and belong in
// a client library. Publishing is one-shot for the same reason: keepalive
// republishing and epoch rollover belong to a media server, which knows when
// its address changed and this does not.
//
// # This is a client of the directory, and the no-logging rule does not bind it
//
// DIRECTORY-SPEC.md §9.2 constrains what a *directory deployment* records about
// its clients. This program is on the other side of that boundary. It prints
// its own identifiers and its own decrypted payload to its own terminal, which
// is the operator reading their own data, and it never sees anybody else's.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
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

// httpTimeout bounds each request. The proof of work is solved before the PUT
// is made, so nothing slow happens inside one.
const httpTimeout = 30 * time.Second

// anonymitySet is §5.3's RECOMMENDED k: the smallest number of records a lookup
// should be indistinguishable among. The directory's cap is computed against a
// k_min fixed at 20, and §5.1 promises that a client following the advertised
// record_count is never rejected as over-precise — which holds precisely
// because this value is above that floor.
const anonymitySet = 50

func main() {
	if err := run(os.Args[0], os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "trigcheck:", err)
		os.Exit(1)
	}
}

type config struct {
	verify    bool
	url       string
	sDir      string
	ik        string
	ikPub     string
	endpoints endpointList
	ttl       int64
	powBits   int
	tlsMode   string
	caps      string
	out       string
	epochOff  int64
}

// endpointList collects repeated -endpoint flags, preserving order. §4.2 makes
// endpoints an ordered sequence rather than a set, and the signature is over the
// serialised bytes, so the order the operator gave is the order published.
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

	fs.BoolVar(&c.verify, "verify", false,
		"read a record back instead of publishing; requires -s-dir and -ik-pub")
	fs.StringVar(&c.url, "url", "", "directory base URL, e.g. https://directory.example.com (required)")
	fs.StringVar(&c.sDir, "s-dir", "", "directory secret, 32 bytes as base64url. Generated and printed if unset when publishing")
	fs.StringVar(&c.ik, "ik", "", "server identity key seed, 32 bytes as base64url. Generated and printed if unset when publishing")
	fs.StringVar(&c.ikPub, "ik-pub", "", "server identity public key, 32 bytes as base64url (-verify only)")
	fs.Var(&c.endpoints, "endpoint", "type:host:port, repeatable (lan, wan4, wan6, dns)")
	fs.Int64Var(&c.ttl, "ttl", record.MaxTTL, "record lifetime in seconds")
	fs.IntVar(&c.powBits, "pow-bits", pow.DefaultBits, "proof-of-work difficulty; must match the directory's")
	fs.StringVar(&c.tlsMode, "tls-mode", record.TLSModePKI, "tls mode: pki or pinned")
	fs.StringVar(&c.caps, "caps", "", "comma-separated capability strings")
	fs.StringVar(&c.out, "o", "", "write the published envelope here, exactly as transmitted")
	fs.Int64Var(&c.epochOff, "epoch-offset", 0, "use a neighbouring epoch (-1, 0, +1); for testing skew handling")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() > 0 {
		return nil, errors.New("unexpected arguments: this command takes flags only")
	}
	if c.url == "" {
		return nil, errors.New("-url is required")
	}
	c.url = strings.TrimSuffix(c.url, "/")

	if c.verify {
		if c.sDir == "" {
			return nil, errors.New("-verify needs -s-dir: without it there is no RecordKey to decrypt with")
		}
		if c.ikPub == "" {
			return nil, errors.New("-verify needs -ik-pub: without it the inner signature cannot be checked")
		}
		return c, nil
	}

	if len(c.endpoints) == 0 {
		return nil, errors.New("at least one -endpoint is required when publishing")
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

	if cfg.verify {
		return runVerify(ctx, cfg)
	}
	return runPublish(ctx, cfg)
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

func runPublish(ctx context.Context, cfg *config) error {
	sDir, sDirGen, err := secret(cfg.sDir, "s-dir")
	if err != nil {
		return err
	}
	ikSeed, ikGen, err := secret(cfg.ik, "ik")
	if err != nil {
		return err
	}
	ik := ed25519.NewKeyFromSeed(ikSeed)
	ikPub := ik.Public().(ed25519.PublicKey)

	// Keys the operator must keep in order to verify or republish. Printed
	// before anything can fail, so a generated secret is never lost to a later
	// error.
	if sDirGen {
		fmt.Printf("s_dir       %s   (generated — keep this)\n", b64.Encode(sDir))
	}
	if ikGen {
		fmt.Printf("ik_seed     %s   (generated — keep this)\n", b64.Encode(ikSeed))
	}
	fmt.Printf("ik_pub      %s\n", b64.Encode(ikPub))

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
	// answers. It also yields a valid envelope that was never published, which
	// is what an unknown-member probe needs.
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

	status, respBody, err := do(ctx, http.MethodPut, cfg.url+"/v1/record", body)
	if err != nil {
		return err
	}
	fmt.Printf("status      %d %s\n", status, http.StatusText(status))
	if len(respBody) > 0 {
		fmt.Printf("response    %s\n", strings.TrimSpace(string(respBody)))
	}

	// §5.2 binds every outcome to exactly one code, and success is 204 alone —
	// not 200, and not 201, since a publish that replaces an existing record is
	// not distinguished from one that creates it. Anything else is a refusal the
	// operator needs as a non-zero exit. The code is the whole answer: §5.2
	// gives response bodies no diagnostic detail, so there is nothing to add.
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

// meta is the subset of GET /v1/meta this tool reads.
type meta struct {
	RecordCount int64 `json:"record_count"`
}

// lookupResponse is the shape of GET /v1/record. Envelopes are held raw so that
// the bytes the directory sent are the bytes examined — §5.2 requires them
// stored verbatim, and decoding then re-encoding them here would conceal a
// directory that does not.
type lookupResponse struct {
	Records []json.RawMessage `json:"records"`
}

func runVerify(ctx context.Context, cfg *config) error {
	sDir, _, err := secret(cfg.sDir, "s-dir")
	if err != nil {
		return err
	}
	ikPubRaw, err := b64.DecodeFixed(cfg.ikPub, ed25519.PublicKeySize)
	if err != nil {
		return fmt.Errorf("-ik-pub: must be %d bytes as base64url", ed25519.PublicKeySize)
	}
	ikPub := ed25519.PublicKey(ikPubRaw)

	// §5.3 computes the prefix width from the advertised record count, and §5.1
	// promises a client following it is never rejected as over-precise.
	status, body, err := do(ctx, http.MethodGet, cfg.url+"/v1/meta", nil)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("GET /v1/meta: %d %s", status, http.StatusText(status))
	}
	var m meta
	if err := json.Unmarshal(body, &m); err != nil {
		return fmt.Errorf("parse /v1/meta: %w", err)
	}

	epoch := derive.Epoch(time.Now().Unix()) + cfg.epochOff
	wk, err := derive.WriteKey(sDir, epoch)
	if err != nil {
		return fmt.Errorf("derive write key: %w", err)
	}
	lookupID := derive.LookupID(wk.Public().(ed25519.PublicKey))
	recordKey, err := derive.RecordKey(sDir, epoch)
	if err != nil {
		return fmt.Errorf("derive record key: %w", err)
	}

	bits := prefixBits(m.RecordCount, anonymitySet)
	prefix := prefixHex(lookupID, bits)

	fmt.Printf("record_count  %d\n", m.RecordCount)
	fmt.Printf("bits          %d   (k=%d, §5.3)\n", bits, anonymitySet)
	fmt.Printf("prefix        %q\n", prefix)
	fmt.Printf("epoch         %d\n", epoch)

	q := fmt.Sprintf("%s/v1/record?prefix=%s&bits=%d", cfg.url, prefix, bits)
	status, body, err = do(ctx, http.MethodGet, q, nil)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("GET /v1/record: %d %s", status, http.StatusText(status))
	}
	var lr lookupResponse
	if err := json.Unmarshal(body, &lr); err != nil {
		return fmt.Errorf("parse lookup response: %w", err)
	}

	// The bucket size is what §5.3's anonymity-set claim amounts to in practice:
	// the directory learns that somebody asked about this many servers, and no
	// more. Printing it makes the claim observable rather than theoretical.
	fmt.Printf("returned      %d envelopes, %d bytes — the anonymity set for this lookup\n",
		len(lr.Records), len(body))
	if m.RecordCount > 0 && int64(len(lr.Records))*2 > m.RecordCount {
		fmt.Printf("              note: that is most of the directory. Below 2 x k a bucket is\n")
		fmt.Printf("              much of the table, which is expected on a small instance and\n")
		fmt.Printf("              resolves itself as the instance grows.\n")
	}

	// §5.3: trial decryption is the filter. Every envelope in the bucket is
	// attempted, exactly one authenticates, and the rest fail and are discarded —
	// an ordinary outcome on this path rather than an anomaly.
	matched := 0
	for _, raw := range lr.Records {
		var e record.Envelope
		if json.Unmarshal(raw, &e) != nil {
			continue
		}
		d, err := e.Decode()
		if err != nil {
			continue
		}
		// Verify covers the lookup_id binding and the envelope signature. A
		// directory cannot forge either, but a client that skipped them would
		// accept whatever it was handed.
		if err := d.Verify(); err != nil {
			continue
		}
		plaintext, err := record.Open(recordKey, d.Nonce, d.CT)
		if err != nil {
			continue
		}
		matched++

		bodyJSON, err := record.VerifyPlaintext(ikPub, plaintext)
		if err != nil {
			return fmt.Errorf("payload decrypted but its inner signature does not verify under -ik-pub: %w", err)
		}
		var pb record.Body
		if err := json.Unmarshal(bodyJSON, &pb); err != nil {
			return fmt.Errorf("payload body is not valid JSON: %w", err)
		}

		fmt.Printf("\nmatched       envelope signature and lookup_id binding: OK\n")
		fmt.Printf("              payload decrypted under the derived RecordKey: OK\n")
		fmt.Printf("              inner signature under ik_pub: OK\n")
		fmt.Printf("published at  %s\n", time.Unix(pb.TS, 0).UTC().Format(time.RFC3339))
		fmt.Printf("expires at    %s\n", time.Unix(d.ExpiresAt, 0).UTC().Format(time.RFC3339))
		fmt.Printf("tls           %s%s\n", pb.TLS.Mode, optional(pb.TLS.Fingerprint))
		if len(pb.Caps) > 0 {
			fmt.Printf("caps          %s\n", strings.Join(pb.Caps, ", "))
		}
		for _, ep := range pb.Endpoints {
			fmt.Printf("endpoint      %-5s %s\n", ep.Type, hostPort(ep.Host, ep.Port))
		}
	}

	if matched == 0 {
		return errors.New("no envelope in the bucket decrypted under this S_dir. " +
			"If the record was published under a neighbouring epoch, retry with -epoch-offset -1 or 1")
	}
	if matched > 1 {
		// Two records under one S_dir and epoch cannot arise: the lookup_id is
		// derived from the epoch write key and §5.2 keeps one record per
		// lookup_id. Worth reporting rather than passing over.
		return fmt.Errorf("%d envelopes decrypted under one S_dir and epoch, which should be impossible", matched)
	}
	return nil
}

func optional(s string) string {
	if s == "" {
		return ""
	}
	return " " + s
}

// hostPort renders an endpoint for display, bracketing an IPv6 literal.
//
// Without the brackets 2001:db8::1 on port 8920 prints as 2001:db8::1:8920,
// which is both unreadable and a valid IPv6 address in its own right — so the
// operator cannot tell where the address ends and the port begins, in the one
// output they are reading to confirm the record is correct.
func hostPort(host string, port int) string {
	if strings.ContainsRune(host, ':') {
		return fmt.Sprintf("[%s]:%d", host, port)
	}
	return fmt.Sprintf("%s:%d", host, port)
}

// prefixBits is §5.3's client-side width: the largest bits such that the
// expected result set is at least k records.
//
//	bits = max(0, floor(log2(record_count / k)))
//
// floor is deliberate and makes k a floor rather than a target, so the expected
// result set lands between k and 2k. Computed in integers, because the float
// form invites a rounding disagreement between implementations at exactly the
// powers of two where the answer changes.
func prefixBits(recordCount, k int64) int {
	if k <= 0 || recordCount < k {
		return 0
	}
	bits := 0
	for k<<(bits+1) <= recordCount {
		bits++
	}
	return bits
}

// prefixHex renders the leading bits of lookupID as §5.3 requires: exactly
// ceil(bits/4) hex characters, with the trailing low bits of the final
// character zeroed.
//
// A directory MUST mask and ignore those trailing bits rather than reject a
// query carrying them, but a client SHOULD send them as zero.
func prefixHex(lookupID []byte, bits int) string {
	if bits <= 0 {
		return ""
	}
	chars := (bits + 3) / 4
	full := hex.EncodeToString(lookupID)
	if chars > len(full) {
		chars = len(full)
	}
	out := []byte(full[:chars])

	if rem := chars*4 - bits; rem > 0 {
		v, err := strconv.ParseUint(string(out[chars-1]), 16, 8)
		if err != nil {
			return string(out)
		}
		v &^= (1 << rem) - 1
		out[chars-1] = "0123456789abcdef"[v]
	}
	return string(out)
}

// do issues one request and returns the status and a bounded body.
func do(ctx context.Context, method, url string, body []byte) (int, []byte, error) {
	ctx, cancel := context.WithTimeout(ctx, httpTimeout)
	defer cancel()

	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, r)
	if err != nil {
		return 0, nil, fmt.Errorf("build request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("%s %s: %w", method, url, err)
	}
	defer resp.Body.Close()

	// Bounded. A §5.3 response is around 2k envelopes at the recommended width,
	// so a megabyte is generous, and an unbounded read would trust a server this
	// tool exists to test.
	rb, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return resp.StatusCode, nil, fmt.Errorf("read response: %w", err)
	}
	return resp.StatusCode, rb, nil
}
