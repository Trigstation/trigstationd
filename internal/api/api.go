// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Simon Wright

// Package api is the HTTP surface of the directory: the four operations of
// DIRECTORY-SPEC.md §5 and nothing else.
//
// This package decides almost nothing. Every rule it applies belongs to a
// package underneath it — internal/accept holds the §5.2 pipeline,
// internal/query the §5.3 prefix maths, internal/signal the §5.4 rendezvous,
// internal/reject the status tables, internal/ratelimit the §6.2 limits and
// internal/clientaddr the §6.4 trusted-proxy rules. What lives here is the
// wiring: read a body under a limit, hand it to the right package, and turn the
// answer into a status code by asking internal/reject for it. A status code
// written out by hand in a handler is a second copy of a normative table, and
// two copies of a table is how two directories come to disagree.
//
// # Four operations, and OPTIONS
//
//	GET  /v1/meta
//	PUT  /v1/record
//	GET  /v1/record
//	POST /v1/signal/{channel_id}
//	GET  /v1/signal/{channel_id}
//
// That is it. There is no health endpoint, no metrics endpoint, no readiness
// probe, no admin route and no handler on / that describes the API. §10 makes
// this a design invariant rather than a preference: anything that would add a
// fifth operation is a proposal to make directories less replaceable, and an
// operator who needs a container health check can use GET /v1/meta, which is
// unauthenticated, cheap and already there. Routes reports the registered
// patterns so a test can assert the set has not grown.
//
// OPTIONS is registered for the two routes §5.5 requires a preflight on. §5.5
// states in terms that it is HTTP transport mechanics for the four operations
// and not a fifth one.
//
// # No request logging
//
// This package sees every request path, every client address, every lookup
// prefix and every channel identifier, so it is the one place in the codebase
// where the no-logging requirement of §9 could most easily be lost. It imports
// no logging package, writes to no output stream, and formats no request value
// into anything. nolog_test.go asserts that against this package's own source
// rather than leaving it to review.
//
// One consequence is not obvious and is handled in ServeHTTP: net/http's own
// error logger prints the client address when a handler panics. See the comment
// there.
//
// # Time
//
// Every handler reads the clock exactly once, at the top, and passes that one
// reading to everything below. Two reads within one request could straddle a
// second boundary and have the same request evaluated against two different
// clocks — which §5.2 forbids across directories and would be no more defensible
// within one. The clock is a field so that tests can pin it.
package api

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/trigstation/trigstationd/internal/accept"
	"github.com/trigstation/trigstationd/internal/clientaddr"
	"github.com/trigstation/trigstationd/internal/ratelimit"
	"github.com/trigstation/trigstationd/internal/signal"
	"github.com/trigstation/trigstationd/internal/store"
)

// DefaultSourceURL is where the unmodified reference implementation lives.
//
// It ships populated because §5.1 and AGPL §13 together make it an obligation
// rather than a courtesy: anyone offering a modified version of this program
// over a network must give its users a way to obtain the modified source, and a
// field in GET /v1/meta is how this implementation discharges that. An operator
// running a fork MUST change it to point at their own source.
const DefaultSourceURL = "https://github.com/trigstation/trigstationd"

// ErrNoSourceURL is returned by New when SourceURL is empty.
//
// The service refuses to start rather than starting with the field blank or
// omitted. Both would be a licence violation the operator could not see, and a
// directory that starts is a directory that is serving.
var ErrNoSourceURL = errors.New("api: source_url is empty: GET /v1/meta must carry the URL of this instance's source (AGPL §13)")

// Errors for a Config that cannot produce a working service.
var (
	ErrNoStore      = errors.New("api: no record store")
	ErrNoLimiter    = errors.New("api: no rate limiter")
	ErrNoClientAddr = errors.New("api: no client address extractor")
)

// Config is everything the handlers need. Every field except Signal and Now is
// required.
type Config struct {
	// Store is the record store of §9. Required.
	Store *store.Store

	// Signal is the in-memory rendezvous store of §5.4. A nil Signal is an
	// instance that does not broker signal channels: /v1/meta reports
	// "signal": false and both methods on /v1/signal/{channel_id} answer 404,
	// which is the one outcome in the §5.4 table that means exactly that.
	Signal *signal.Store

	// Limiter enforces the three independent §6.2 classes. Required: there is
	// deliberately no way to configure the service without one, because §6.4's
	// closing paragraph ranks abuse resistance as a defence that can be lost and
	// rebuilt, not as one that should be switchable off.
	Limiter *ratelimit.Limiter

	// ClientAddr resolves which address a limit is counted against, under the
	// §6.4 trusted-proxy rules. Required. The handler extracts the peer address
	// and the raw header and hands both over; the trust decision is not made
	// here.
	ClientAddr *clientaddr.Extractor

	// Limits are the instance's advertised bounds. A zero value selects
	// accept.DefaultLimits.
	Limits accept.Limits

	// SourceURL is the source_url member of §5.1. Required and never empty; see
	// ErrNoSourceURL.
	SourceURL string

	// Now is the clock. Nil selects time.Now.
	Now func() time.Time
}

// Server is the router and the handlers. It implements http.Handler.
type Server struct {
	store      *store.Store
	signal     *signal.Store
	limiter    *ratelimit.Limiter
	client     *clientaddr.Extractor
	limits     accept.Limits
	sourceURL  string
	now        func() time.Time
	mux        *http.ServeMux
	registered []string
}

// New validates cfg and returns a Server.
//
// It refuses rather than substituting a default for anything whose absence
// would change what the service is: a missing store, a missing limiter, a
// missing address extractor, or an empty source_url.
func New(cfg Config) (*Server, error) {
	if cfg.Store == nil {
		return nil, ErrNoStore
	}
	if cfg.Limiter == nil {
		return nil, ErrNoLimiter
	}
	if cfg.ClientAddr == nil {
		return nil, ErrNoClientAddr
	}
	if strings.TrimSpace(cfg.SourceURL) == "" {
		return nil, ErrNoSourceURL
	}

	s := &Server{
		store:     cfg.Store,
		signal:    cfg.Signal,
		limiter:   cfg.Limiter,
		client:    cfg.ClientAddr,
		limits:    cfg.Limits,
		sourceURL: cfg.SourceURL,
		now:       cfg.Now,
		mux:       http.NewServeMux(),
	}
	if s.limits == (accept.Limits{}) {
		s.limits = accept.DefaultLimits()
	}
	if s.now == nil {
		s.now = time.Now
	}

	s.route()
	return s, nil
}

// route registers the four operations, and the OPTIONS preflights §5.5
// requires.
//
// Nothing else may be added here. If a change to this function adds a path,
// TestRouterExposesExactlyFourOperations fails, which is the intended outcome:
// the fifth operation is meant to be hard to add by accident.
func (s *Server) route() {
	s.handle("GET /v1/meta", s.handleMeta)

	s.handle("PUT /v1/record", s.handlePutRecord)
	s.handle("GET /v1/record", s.handleGetRecord)
	s.handle("OPTIONS /v1/record", preflight("GET, PUT, OPTIONS"))

	s.handle("POST /v1/signal/{channel_id}", s.handlePostSignal)
	s.handle("GET /v1/signal/{channel_id}", s.handleGetSignal)
	s.handle("OPTIONS /v1/signal/{channel_id}", preflight("GET, POST, OPTIONS"))
}

// handle registers a pattern and records it, so that Routes can report the
// whole surface without a second list to keep in step.
func (s *Server) handle(pattern string, h http.HandlerFunc) {
	s.mux.HandleFunc(pattern, h)
	s.registered = append(s.registered, pattern)
}

// Routes returns the registered method-and-path patterns, in registration
// order.
//
// It exists for the test that asserts the API has exactly the operations §5
// gives it. It is not an endpoint, and nothing serves it.
func (s *Server) Routes() []string {
	out := make([]string, len(s.registered))
	copy(out, s.registered)
	return out
}

// ServeHTTP applies the two things that are true of every response, then
// dispatches.
//
// # Cross-origin
//
// §5.5 requires Access-Control-Allow-Origin: * on every /v1/ response, so it is
// set here rather than in each handler — including on the responses a handler
// never sees, such as the mux's own 404 for an unregistered path under /v1/ and
// its 405 for a method that is not one of the four. A wildcard is safe here in a
// way it is not for most services: the API carries no cookies, no credentials
// and no session, and every write is authorised by a signature in the body, so
// a cross-origin caller can do nothing a direct caller cannot.
// Access-Control-Allow-Credentials is never sent, from anywhere in this package.
//
// # Why a panic is recovered and discarded
//
// net/http, with no ErrorLog configured, logs a handler panic through the
// standard logger as "http: panic serving <client address>: …". That writes a
// client address to stderr, which CLAUDE.md forbids absolutely and §6.4 forbids
// "at any severity, under any configuration". The obvious fix — setting
// http.Server.ErrorLog to a discarding logger — requires importing log, and the
// requirement is that the code to log must not exist rather than be configured
// off, with CI enforcing it through the import graph.
//
// So the panic is stopped before net/http can see it. The value is not
// formatted, not stored and not re-panicked; the client gets a bare 500 if
// nothing has been written yet, and the process keeps serving. Discarding a
// panic value is not good practice in general and is the right trade here: the
// alternative is a code path that prints a client address.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	tracked := &trackingWriter{ResponseWriter: w}

	defer func() {
		if recover() == nil {
			return
		}
		if !tracked.wrote {
			tracked.WriteHeader(http.StatusInternalServerError)
		}
	}()

	if strings.HasPrefix(r.URL.Path, "/v1/") {
		tracked.Header().Set("Access-Control-Allow-Origin", "*")
	}
	s.mux.ServeHTTP(tracked, r)
}

// Drain releases every in-flight long-poll so that a graceful shutdown does not
// wait on them.
//
// §5.4 lets a directory hold a GET open for 30 seconds, so a shutdown that
// waited for handlers to return would take up to 30 seconds on an instance with
// one idle poller — and up to 30 seconds on a busy one too, since fresh polls
// keep arriving until the listener closes. Draining first turns every open poll
// into the 204 §5.4 already requires clients to tolerate, and posts arriving in
// the window get the 429 the table gives an instance that is shutting down.
//
// Call it before http.Server.Shutdown. It is idempotent, and safe on an
// instance with signal channels disabled.
func (s *Server) Drain() {
	if s.signal != nil {
		s.signal.Shutdown()
	}
}

// SweepRecords reclaims storage from records that have expired.
//
// It changes no answer this service gives: expiry is a property of the record
// and the clock (§5.2), so every read already excludes a lapsed row. That is
// why the returned error has no handler here and why a caller on a timer may
// discard it — a sweep that fails leaves a larger table and identical
// behaviour, and a database that is genuinely broken surfaces on the next
// publish or lookup as a 500 rather than being hidden by a silent sweep.
func (s *Server) SweepRecords(ctx context.Context) error {
	_, err := s.store.Sweep(ctx, s.now().Unix())
	return err
}

// SweepLimiter discards limiter state whose window has elapsed.
//
// §6.4 requires this on a timer and not only on the request path. The limiter
// sweeps from inside Allow as well, but an instance that goes quiet has nothing
// to drive that, and the last keys seen before the traffic stopped would
// otherwise sit in memory indefinitely. They are truncated networks rather than
// addresses, and they are still address-derived state past the one window §6.4
// allots it.
func (s *Server) SweepLimiter() {
	s.limiter.Sweep(s.now())
}

// preflight answers a CORS preflight for one route, per §5.5.
//
// Access-Control-Allow-Origin is already set by ServeHTTP. Allow-Credentials is
// not sent, here or anywhere: §5.5 forbids it, and the API has no ambient
// authority for it to apply to.
func preflight(methods string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Access-Control-Allow-Methods", methods)
		h.Set("Access-Control-Allow-Headers", "Content-Type")

		// A preflight result is cacheable, and caching it is worth doing: §5.2
		// recommends publishers send a vendor content type, which is precisely
		// what forces a browser to preflight every publish.
		h.Set("Access-Control-Max-Age", "86400")

		w.WriteHeader(http.StatusNoContent)
	}
}

// allow applies the §6.2 limit for one class to one request.
//
// The address is resolved by internal/clientaddr from the immediate peer and
// the raw forwarded header. This function does not decide whether the header
// may be believed; §6.4 puts that decision behind an explicitly configured
// trusted-proxy list, and it lives in that package.
//
// Where several X-Forwarded-For field-lines arrive they are joined in order,
// which RFC 9110 §5.3 makes equivalent to the single combined field the
// extractor expects — and which keeps the rightmost entry of the whole being
// the one the trusted proxy appended.
func (s *Server) allow(r *http.Request, c ratelimit.Class, now time.Time) bool {
	forwarded := strings.Join(r.Header.Values("X-Forwarded-For"), ",")
	return s.limiter.Allow(s.client.Addr(peerAddr(r), forwarded), c, now)
}

// peerAddr extracts the immediate peer from a request.
//
// An address that cannot be parsed comes back as the zero netip.Addr, which
// ratelimit.Allow refuses rather than admits: an unmetered path is worth more
// to a flooder than a rejection is worth to anyone else.
func peerAddr(r *http.Request) netip.Addr {
	if ap, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
		return ap.Addr()
	}
	// A listener on a Unix socket, and httptest in some configurations, set a
	// RemoteAddr with no port.
	if a, err := netip.ParseAddr(r.RemoteAddr); err == nil {
		return a
	}
	return netip.Addr{}
}

// readLimited reads at most limit bytes of a request body.
//
// The caller passes one byte more than it will accept, so that a body at the
// limit and a body over it are distinguishable without reading the excess: the
// size checks in internal/accept and internal/signal both test for strictly
// greater than their maximum, and this returns exactly enough for that test to
// be true. A body of any size therefore costs the directory at most limit bytes
// of memory, which is what makes §5.2's "measured against the received body as
// transmitted, before any parsing" cheap as well as correct.
//
// It reports failure on a read error, which in practice is a client that
// disconnected mid-body. The error itself is discarded: it is a value derived
// from a request, and nothing here has anywhere legitimate to put one.
func readLimited(r *http.Request, limit int) ([]byte, bool) {
	body, err := io.ReadAll(io.LimitReader(r.Body, int64(limit)))
	if err != nil {
		return nil, false
	}
	return body, true
}

// trackingWriter records whether a response has begun, so that the panic
// recovery in ServeHTTP can tell a request that failed before answering from
// one that failed after.
//
// It deliberately implements nothing beyond http.ResponseWriter. Wrapping hides
// any optional interface the underlying writer has, and no handler here needs
// one: the long-poll of §5.4 writes its whole response at once, so there is
// nothing to flush, and nothing hijacks a connection.
type trackingWriter struct {
	http.ResponseWriter
	wrote bool
}

func (w *trackingWriter) WriteHeader(code int) {
	w.wrote = true
	w.ResponseWriter.WriteHeader(code)
}

func (w *trackingWriter) Write(b []byte) (int, error) {
	w.wrote = true
	return w.ResponseWriter.Write(b)
}
