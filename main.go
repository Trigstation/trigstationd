// Trigstation directory service — a zero-knowledge coordination service
// for self-hosted media servers.
// Copyright (C) 2026  Simon Wright
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or (at your
// option) any later version.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Affero General Public
// License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

// Command trigstationd is the reference implementation of the Trigstation
// directory service, specified in DIRECTORY-SPEC.md.
//
// The service stores encrypted address records on behalf of self-hosted media
// servers and brokers short-lived rendezvous channels between paired clients.
// It never carries media, holds no accounts, and cannot read what it stores.
//
// # Configuration
//
// Every setting is a flag with an environment variable fallback, so the same
// binary suits a systemd unit and a container without a config file. The flag
// wins where both are given. Run with -h for the list.
//
// # What this command does not do
//
// It does not terminate TLS. §9's deployment story puts a reverse proxy in
// front — set a domain, get a certificate, run — and a directory that also
// spoke TLS would be a second certificate to renew for no gain. Note that
// running behind a proxy makes -trusted-proxies necessary: without it the
// directory sees the proxy's address on every request, every client in the
// world collapses into one rate-limiter key, and the limiter then refuses
// everybody (§6.4).
//
// It does not log requests. Not at a lower level, not behind a flag: the code
// to do it does not exist anywhere in this program. The messages this file
// writes to stderr are startup and fatal-error messages, and none of them names
// anything from a request.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/trigstation/trigstationd/internal/accept"
	"github.com/trigstation/trigstationd/internal/api"
	"github.com/trigstation/trigstationd/internal/clientaddr"
	"github.com/trigstation/trigstationd/internal/ratelimit"
	"github.com/trigstation/trigstationd/internal/record"
	sigstore "github.com/trigstation/trigstationd/internal/signal"
	"github.com/trigstation/trigstationd/internal/store"
)

// Server timeouts.
//
// The binding constraint is the 30-second long-poll of §5.4, and it binds on
// both deadlines rather than only the obvious one.
//
// WriteTimeout is the obvious one: net/http sets the write deadline before the
// handler runs, so a deadline below 30 seconds would kill the connection just as
// a poll that found nothing was writing its 204.
//
// ReadTimeout is the less obvious one. The read deadline also covers the
// handler's lifetime, and while a handler runs net/http keeps a background read
// outstanding to notice the client closing. If the read deadline expires under
// that read, the connection is treated as failed and torn down — so a
// ReadTimeout of 30 seconds would abort long-polls at almost exactly the moment
// they were due to answer.
//
// Both are therefore set above the poll window with room to spare. The slow-body
// exposure that a long ReadTimeout would normally create is closed elsewhere:
// ReadHeaderTimeout bounds the header phase tightly, and every body this service
// reads is bounded at 4 KB or 64 KB by the handler, so a dribbling client
// occupies one connection and no meaningful memory.
const (
	readHeaderTimeout = 10 * time.Second
	readTimeout       = 45 * time.Second
	writeTimeout      = 45 * time.Second
	idleTimeout       = 120 * time.Second
	maxHeaderBytes    = 16 << 10

	// shutdownGrace bounds the wait for in-flight requests once the listener
	// has closed. Long-polls are released before this starts, so in practice
	// the wait is the time a few small responses take to flush.
	shutdownGrace = 10 * time.Second

	// recordSweepInterval reclaims storage from expired records. It changes no
	// answer the service gives — expiry is a property of the record and the
	// clock (§5.2) — so the interval is a housekeeping choice, not a
	// correctness one.
	recordSweepInterval = 5 * time.Minute

	// limiterSweepInterval discards limiter state whose window has elapsed.
	// §6.4 requires this on a timer as well as on the request path, so that an
	// instance which goes quiet does not retain the last keys it saw.
	limiterSweepInterval = 1 * time.Minute
)

func main() {
	if err := run(os.Args[0], os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "trigstationd:", err)
		os.Exit(1)
	}
}

// config is the parsed command line.
type config struct {
	listen         string
	database       string
	sourceURL      string
	powBits        int
	maxTTL         int64
	maxRecordBytes int
	signalEnabled  bool
	trustedProxies string
	ratePut        int
	rateGet        int
	rateSignal     int
}

// parseFlags builds the configuration from the command line, with an
// environment variable behind each flag as its default so that an explicit flag
// always wins.
func parseFlags(program string, args []string) (*config, error) {
	fs := flag.NewFlagSet(program, flag.ContinueOnError)
	c := &config{}

	fs.StringVar(&c.listen, "listen", envString("TRIGSTATIOND_LISTEN", ":8080"),
		"address to listen on (env TRIGSTATIOND_LISTEN). Plain HTTP: TLS is terminated upstream, per §9")
	fs.StringVar(&c.database, "db", envString("TRIGSTATIOND_DB", "trigstation.db"),
		"path to the SQLite database, or :memory: (env TRIGSTATIOND_DB)")
	fs.StringVar(&c.sourceURL, "source-url", envString("TRIGSTATIOND_SOURCE_URL", api.DefaultSourceURL),
		"source of the running instance, published as source_url in GET /v1/meta "+
			"(env TRIGSTATIOND_SOURCE_URL). An operator running a fork MUST change this to their own "+
			"source: it is how AGPL §13 is discharged. It may not be empty")
	fs.IntVar(&c.powBits, "pow-bits", envInt("TRIGSTATIOND_POW_BITS", 20),
		"proof-of-work difficulty in leading zero bits (env TRIGSTATIOND_POW_BITS)")
	fs.Int64Var(&c.maxTTL, "max-ttl", int64(envInt("TRIGSTATIOND_MAX_TTL", record.MaxTTL)),
		"maximum record lifetime in seconds (env TRIGSTATIOND_MAX_TTL)")
	fs.IntVar(&c.maxRecordBytes, "max-record-bytes", envInt("TRIGSTATIOND_MAX_RECORD_BYTES", record.MaxEnvelopeBytes),
		"maximum envelope size in bytes, measured as transmitted (env TRIGSTATIOND_MAX_RECORD_BYTES)")
	fs.BoolVar(&c.signalEnabled, "signal", envBool("TRIGSTATIOND_SIGNAL", true),
		"broker signal channels (env TRIGSTATIOND_SIGNAL). When off, /v1/meta reports signal:false "+
			"and both methods on /v1/signal/{channel_id} answer 404")
	fs.StringVar(&c.trustedProxies, "trusted-proxies", envString("TRIGSTATIOND_TRUSTED_PROXIES", ""),
		"comma-separated CIDR blocks whose X-Forwarded-For may be believed (env "+
			"TRIGSTATIOND_TRUSTED_PROXIES). Empty by default, which ignores the header entirely. "+
			"Set this when running behind a reverse proxy, or rate limiting keys every client in "+
			"the world to the proxy and refuses them all (§6.4)")
	fs.IntVar(&c.ratePut, "rate-put", envInt("TRIGSTATIOND_RATE_PUT", ratelimit.DefaultPutRecord),
		"PUT /v1/record allowance per source per hour (env TRIGSTATIOND_RATE_PUT)")
	fs.IntVar(&c.rateGet, "rate-get", envInt("TRIGSTATIOND_RATE_GET", ratelimit.DefaultGetRecord),
		"GET /v1/record allowance per source per hour (env TRIGSTATIOND_RATE_GET)")
	fs.IntVar(&c.rateSignal, "rate-signal", envInt("TRIGSTATIOND_RATE_SIGNAL", ratelimit.DefaultSignal),
		"signal channel allowance per source per hour (env TRIGSTATIOND_RATE_SIGNAL)")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() > 0 {
		return nil, errors.New("unexpected arguments: this command takes flags only")
	}
	return c, nil
}

// run is main with the process boundary removed, so that a failure is a returned
// error rather than an exit.
func run(program string, args []string) error {
	cfg, err := parseFlags(program, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	trusted, err := clientaddr.ParsePrefixes(cfg.trustedProxies)
	if err != nil {
		return fmt.Errorf("-trusted-proxies: %w", err)
	}

	recordStore, err := store.Open(cfg.database)
	if err != nil {
		return err
	}
	defer recordStore.Close()

	// A nil signal store is what makes an instance advertise "signal": false,
	// so the flag is expressed by building one or not building one rather than
	// by a second flag the handlers would have to consult.
	var signalStore *sigstore.Store
	if cfg.signalEnabled {
		signalStore = sigstore.New(sigstore.Options{})
	}

	limiter := ratelimit.New(ratelimit.Options{
		PutRecord: cfg.ratePut,
		GetRecord: cfg.rateGet,
		Signal:    cfg.rateSignal,
	})

	handler, err := api.New(api.Config{
		Store:      recordStore,
		Signal:     signalStore,
		Limiter:    limiter,
		ClientAddr: clientaddr.New(trusted),
		Limits: accept.Limits{
			MaxRecordBytes: cfg.maxRecordBytes,
			MaxTTL:         cfg.maxTTL,
			PoWBits:        cfg.powBits,
			SkewGrace:      accept.DefaultSkewGrace,
		},
		SourceURL: cfg.sourceURL,
	})
	if err != nil {
		return err
	}

	srv := &http.Server{
		Addr:              cfg.listen,
		Handler:           handler,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
	}

	return serve(srv, handler)
}

// serve runs the listener until a termination signal arrives, then shuts down.
//
// # The shutdown order is the interesting part
//
// Draining comes before http.Server.Shutdown, and the order is not cosmetic.
// Shutdown closes the listener and then waits for active requests to finish. A
// §5.4 long-poll is an active request that will sit there for up to 30 seconds
// by design, so shutting down first would mean waiting out the poll window on
// any instance with one idle poller — and PAIRING-SPEC.md §6.3 makes an idle
// poller the normal state, not an unusual one. Draining first releases every
// waiter, each returns the 204 §5.4 requires clients to tolerate, and Shutdown
// then has only small responses left to flush.
func serve(srv *http.Server, handler *api.Server) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	sweeps := startSweeps(ctx, handler)

	listenErr := make(chan error, 1)
	go func() {
		err := srv.ListenAndServe()
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		listenErr <- err
	}()

	listen := srv.Addr
	fmt.Fprintf(os.Stderr, "trigstationd: listening on %s\n", listen)

	select {
	case err := <-listenErr:
		stop()
		<-sweeps
		return err
	case <-ctx.Done():
	}

	fmt.Fprintln(os.Stderr, "trigstationd: shutting down")

	handler.Drain()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()
	shutdownErr := srv.Shutdown(shutdownCtx)

	<-sweeps

	if err := <-listenErr; err != nil {
		return err
	}
	return shutdownErr
}

// startSweeps runs the two reclamation timers and returns a channel closed once
// both have stopped.
//
// The limiter timer is required by §6.4: state must be discarded when its window
// elapses, and on an instance receiving no requests there is nothing on the
// request path to drive that. The record timer is housekeeping only — an expired
// record is absent from every read whether or not a sweep has reached it — so
// its error is deliberately discarded. There is nowhere to report it that would
// not be logging, and a database that is genuinely broken surfaces on the next
// publish or lookup as a 500 rather than being concealed by a quiet sweep.
func startSweeps(ctx context.Context, handler *api.Server) <-chan struct{} {
	done := make(chan struct{})

	go func() {
		defer close(done)

		records := time.NewTicker(recordSweepInterval)
		defer records.Stop()
		limits := time.NewTicker(limiterSweepInterval)
		defer limits.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-records.C:
				_ = handler.SweepRecords(ctx)
			case <-limits.C:
				handler.SweepLimiter()
			}
		}
	}()

	return done
}

// envString returns the environment variable if it is set to a non-empty value,
// otherwise def.
func envString(name, def string) string {
	if v, ok := os.LookupEnv(name); ok && v != "" {
		return v
	}
	return def
}

// envInt returns the environment variable parsed as an integer, or def if it is
// unset or unparseable. An unparseable value falls back rather than failing:
// these are all bounded quantities with sound defaults, and refusing to start
// over a typo in an environment variable is a worse outcome than running at the
// documented default.
func envInt(name string, def int) int {
	if v, ok := os.LookupEnv(name); ok {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

// envBool returns the environment variable parsed as a boolean, or def.
func envBool(name string, def bool) bool {
	if v, ok := os.LookupEnv(name); ok {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return def
}
