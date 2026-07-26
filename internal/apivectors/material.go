// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Simon Wright

package apivectors

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/trigstation/trigstationd/internal/accept"
	"github.com/trigstation/trigstationd/internal/b64"
	"github.com/trigstation/trigstationd/internal/pow"
	"github.com/trigstation/trigstationd/internal/query"
	"github.com/trigstation/trigstationd/internal/record"
	"github.com/trigstation/trigstationd/internal/signal"
)

// The instance these fixtures describe. Every one of these is either a §4.3
// ceiling or an instance parameter §5.1 requires the instance to advertise.
const (
	// Now is the directory's clock for every fixture, in Unix seconds. It is
	// 86400 * 20295 — the first second of an epoch, and the same instant the
	// §4.2 worked example uses — so that a reader comparing the two files is
	// not also converting between two arbitrary times.
	//
	// A directory performs no epoch computation (§5.3), so the choice has no
	// effect on any expectation here. It is fixed because expiry is
	// time-dependent and a vector file evaluated against wall time would start
	// failing on its own.
	Now = int64(1753488000)

	// PoWBits is this instance's advertised difficulty. See the package
	// comment for why it is not the default 20.
	PoWBits = 8

	// MaxTTL, MaxRecordBytes and SkewGrace are the §4.3 and §5.2 figures.
	MaxTTL         = int64(record.MaxTTL)
	MaxRecordBytes = record.MaxEnvelopeBytes
	SkewGrace      = int64(accept.DefaultSkewGrace)

	// RecordExpiresAt is the expiry every pre-loaded record carries: an hour
	// after Now, comfortably inside max_ttl and comfortably in the future.
	RecordExpiresAt = Now + 3600

	// InitialRecordCount is exactly 2 × k_min.
	//
	// The figure is chosen, not arbitrary. §5.3 caps a query at
	// max(0, floor(log2(record_count / k_min))) against a normative k_min of
	// 20, so an instance holding fewer than 40 records accepts bits = 0 and
	// nothing else — and none of the §5.3 prefix rules would be observable. At
	// exactly 40 the cap is 1, which is the smallest instance on which a
	// masked prefix query can be shown to work at all.
	InitialRecordCount = 2 * query.KMin

	// SignalTTL is the §4.3 signal channel TTL in seconds.
	SignalTTL = int64(signal.MaxTTL / time.Second)

	// SignalPollWindowMaximum is the §5.4 long-poll ceiling in seconds.
	SignalPollWindowMaximum = int64(signal.MaxPollWindow / time.Second)

	// SourceURL is the §5.1 member AGPL §13 makes an obligation. A harness
	// should configure its instance with this value so that the meta fixture
	// compares exactly; an operator running a fork points it at their own
	// source.
	SourceURL = "https://github.com/trigstation/trigstationd"
)

// Rate-limit allowances for the two configurations that need them.
const (
	generousLimit    = 600
	limitWindowSecs  = 3600
	exhaustibleLimit = 1
)

// publisherDomain separates this file's key material from every other
// derivation in the project. The seeds are a counting sequence hashed with it,
// so they are reproducible by anyone and secret to nobody.
const publisherDomain = "trigstation/api-vectors/publisher/v1"

// channelDomain does the same for signal channel identifiers.
const channelDomain = "trigstation/api-vectors/channel/v1"

// publisher is a server publishing under one write key.
//
// The directory never derives a key (§4.4), so these fixtures need no epoch
// schedule: any Ed25519 keypair with lookup_id = SHA-256(wk_pub) satisfies
// every condition §5.2 checks. Deriving them from S_dir would suggest the
// directory knew something about the derivation, which is the misunderstanding
// the specification spends §3.3 preventing.
type publisher struct {
	index    uint32
	priv     ed25519.PrivateKey
	pub      ed25519.PublicKey
	lookupID []byte

	// ct is a stand-in ciphertext of exactly one AEAD tag's width, the
	// shortest §4.1 permits. The directory never decrypts, and the only thing
	// it checks is that the value is at least as long as the tag — so a real
	// sealed payload would add several hundred bytes to every expected body in
	// the file and prove nothing the derivation vectors do not already prove.
	ct    []byte
	nonce []byte
}

func newPublisher(index uint32) *publisher {
	var idx [4]byte
	binary.BigEndian.PutUint32(idx[:], index)

	h := sha256.New()
	h.Write([]byte(publisherDomain))
	h.Write(idx[:])
	seed := h.Sum(nil)

	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	lookupID := sha256.Sum256(pub)

	ct := sha256.Sum256(append([]byte("ct:"), pub...))
	nonce := sha256.Sum256(append([]byte("nonce:"), pub...))

	return &publisher{
		index:    index,
		priv:     priv,
		pub:      pub,
		lookupID: lookupID[:],
		ct:       ct[:record.TagLen],
		nonce:    nonce[:record.NonceLen],
	}
}

// highPublishers returns n publishers whose lookup_id has its top bit set,
// scanning the seed sequence from start and reporting where it stopped.
//
// Every record in the initial state shares that top bit, which is what makes
// the §5.3 fixtures possible on an instance small enough to ship. With a cap of
// 1 bit the only queries available are bits = 0 and bits = 1, and a table whose
// identifiers all begin with a 1 answers the two halves of that query with the
// whole table and with nothing. So a masked query that lands on 1 proves
// matching, a masked query that lands on 0 proves the empty-result shape §5.3
// requires instead of a 404, and a query whose padding bits disagree with its
// significant bit proves the mask is applied rather than the character compared.
//
// About half of any seed sequence qualifies, so the scan is short. It is
// deterministic, which is the only property that matters here.
func highPublishers(start uint32, n int) ([]*publisher, uint32) {
	out := make([]*publisher, 0, n)
	i := start
	for len(out) < n {
		p := newPublisher(i)
		i++
		if p.lookupID[0]&0x80 == 0 {
			continue
		}
		out = append(out, p)
	}
	return out, i
}

// solve returns a proof of work satisfying PoWBits for this publisher's
// identifier and the given expiry (§6.1).
func (p *publisher) solve(ctx context.Context, expiresAt int64) ([]byte, error) {
	v, err := pow.Solve(ctx, p.lookupID, expiresAt, PoWBits)
	if err != nil {
		return nil, fmt.Errorf("apivectors: solve proof of work: %w", err)
	}
	return v, nil
}

// envelope builds a fully valid envelope for this publisher (§4.1).
func (p *publisher) envelope(ctx context.Context, expiresAt int64) (record.Envelope, error) {
	solved, err := p.solve(ctx, expiresAt)
	if err != nil {
		return record.Envelope{}, err
	}
	return record.Envelope{
		V:         record.Version,
		LookupID:  b64.Encode(p.lookupID),
		WKPub:     b64.Encode(p.pub),
		ExpiresAt: expiresAt,
		CT:        b64.Encode(p.ct),
		Nonce:     b64.Encode(p.nonce),
		PoW:       b64.Encode(solved),
		Sig: b64.Encode(record.Sign(p.priv, record.Version,
			p.lookupID, p.pub, expiresAt, p.nonce, p.ct)),
	}, nil
}

// member is one name/value pair of a JSON object, with the value already
// rendered.
//
// Envelopes are built through this rather than through struct marshalling
// because several fixtures need a shape encoding/json cannot produce: a
// duplicate member name, an explicit null where a value belongs, a member
// removed, or a member order that differs from the specification's examples.
type member struct {
	name string
	raw  string
}

// envelopeMembers renders an envelope in the field order of §4.1.
func envelopeMembers(e record.Envelope) []member {
	return []member{
		{"v", strconv.Itoa(e.V)},
		{"lookup_id", jsonString(e.LookupID)},
		{"wk_pub", jsonString(e.WKPub)},
		{"expires_at", strconv.FormatInt(e.ExpiresAt, 10)},
		{"ct", jsonString(e.CT)},
		{"nonce", jsonString(e.Nonce)},
		{"pow", jsonString(e.PoW)},
		{"sig", jsonString(e.Sig)},
	}
}

// render writes members as a compact JSON object, in the order given.
func render(ms []member) string {
	var b strings.Builder
	b.WriteByte('{')
	for i, m := range ms {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(jsonString(m.name))
		b.WriteByte(':')
		b.WriteString(m.raw)
	}
	b.WriteByte('}')
	return b.String()
}

// set replaces the raw value of a member, or appends it if absent.
func set(ms []member, name, raw string) []member {
	out := append([]member(nil), ms...)
	for i := range out {
		if out[i].name == name {
			out[i].raw = raw
			return out
		}
	}
	return append(out, member{name, raw})
}

// remove drops a member.
func remove(ms []member, name string) []member {
	out := make([]member, 0, len(ms))
	for _, m := range ms {
		if m.name == name {
			continue
		}
		out = append(out, m)
	}
	return out
}

// jsonString renders a Go string as a JSON string without HTML escaping.
//
// encoding/json escapes '<', '>' and '&' by default, which is the same default
// that makes a naive directory corrupt a stored envelope (§5.2). It would be an
// odd file that demonstrated the fault while committing it.
func jsonString(s string) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		// Unreachable: encoding a string cannot fail.
		return strconv.Quote(s)
	}
	return strings.TrimRight(buf.String(), "\n")
}

// decodeBase64URL is the file's one decoding entry point, so that Body.Bytes
// applies the same §4.4 strictness as the wire path.
func decodeBase64URL(s string) ([]byte, error) {
	return b64.Decode(s)
}

// encodeLookupID renders an identifier for the initial-state listing. It is
// there so a reader can see which record a fixture is talking about; nothing
// is driven from it.
func encodeLookupID(lookupID []byte) string {
	return b64.Encode(lookupID)
}

// padded returns the padded spelling of an unpadded base64url value.
//
// §4.4 requires padded input to be rejected as malformed rather than stripped,
// and names Java's Base64.getUrlEncoder and Python's urlsafe_b64encode as the
// reason an implementer will meet this first.
func padded(unpadded string) (string, error) {
	raw, err := b64.Decode(unpadded)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(raw), nil
}

// nonCanonical returns a spelling of the same 32 bytes whose final character
// carries non-zero unused bits.
//
// §4.4: "Where the encoded length does not correspond to a whole number of
// bytes, the unused low bits of the final character MUST be zero, and a value
// whose unused bits are non-zero MUST be rejected as malformed." A 32-byte
// value occupies 43 characters carrying 258 bits, so two of them decode to
// nothing and there are four spellings of every such value unless the rule is
// enforced.
func nonCanonical(canonical string) (string, error) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

	if canonical == "" {
		return "", fmt.Errorf("apivectors: cannot perturb an empty value")
	}
	last := canonical[len(canonical)-1]
	idx := strings.IndexByte(alphabet, last)
	if idx < 0 {
		return "", fmt.Errorf("apivectors: value is not base64url")
	}
	if idx&0x03 != 0 {
		return "", fmt.Errorf("apivectors: value is already non-canonical")
	}
	return canonical[:len(canonical)-1] + string(alphabet[idx|0x01]), nil
}

// insufficientPoW returns an 8-byte counter that does not satisfy PoWBits for
// the given identifier and expiry.
//
// It searches upward from zero rather than assuming that zero fails, so the
// generator cannot produce a fixture that accidentally satisfies the challenge
// it is meant to violate.
func insufficientPoW(lookupID []byte, expiresAt int64) []byte {
	value := make([]byte, pow.Len)
	for i := uint64(0); ; i++ {
		binary.BigEndian.PutUint64(value, i)
		if !pow.Verify(lookupID, expiresAt, value, PoWBits) {
			out := make([]byte, pow.Len)
			copy(out, value)
			return out
		}
	}
}

// storedRecord is one pre-loaded record: the publisher behind it, and the exact
// bytes the directory received.
type storedRecord struct {
	id        string
	note      string
	publisher *publisher
	expiresAt int64
	body      string
}

// sortStored orders records by lookup_id, which is the ordering §5.3
// RECOMMENDS for a response and the ordering this reference implementation
// uses. The order of `records` is not significant and clients MUST NOT depend
// on it; the expected bodies in this file are written in it because a byte
// comparison needs some order, and each fixture says so.
func sortStored(recs []storedRecord) {
	sort.Slice(recs, func(i, j int) bool {
		return bytes.Compare(recs[i].publisher.lookupID, recs[j].publisher.lookupID) < 0
	})
}

// recordsBody assembles the §5.3 response around the stored bytes.
//
// It concatenates rather than marshalling, which is the same construction §5.2
// requires of a directory and for the same reason: embedding stored bytes in a
// structure and serialising it re-encodes them.
func recordsBody(recs []storedRecord) string {
	var b strings.Builder
	b.WriteString(`{"records":[`)
	for i, r := range recs {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(r.body)
	}
	b.WriteString(`]}`)
	return b.String()
}

// matchingRecords returns the records whose lookup_id begins with the given
// hex prefix, masked to bits per §5.3.
//
// The masking is implemented here rather than borrowed from internal/query, so
// that the expected bodies in this file are an independent statement of the
// rule rather than a restatement of the code being tested.
func matchingRecords(recs []storedRecord, prefixHex string, bits uint) ([]storedRecord, error) {
	// The errors below name the failure mode and never the prefix. A lookup
	// prefix is exactly the value the no-logging requirement exists to protect,
	// and a build-time tool is not a reason to keep a code path that formats
	// one.
	if uint(len(prefixHex)) != (bits+3)/4 {
		return nil, fmt.Errorf("apivectors: prefix length is not ceil(bits/4) characters")
	}

	full := make([]byte, (bits+7)/8)
	for i := 0; i < len(prefixHex); i++ {
		v, ok := hexNibble(prefixHex[i])
		if !ok {
			return nil, fmt.Errorf("apivectors: prefix contains a character outside the hex alphabet")
		}
		if i%2 == 0 {
			full[i/2] |= v << 4
		} else {
			full[i/2] |= v
		}
	}
	if spare := uint(len(full))*8 - bits; spare > 0 {
		full[len(full)-1] &^= byte(1)<<spare - 1
	}

	out := []storedRecord{}
	for _, r := range recs {
		if matchesPrefix(r.publisher.lookupID, full, bits) {
			out = append(out, r)
		}
	}
	return out, nil
}

func matchesPrefix(lookupID, full []byte, bits uint) bool {
	whole := bits / 8
	if !bytes.Equal(full[:whole], lookupID[:whole]) {
		return false
	}
	if rem := bits % 8; rem != 0 {
		mask := byte(0xFF) << (8 - rem)
		if full[whole]&mask != lookupID[whole]&mask {
			return false
		}
	}
	return true
}

func hexNibble(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// channelID returns the nth deterministic 32-byte channel identifier, spelled
// canonically per §4.4.
func channelID(n uint32) string {
	var idx [4]byte
	binary.BigEndian.PutUint32(idx[:], n)

	h := sha256.New()
	h.Write([]byte(channelDomain))
	h.Write(idx[:])
	return b64.Encode(h.Sum(nil))
}
