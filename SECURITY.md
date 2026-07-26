# Security policy

## Scope, and which finding is worth more

This repository is the reference implementation. **A flaw in the specification
is more serious than a flaw in this code.**

A bug here affects instances running this binary, and a release fixes it. A
specification flaw affects **every** implementation — including ones nobody has
written yet — and cannot be fixed by a release. If your finding is in the
protocol rather than in this code, report it against
[trigstation/spec](https://github.com/trigstation/spec) and **say so in the
subject line**. Those reports are especially welcome.

Things worth looking at hardest in this repository:

- Anything that causes a client address, lookup prefix, channel identifier or
  request URI to reach an output stream, a file or a log — including through a
  dependency, the Go runtime, or the shipped proxy configuration. The
  no-logging property is the one this service is least able to survive losing.
- The trusted-proxy handling in `internal/clientaddr`, where a mistake turns
  rate limiting into either an outage or a bypass.
- The acceptance pipeline in `internal/accept` and the evaluation order it
  implements, where a wrong order can admit an envelope that should have been
  refused.
- Verbatim storage in `internal/store` and `internal/api` — anything that lets a
  stored envelope be altered between publish and lookup.
- The signal channel store, where first-write-wins is a security property and
  not an error case.

Note that the directory is **assumed hostile** by the protocol's own threat
model (§8): a malicious directory can deny service but cannot impersonate a
server or read a record. A finding is more interesting if it breaks that
boundary than if it demonstrates a directory behaving badly within it.

## Reporting

**security@trigstation.com.** Please do not open a public issue for a suspected
vulnerability.

You will get an acknowledgement within **7 days**. This is a personal project
maintained by one person in New Zealand, and response times reflect that — if
you have not heard back within 7 days, please send a reminder rather than
assuming the report was received. Mail goes astray, and a silent maintainer is
more often an unlucky one than an unresponsive one.

## Disclosure

Coordinated, with a **90-day window** from acknowledgement or until a fix is
released, whichever is sooner.

If a fix will take longer than that, you will be told so explicitly and told
why. You will not be left waiting on silence and then asked for an extension at
day 89.

## What is offered

There is **no bug bounty** and no payment. This is an unfunded personal project
and pretending otherwise would waste your time.

Credit in the changelog and the release notes is offered to anyone who wants it,
under whatever name or handle you prefer, and it is equally fine to stay
anonymous.
