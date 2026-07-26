# CLAUDE.md — trigstationd

Reference implementation of the Trigstation directory service.

## Read CONTRIBUTING.md first

**[CONTRIBUTING.md](CONTRIBUTING.md) is the normative statement of what this
project requires.** The design invariants, the no-logging rule and where its
boundary falls, `CGO_ENABLED=0`, four operations and not five, the dependency
budget, the testing conventions, the licence headers and the house style all
live there and are not repeated here.

They are project constraints, not agent constraints. A human contributor is
bound by them exactly as much, and they used to live in this file — which was
the wrong home, because a human reading a file addressed to an AI could
reasonably assume it was somebody else's problem.

What follows is only the part that is specific to working here as an agent.

---

## The spec is authoritative, and you do not have spec authority

`DIRECTORY-SPEC.md` and `PAIRING-SPEC.md` live in the `spec` repository. They
define the wire format; this repository implements it. **Where code and spec
disagree, the spec is right and the code is a bug.**

You do not get to resolve protocol questions. Simon does.

This matters more than anything else here. The value of this project is not that
the code got written — it is that every ambiguity was resolved deliberately,
written back into the specification, and recorded in `DECISIONS.md` with its
reasoning and its rejected alternatives. That is what makes design goal 3 —
anyone can reimplement this from the spec in a weekend — true rather than
aspirational.

Resolve ambiguities silently in code and the spec drifts from the
implementation, the vectors stop meaning anything, and the project quietly
becomes "whatever trigstationd happens to do". That failure is invisible until
somebody tries to write a second implementation and cannot.

### So when the spec does not settle something

1. **Stop that work item.** Do not pick something reasonable and continue.
2. Write up the question: spec section, what is underspecified, the options,
   what breaks if two implementations choose differently, and your
   recommendation with reasoning.
3. Prepare a concrete spec patch as a diff — the actual wording, not a
   description of it.
4. Bring it to Simon.
5. On approval: apply the patch, append to `DECISIONS.md` in the existing
   format, regenerate affected vectors, then resume.

Batch these. Ten questions at one stopping point is far better than ten
interruptions.

### You may decide freely, without asking

Package layout, error handling shape, test structure, naming, file organisation,
sub-agent task breakdown, and anything else that does not change observable
behaviour or the wire format. Record structural choices in your report; do not
ask permission for them.

---

## After a spec amendment: re-audit, then continue

Covered in CONTRIBUTING.md, repeated here because it is the step most likely to
be skipped under momentum.

Applying a spec patch is not the end of a ruling. Audit **every** existing
package against **every** amendment in the batch, and put the audit in your next
report as a table of amendment against package checked. A table reading "no
change needed" in most cells is the evidence the audit happened.

Three of eighteen amendments were once missed this way and found later by luck.

---

## Reporting

Stop at each phase boundary, and any time you accumulate spec questions.

**To disk** — `docs/reports/<phase>.md`: spec ambiguities with a proposed patch
for each, spec errors, judgement calls, dependencies added, verification output,
and what is not done.

**To the terminal** — one screen: what was completed, what is blocked and on
which decision, and the build/test verdict. Simon reads the file for detail.

Commit as you go, with `git commit -s` per the DCO.

---

## Two standards worth holding

**Verify, do not assert.** Never claim a build or test passes without having run
it and seen the output. Query the registry, read the file, run the command. This
applies to claims about other people's software too — the Caddy error-log
behaviour that turned out to leak client addresses was found by reproducing it
with a control, not by reading documentation.

**Prove a test can fail.** Where a test guards something that matters, break the
thing deliberately, confirm the test catches it, and restore. A test that cannot
fail reads as coverage while providing none. This has already caught a false
negative in this repository: a verification run that came back clean for both
arms of an A/B, because a mangled path meant neither configuration had loaded.
A symmetric result that looks like evidence is the most expensive thing in a
verification exercise.

---

## Working with Simon

- Solo developer, limited evening time. Be realistic about scope, and say
  plainly when something is a multi-month commitment rather than a session.
- Be direct. Push back on bad ideas, name trade-offs explicitly, and state
  honest limitations rather than presenting work as airtight.
- Prefer concrete specification over architecture talk — byte layouts, endpoint
  contracts, failure modes.
- Do not re-explain settled decisions back to him. `DECISIONS.md` is the record;
  if you think one is wrong, say so once with a concrete new argument and let
  him decide.

---

## Provenance

This project was built with substantial AI assistance, and this file is part of
the record of how. It is kept rather than removed because hiding it would be
dishonest, and because the reasoning in the specification and `DECISIONS.md`
stands or falls on its own merits regardless of who typed it.
