# Phase reports

One report per phase boundary. Each records the spec ambiguities raised, the
errors found, the judgement calls made, the dependencies added, the verification
output actually run, and what was left undone.

Reports are a historical record. They describe the tree as it stood when they
were written and are not updated afterwards — where a report's description of the
layout disagrees with the current tree, the tree is right and the report is a
snapshot.

| Report | Covers |
|---|---|
| *(phase 1 — missing, see below)* | Key derivations, envelope and payload handling, proof of work, base64url, first test vectors |
| [phase-1b.md](phase-1b.md) | Reconciliation against the amended `DIRECTORY-SPEC.md`; detached payload signature; pairing vectors |
| [phase-2-preflight.md](phase-2-preflight.md) | Fresh-eyes spec review before phase 2: eight rulings sought, five editorial errors, sub-agent breakdown |
| [phase-2-questions.md](phase-2-questions.md) | Eighteen further questions raised while building phase 2, each with a recommendation and a patch |
| [phase-2.md](phase-2.md) | Storage, the four operations, deployment. The service runs. |

## The missing phase 1 report

There is no `phase-1.md`. It was not misplaced — it was never written to this
tree, and it has deliberately not been reconstructed after the fact. An invented
record is worse than an acknowledged gap: the value of these reports is that they
say what was actually considered at the time, and a retrospective one would
quietly launder later knowledge into an earlier date.

`phase-1b.md` carries phase 1's substantive outcomes. Its opening section states
that every ambiguity raised in phase 1 was accepted into the spec, and its §3
diffs the phase 1 test vectors field by field, so the phase 1 decisions are
recoverable from it and from `DECISIONS.md` in the `spec` repo.
