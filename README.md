# TSPG (Trust Semantic Process Graph)

TSPG is a four-contract GenLayer Intelligent Contract system for registering, adjudicating, and
graph-composing claims whose truth depends on off-chain evidence and natural-language predicates.
Adjudication is performed by LLM validator consensus under GenVM's equivalence-principle model, not
by deterministic parsing, which is the reason this system needs GenLayer rather than a conventional
EVM contract.

This document describes the system as of the post-audit revision, after a security review found
13 issues across the four contracts (10 fixed or mitigated, 3 accepted as documented open risks)
and after a full round of live testing against GenLayer Studio surfaced and fixed a further set of
environment-specific defects. Every claim in this document was verified against a live Studio
deployment; none of it is asserted from reading the source alone. See `TEST_RESULTS.md` for the
exact run that backs the end-to-end claims below.

## What the system does

A caller registers a **policy**: the rules any claim under it must satisfy (which predicate types
are allowed, minimum validator count, evidence freshness window, deposit size, graph size limits).
A caller separately registers **evidence**: a content-addressed commitment to an off-chain artifact,
plus a URI hinting where to fetch it. A caller then registers a **claim**: an assertion, tied to a
policy and a piece of evidence, expressed as a predicate such as "quantity delivered is at least
500 items". Anyone may trigger **adjudication**: the contract fetches the evidence content through
GenVM's non-deterministic web fetch, hash-checks it against the commitment made at evidence
registration time, and if it matches, asks the validator set to judge the predicate against that
content under consensus. The result (`TRUE`, `FALSE`, or `UNKNOWN`) is recorded on-chain and a
deposit is settled accordingly.

Claims can be composed into a **process graph**: `AND` / `OR` / `NOT` / `THRESHOLD` nodes whose
leaves are claim slots. A slot resolves once a claim bound to it reaches a final adjudicated state,
subject to a dispute window described below. A process can only be finalized once every claim slot
reachable from the root has fully resolved.

## Contracts

| Contract | File | Responsibility |
|---|---|---|
| PolicyRegistry | `policy_registry.py` | Immutable versioned policies: predicate rules, validator count, evidence freshness rules, deposit size, graph size limits. |
| EvidenceRegistry | `evidence_registry.py` | Content-addressed evidence records: artifact hash, size, mime type, retrieval hint URI, submission time. |
| ClaimEngine | `claim_engine.py` | Claim lifecycle: registration, deposit handling, LLM adjudication against fetched evidence, withdrawal of deposits and protocol fees. |
| ProcessGraph | `process_graph.py` | Boolean composition of claims into a directed graph, slot binding with a bond-escalation dispute window, and final result evaluation. |

Only `ClaimEngine` moves value (claim deposits and the protocol sink). `PolicyRegistry`,
`EvidenceRegistry`, and `ProcessGraph` are not payable.

## Trust and cross-contract wiring

`ClaimEngine` reads policy and evidence data from `PolicyRegistry` and `EvidenceRegistry` through
read-only cross-contract calls (`gl.get_contract_at(...).view()`). `ProcessGraph` reads claim data
from `ClaimEngine` the same way. None of the four contracts ever writes into another; every
cross-contract call is a `.view()` read. The dependency graph is a strict DAG: `PolicyRegistry` and
`EvidenceRegistry` have no dependencies; `ClaimEngine` depends on both; `ProcessGraph` depends on
`PolicyRegistry` and `ClaimEngine`.

Each contract's dependency addresses are set once at construction and are immutable for the life of
that deployment. Deploying against the wrong registry, or replacing a registry later, requires a
fresh deployment of every contract that pointed at it, and a full re-run of every step from policy
registration onward. See `DEPLOYMENT.md`.

## What changed in the post-audit revision

Before the audit, four issues were found and fixed while writing the test suite: no `tests/`
directory existed (78 tests added), a lint rule against bare `except Exception` / bare
`raise Exception` was violated throughout (all four contracts now raise `gl.vm.UserError` instead),
caller-supplied `now` values had no bounds at all (monotonicity checks added in five places), and
`evidence_freshness_on_expiry` was only validated when a policy's `evidence_max_age_seconds` was
greater than zero, so an invalid value on a freshness-disabled policy surfaced as a raw, uncaught
`ValueError` instead of a clean rejection.

During the audit itself, nine further findings were reviewed. Six were fixed or mitigated:
unauthorized `invalidate_claim` calls (now restricted to the claim's own submitter), slot-squatting
via a decorative `authority_commitment` (mitigated with a bond-escalation dispute window, described
below, not eliminated), a decorative `predicate_rules` field that was stored and hashed but never
checked (`ClaimEngine.register_claim` now calls the new `PolicyRegistry.get_predicate_rules`), a
narrow deadlock in `expire_claim` when a policy disabled evidence freshness entirely (fixed; a
broader version of this finding was raised and disputed, and was not confirmed), conflation of two
distinct claim outcomes under the identical string `"INVALIDATED"` (now distinguished via
`ClaimState.EXPIRED`), and a missing range check on `predicate_value` for quantity predicates (now
rejects negative values). Three findings were reviewed and left open, by decision, as documented
risks rather than silently ignored: a decorative `min_unique_validators` field (GenVM's own
validator-set sizing is not currently controllable per-policy from contract code), an unverified
native-transfer call path in `ClaimEngine._send_native` (needed live confirmation before any fix
could be trusted; see `KNOWN_ISSUES.md` and `SECURITY.md`), and `admin_address` as a single point of
failure (an architecture change was out of scope for this round, by the project owner's decision).

The dispute window mentioned above works as follows: the first claim to reach a `TRUE` or `FALSE`
verdict and bind to an open slot does not resolve it immediately. It opens a fixed window
(`DISPUTE_WINDOW_SECONDS = 3600`) during which a different, already-adjudicated claim can displace
it, but only by posting a strictly larger deposit. `ProcessGraph.finalize_slot` locks the slot in as
resolved once the window has elapsed unchallenged. This raises the cost of winning a slot with
self-hosted, unverified evidence; it does not eliminate the risk, since a well-funded attacker can
still outbid every legitimate challenger.

## Post-audit runtime findings

Live testing after the audit surfaced one further issue, found and fixed in this round rather than
during the audit itself: `ClaimEngine.register_claim` is a payable method, and value attached to a
call is delivered to the contract before any of the method's own validation logic runs. GenVM's
execution model is atomic: if the method later rejects the call by raising, the entire execution,
including any attempt to send that value back, is rolled back, while the incoming delivery of value
is not, because it happens outside the scope of what GenVM's rollback undoes. The practical effect
was that any rejected `register_claim` call permanently forfeited its attached deposit with no
record anywhere that it was owed. The fix changes every validation failure in `register_claim` from
`raise` to `return` of a string prefixed `"REJECTED: "`, crediting the sender's `withdrawable`
balance first. This is a real change to the method's calling convention: **`register_claim` no
longer raises for a business-logic rejection; callers must check whether the returned string starts
with `"REJECTED: "` rather than relying on an exception.** See `SECURITY.md`, "Value delivery and
rejected payable calls", for the full explanation, and `KNOWN_ISSUES.md` for everything else found
in this same round (storage-construction limits in the pinned GenVM build, calldata encoding
quirks in GenLayer Studio, the absence of an on-chain clock, and the still-unresolved native-transfer
question).

## Documents in this repository

- `DEPLOYMENT.md`: constructor arguments, required deployment order, and what to do when
  redeploying any of the four contracts.
- `SECURITY.md`: the trust map, the caller-supplied-time model, the deposit and settlement model
  including the reject-and-refund pattern above, the dispute window, and the full list of accepted
  and open risks.
- `KNOWN_ISSUES.md`: environment-specific defects found in the pinned GenVM build
  (`py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6`) and in GenLayer Studio's
  calldata handling, each with the workaround applied in the contract source.
- `TESTING.md`: a complete field-by-field reference for every public method across all four
  contracts, cross-field constraints that Studio's form does not enforce, and a set of adversarial
  test cases.
- `TEST_RESULTS.md`: the actual end-to-end test run performed against a live GenLayer Studio
  deployment of the post-audit contracts, with every value used and every result observed.

## Predicate types

`ClaimEngine` implements one predicate family end to end and verified live: `QuantityAtLeast` and
`QuantityEquals`, over a fixed unit set (`GRAMS`, `KG`, `ITEMS`). `DateBefore`, `DateEquals`,
`AttributeEquals`, and `ArtifactContains` are defined in the enum and have prompt-building logic,
but have not been exercised end to end in this project's testing. Confirm their behavior before
relying on them.

## Status

All four contracts have been deployed to GenLayer Studio and exercised end to end more than once
after the audit, including a real LLM adjudication returning `VERDICT:TRUE` against real off-chain
content, the new dispute-window flow (`bind_slot` to `PENDING`, `finalize_slot` to `RESOLVED`), and
`finalize_process` returning `TRUE`. The one remaining unresolved question is whether
`ClaimEngine.withdraw()` and `withdraw_protocol_sink()` actually move native value to a wallet
address in this environment; see `SECURITY.md` for what was tested and why the result is
inconclusive rather than negative.
