# Security notes

## Trust map

| Boundary | Trust level | Notes |
|---|---|---|
| Caller to PolicyRegistry / EvidenceRegistry | Untrusted | Any address can register a policy or evidence record. This is by design; the policy and evidence themselves carry no authority, only the claims and adjudications built on top of them do. |
| PolicyRegistry / EvidenceRegistry to ClaimEngine | Partial | ClaimEngine trusts that a policy or evidence commitment returned by `verify_commitment` genuinely matches what the registrant submitted. It does not trust the registrant's own description of that content. |
| ClaimEngine to ProcessGraph | Partial | ProcessGraph trusts ClaimEngine's recorded `state`, `process_commitment`, `policy_commitment`, and predicate fields, all read through `.view()`. It re-derives the expected process commitment itself (`commit_process(...)`) rather than trusting a caller-supplied value. |
| Off-chain evidence content (URI) | Untrusted until fetched and hash-checked | The retrieval hint URI is never trusted on its own. `ClaimEngine.adjudicate_claim` fetches the content, hashes it, and rejects (`HASH_MISMATCH`, verdict UNKNOWN) if it does not match the committed `artifact_hash`. Only after that check does the content reach the LLM predicate evaluation. |
| LLM validator verdict | Trusted only through consensus | The verdict returned by the equivalence-principle-wrapped LLM call is trusted because GenVM validators must agree on it, not because any single validator's output is trusted. |
| Caller-supplied `now` | Trusted, not verified | See "Caller-supplied time" below. This is the one place a caller's own input is treated as ground truth without a matching consensus or hash check. |

## Caller-supplied time

`gl.block.timestamp` does not exist in the pinned GenVM build used by this system (see
`KNOWN_ISSUES.md`). There is no other deterministic source of wall-clock time available to
contract code in this build. As a result, every place that would otherwise read the chain's
current time now takes an explicit `now: u64` argument supplied by the transaction's caller:
`ClaimEngine.register_claim`, `adjudicate_claim`, `expire_claim`, and `ProcessGraph.create_process`,
`commit_process`, `finalize_process`.

This is a real, intentional widening of what the caller is trusted with, not merely a signature
change. A caller can supply an incorrect `now` (too early or too late) for their own transaction.
Concretely:

- A claim's `asserted_at` and a process's `created_at` / `committed_at` / `finalized_at` reflect
  whatever the caller claimed at call time, not a consensus-backed clock.
- Evidence freshness checks (`evidence_max_age_seconds`, compared in `adjudicate_claim`) can be
  defeated by a caller who supplies a `now` close to the evidence's `submitted_at`, regardless of
  how much real time has actually passed.

This risk is bounded by two things: the caller is only ever misleading their own transaction (a
false `now` does not let a caller forge someone else's claim or process timeline), and the same
trust decision was already made, independently, by this codebase's own `EvidenceRegistry.commit_evidence`,
which has always taken `submitted_at` as a plain caller-supplied argument. If this system moves to
an environment where `gl.block.timestamp` (or an equivalent consensus-backed clock) becomes
available, replace all six `now` parameters with that instead and remove this section.

## Deposit and settlement model

`ClaimEngine.register_claim` is payable and requires `gl.message.value >= min_deposit` for the
claim's policy. `adjudicate_claim` settles the deposit exactly once (`deposit_settled` guards
against double settlement): a TRUE or FALSE verdict refunds the depositor via the withdrawable
balance mechanism; an UNKNOWN or EXPIRED outcome forfeits the deposit to the protocol sink. Only
`admin_address` can withdraw the protocol sink (`withdraw_protocol_sink`). Ordinary depositors pull
their own refund through `withdraw()`, which zeroes their withdrawable balance before sending value
out, avoiding reentrancy through the standard checks-effects-interactions ordering.

## Immutability boundaries

- A policy version, once registered, cannot be mutated (`register_policy` refuses to overwrite an
  existing `(policy_id, version)` pair). Only `active` can change later, through `set_active`.
- An evidence record's content fields are immutable once committed. The retrieval hint URI is
  stored on the record but is not part of the hashed content, so if a URI turns out to be
  unreachable or wrong, the fix is to commit a new evidence record with the same content fields and
  a corrected URI (this produces the same `evidence_commitment` but a new `evidence_id`), not to
  edit the existing record.
- A claim, once registered, is identified by the hash of its own content (`claim_hash`); there is
  no update path, only new registration. `register_claim` refuses to create a claim whose content
  hash already exists (`claim_id collision on registration`).
- Once a `ProcessGraph` process is committed (`commit_process`), its structure is fixed; nodes and
  claim slots cannot be added after that point.

## Graph integrity checks

`commit_process` validates, before allowing activation, that the graph has no cycles
(`_has_cycle`), that its depth does not exceed the policy's `max_graph_depth`, that its node and
edge counts do not exceed `max_graph_nodes` / `max_graph_edges`, and that every child reference
points at a node that actually exists in the same process. A process cannot be finalized while any
claim slot reachable from the root is still `OPEN` (unbound, or bound to a claim whose adjudicated
state is not yet TRUE or FALSE).

## Checklist this system was reviewed against

- Unauthorized actor: policy/evidence registration is intentionally permissionless; claim
  adjudication and process advancement (`refresh`-style calls) are permissionless by design, since
  restricting them would create a liveness risk (whoever benefits from delay simply never calls),
  without adding security, because the outcome is fully determined by already-committed state, not
  by the caller. Only `set_active` and `withdraw_protocol_sink` are admin-gated, because those are
  the only two operations that affect other parties' outcomes without being fully determined by
  prior consensus.
- Malformed or malicious input: every `bytes` and `Address` typed argument is defensively coerced
  (`_coerce_bytes`, `_coerce_address`) before use, rejecting values that cannot be interpreted as
  the expected type. `predicate_unit`, `scope`, `node_type`, and predicate type strings are all
  validated against a fixed enum before being trusted.
- Replay and duplication: claim registration is content-addressed, so replaying the same
  `register_claim` call is a no-op (rejected as a collision), not a duplicate charge. Evidence
  commitments are similarly content-addressed for the parts that matter to hashing.
- Conflicting or stale evidence: `adjudicate_claim` always fetches evidence content fresh at
  adjudication time and hash-checks it against the commitment made at evidence-registration time;
  it never trusts a cached or previously-fetched copy.
- Economic failure: see "Deposit and settlement model" above; no double payout and no unsettled
  deposit path was found once `deposit_settled` was in place.

## Out of scope for this version

- `scope` values other than `"PROCESS"` (`"POLICY"`, `"GLOBAL"`) are defined in the enum but
  explicitly rejected in `register_claim`. Do not enable them without designing the authority model
  they would need first.
- Predicate types other than `QuantityAtLeast` / `QuantityEquals` are defined but not exercised
  end to end in `TEST_RESULTS.md`. Review `build_proposition_template` and the adjudication prompt
  for each before relying on them.
- `router_address` / registry addresses are immutable per deployment; there is no on-chain registry
  upgrade mechanism. A compromised or deprecated dependency requires a fresh deployment of every
  contract that pointed at it.
