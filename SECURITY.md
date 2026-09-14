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

**Partial mitigation applied (monotonicity, not verification).** `now` still cannot be checked
against real wall-clock time -- that requires a clock this build does not have, full stop. What
*can* be checked, and now is: `now` cannot move backwards relative to a fact this contract already
committed to earlier, specifically --

- `ClaimEngine.register_claim` rejects a `now` earlier than the referenced evidence's own
  `submitted_at` (a claim cannot assert evidence from before that evidence existed).
- `ClaimEngine.adjudicate_claim` and `expire_claim` both reject a `now` earlier than the claim's
  own `asserted_at`.
- `ProcessGraph.commit_process` rejects a `now` earlier than the process's own `created_at`;
  `finalize_process` rejects a `now` earlier than `committed_at`.

This closes the specific "supply a `now` close to `submitted_at` to defeat freshness, then later
supply an even earlier `now` to a different call on the same entity" shape of the gap. It does
**not** close the gap described above at all: `register_claim`'s own `now` (and `create_process`'s)
is still entirely caller-asserted against nothing, since it is the first timestamp recorded for
that entity and there is nothing earlier of this contract's own to check it against. A caller who
lies consistently, in the same direction, across every call for one entity is not caught by this.
Treat this as raising the cost of gaming freshness, not as removing the trust assumption.

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

## External audit findings (session 2026-09-14)

An external review (framed against a "master prompt" checklist covering state machine,
authority model, trust map, consensus, external evidence, and economic/failure analysis) found
9 issues. Each was independently re-verified against the actual code before any fix was applied
-- not accepted on the auditor's word alone. Status of each:

**#1 [FIXED, was CRITICAL] `invalidate_claim` had no sender check at all.** Verified: confirmed
by grep, zero `gl.message.sender_address` references in the function. Any address could
invalidate any other party's already-consensus-reached `TRUE` claim. Fixed: restricted to
`stored.submitter`. This is a minimum-viable fix (closes "any address, no interest required"),
not a real dispute-resolution mechanism -- there still isn't one. A contested revocation still
has no independent adjudication path.

**#2 [PARTIALLY MITIGATED, was CRITICAL] Slot-squatting via permissionless `bind_slot` +
decorative `authority_commitment`.** Verified: `bind_slot`'s own docstring said "Deliberately
PERMISSIONLESS"; `authority_commitment` is stored and hashed but never checked anywhere. Real
attack: register a claim against self-hosted, self-consistent evidence, win the race to
`bind_slot` before the legitimate submitter. Mitigated with a bond-escalation dispute window
(`DISPUTE_WINDOW_SECONDS`, see `bind_slot` / new `finalize_slot`): a `TRUE`/`FALSE` binding no
longer resolves a slot immediately -- it opens a window during which a different claim can
displace it, but only with a strictly larger deposit; the window resets on every successful
challenge. `finalize_slot` locks the slot in once the window closes unchallenged.
`_collect_open_slots_reachable` and `_evaluate_node` were both updated so a `PENDING` slot
correctly blocks `finalize_process` and reads as `UNKNOWN` from `evaluate()`, not as an already-
settled result. This raises the cost of the attack; it does not eliminate it -- a well-funded
attacker can still win by outbidding every legitimate challenger. `authority_commitment` itself
remains unverified (would require a trusted oracle/signer design this fix does not attempt).

**#3 [FIXED] `predicate_rules` was decorative.** Verified: `grep predicate_rules` outside
`policy_registry.py` returned nothing -- stored and hashed, never read by `ClaimEngine` or
`ProcessGraph`. Fixed: added `PolicyRegistry.get_predicate_rules` (did not exist before) and
`register_claim` now rejects any `predicate_type` not in the policy's own whitelist, not just
the global `PredicateType` enum.

**#4 [NOT FIXED, accepted as-is] `min_unique_validators` remains decorative.** Verified: same
grep result as #3, nothing outside `policy_registry.py` reads it. Left alone, deliberately,
unlike #3 -- the actual validator quorum for `gl.eq_principle.strict_eq` is a GenVM network-level
parameter, not something contract code can observe or enforce at the point a claim is
adjudicated. There is no cross-contract call that could verify it even if we tried. Either
remove the field from `PolicyRegistry`'s schema (breaking change, re-versions every existing
policy's commitment) or document it plainly as informational-only, not enforced. Left as a
known limitation rather than guessing at a removal the schema owner hasn't asked for.

**#5 [FIXED, narrower form confirmed correct] `expire_claim` gated `stuck_adjudicating` on
`evidence_max_age_seconds`.** The original finding's premise (a claim gets permanently "stuck"
mid-state if consensus never converges) does not hold -- GenVM transactions are atomic, so a
non-converging `gl.eq_principle.strict_eq` round rolls the whole `adjudicate_claim` call back;
the claim stays honestly `REGISTERED`, retriable indefinitely. The real, narrower bug survived
that correction: `expire_claim`'s `stuck_adjudicating` recovery path was gated on the *same*
`max_age` as evidence staleness, so `max_age == 0` (a legitimate, independent policy choice --
"I don't want freshness checking") also silently meant "a claim that can never actually
adjudicate, e.g. a permanently dead `retrieval_hint_uri`, can never be expired, ever" -- a
process-wide liveness bug with no logical connection to what the policy author opted into.
Fixed: `stuck_adjudicating` now uses its own fixed `STUCK_ADJUDICATION_TIMEOUT_SECONDS` (3600),
independent of the policy's freshness configuration.

**#6 [OPEN, needs live verification, not code-fixable blind] `_send_native`'s `emit_transfer`
call is unverified against a real GenVM node.** Verified: the code comment itself says so
(`"Call-site unverified against a live GenVM node"`). This was already known before the audit
(it's the author's own comment) -- the audit correctly escalated it to a stop-condition-level
concern rather than letting it slide into `TEST_RESULTS.md` as passed. Not fixed here: there is
no correct fix to write without first confirming, live on Studio, what `emit_transfer`'s actual
signature and effect are. Recommended next step: deploy, deposit, call `withdraw()`, and observe
whether native value actually moves before trusting this path with real funds.

**#7 [FIXED] `FreshnessOnExpiry.INVALIDATED` and `ClaimState.INVALIDATED` were the same literal
string.** Verified: both enums define `INVALIDATED = "INVALIDATED"`. `ProcessGraph.bind_slot`
could not distinguish "evidence went stale before adjudication finished" from "a `TRUE` verdict
was later revoked by its own submitter" -- both produced the identical `ClaimState` value. Fixed
by routing evidence-driven expiry through the previously-defined-but-never-assigned
`ClaimState.EXPIRED` instead (see `_claim_state_for_expiry` in `claim_engine.py`);
`ProcessGraph.bind_slot` now checks for `INVALIDATED` and `EXPIRED` explicitly. Behavior
(`allow_revocation_retry` gating the slot's OPEN/LOCKED outcome) is unchanged for both -- this
fix is about making the two cases distinguishable in claim state history, not about changing
what happens to the slot.

**#8 [FIXED] No range validation on `predicate_value`.** Verified: `_require()` only checked
`is not None`, never sign or magnitude -- `"at least -500 GRAMS"` was accepted silently. Fixed:
`register_claim` now rejects `predicate_value < 0` for `QuantityAtLeast` / `QuantityEquals`,
before any cross-contract call.

**#9 [NOT FIXED, accepted risk, documented rather than re-architected] Single point of failure
in `admin_address`.** Set once in the constructor, immutable, no transfer-ownership / multisig /
timelock. The entire `protocol_sink` depends on one private key with no rotation path. This is a
real, accurate observation and a legitimate production concern -- but fixing it (ownership
transfer, multisig, or a timelock) is a genuine architecture decision with real trade-offs
(who holds the multisig keys, what timelock duration is acceptable), not a bug with one correct
answer. Recorded here explicitly as an accepted risk for this MVP rather than left implicit.
