# Security notes

## Trust map

| Boundary | Trust level | Notes |
|---|---|---|
| Caller to PolicyRegistry / EvidenceRegistry | Untrusted | Any address can register a policy or an evidence record. This is by design; neither carries any authority on its own, only the claims and adjudications built on top of them do. |
| PolicyRegistry / EvidenceRegistry to ClaimEngine | Partial | ClaimEngine trusts that a policy or evidence commitment returned by `verify_commitment` genuinely matches what the registrant submitted. It does not trust the registrant's own description of that content, and re-derives the commitment from stored content rather than accepting a caller-supplied one at face value. |
| ClaimEngine to ProcessGraph | Partial | ProcessGraph trusts ClaimEngine's recorded `state`, `process_commitment`, `policy_commitment`, and predicate fields, all read through `.view()`. It independently recomputes the expected process commitment itself (`commit_process(...)`) rather than trusting any caller-supplied value for that check. |
| Off-chain evidence content (URI) | Untrusted until fetched and hash-checked | The retrieval hint URI is never trusted on its own. `ClaimEngine.adjudicate_claim` fetches the content, hashes it, and rejects (result `UNKNOWN`, with the actual hash surfaced via the equivalence-principle output as `HASH_MISMATCH:<hash>`) if it does not match the committed `artifact_hash`. Only content that passes this check reaches the LLM predicate evaluation. |
| LLM validator verdict | Trusted only through consensus | The verdict returned by the equivalence-principle-wrapped LLM call is trusted because GenVM validators must agree on it under `gl.eq_principle.strict_eq`, not because any single validator's output is trusted on its own. |
| Caller-supplied `now` | Trusted, only partially checked | See "Caller-supplied time" below. |
| A claim's self-hosted evidence, during the dispute window | Provisionally trusted, contestable | See "Dispute window and slot-squatting" below. |

## Caller-supplied time

`gl.block.timestamp` does not exist in the pinned GenVM build used by this system (see
`KNOWN_ISSUES.md`). There is no other deterministic source of wall-clock time available to contract
code in this build. As a result, every place that would otherwise read the chain's current time
takes an explicit `now: u64` argument supplied by the transaction's caller: `ClaimEngine`'s
`register_claim`, `adjudicate_claim`, and `expire_claim`, and `ProcessGraph`'s `create_process`,
`commit_process`, `bind_slot`, `finalize_slot`, and `finalize_process`.

This is a real, intentional widening of what the caller is trusted with, not merely a naming
convention. A caller can supply an incorrect `now` for their own transaction. The post-audit
revision narrows, but does not close, the resulting gap by requiring `now` to be monotonic within
a single claim's or process's own lifecycle:

- `adjudicate_claim` and `expire_claim` reject a `now` earlier than the claim's own `asserted_at`
  (the `now` given at `register_claim` time).
- `commit_process` rejects a `now` earlier than the process's own `created_at`.
- `finalize_process` rejects a `now` earlier than the process's own `committed_at`.
- `register_claim` itself rejects a `now` earlier than the referenced evidence's own
  `submitted_at`, so a claim cannot assert evidence from what it claims is the future relative to
  when that evidence was recorded.

None of this checks `now` against real wall-clock time, which is impossible without an on-chain
clock in this build. What it prevents is a caller moving `now` backwards relative to a fact this
system already has independently, for their own claim or process. It does not prevent a caller from
advancing `now` arbitrarily far forward relative to real time. Concretely, this means:

- Evidence freshness checks (`evidence_max_age_seconds`) can still be defeated by a caller who
  simply supplies a large `now` at `adjudicate_claim` time, if that serves their purpose, or a
  small one close to the evidence's `submitted_at`, if that serves theirs; the monotonicity checks
  above stop the second case only relative to a claim's own prior `now`, not against a clock.
- The dispute window (`DISPUTE_WINDOW_SECONDS`, see below) is measured the same way: a caller
  controls the `now` they submit to `bind_slot` and `finalize_slot`, so the window's real-world
  duration is only as trustworthy as the caller's own `now` values are.

This risk is bounded in one respect: a caller is only ever able to mislead their own transaction's
view of time; there is no mechanism by which one caller's `now` forges a fact about a different
caller's claim or process. This trust decision was already made, independently, by this codebase's
own `EvidenceRegistry.commit_evidence`, which has always taken `submitted_at` as a plain
caller-supplied argument, before any of the monotonicity work above existed. If this system moves
to an environment where `gl.block.timestamp` or an equivalent consensus-backed clock becomes
available, replace every `now` parameter with that, and remove this section.

## Value delivery and rejected payable calls

`ClaimEngine.register_claim` is the only payable method in this system. Live testing after the
audit found that value attached to a call is delivered to the contract as part of accepting the
transaction, before any of the method's own Python logic runs. GenVM's execution model is atomic:
if the method later raises, the entire execution is rolled back, including any attempt made
during that same execution to send value back out. The incoming delivery of value is not rolled
back, because it is not something the reverting execution did; it already happened as part of
message delivery. The practical, confirmed effect: a `register_claim` call that attached value and
was then rejected by any validation check permanently forfeited that value, with no record
anywhere in contract state that it was owed to anyone.

The fix changes every validation failure inside `register_claim` from `raise` to `return` of a
string prefixed `"REJECTED: "`, after crediting the sender's `withdrawable` balance with the
attached value via a new `_credit_withdrawable` helper. This works specifically because returning
normally, rather than raising, is what allows GenVM to commit the state change (the withdrawable
credit) along with the rest of the execution. A caller can then recover the value with a separate,
later call to `withdraw()`.

This is a real change to the method's calling convention, not an internal detail: **`register_claim`
no longer raises for a business-logic rejection.** A caller or integration must check whether the
returned string starts with `"REJECTED: "` rather than relying on try/except or a reverted
transaction to detect failure. The only remaining ways `register_claim` can still revert the whole
transaction are genuinely exceptional conditions unrelated to business-logic validation (for
example, an unrecognized `predicate_type` string that fails coercion before the try path is
reached, or an out-of-gas condition), not any of the documented rejection reasons.

An escrow-style intermediate contract was considered and rejected as a fix for this problem. The
constraint that produces it, value and instructions arriving as a single atomic unit before
application logic runs, applies identically to any contract's own payable entry point, including a
dedicated escrow's. Moving the deposit-accepting code to a separate contract does not create a point
where validation can run before value is accepted; it only relocates the same constraint one
contract over, while adding a new trusted address, a new deployment dependency, and a larger attack
surface, for no corresponding benefit. The chosen fix, extending `register_claim`'s own rejection
paths to follow the same accept-then-credit pattern already used by `adjudicate_claim` and
`expire_claim` elsewhere in this same contract, addresses the actual root cause without adding a
new component.

This fix has not been confirmed to fully close the loop: it depends on `_send_native` actually
moving the credited value out of the contract when `withdraw()` is later called. See "Native value
transfer" below.

## Native value transfer

`ClaimEngine._send_native` is used by both `withdraw()` and `withdraw_protocol_sink()`. Its
implementation has been corrected through three confirmed, live-reproduced defects in this pinned
GenVM build, all fixed:

1. The recipient address string (`str(gl.message.sender_address)`) includes a `0x` prefix that
   `bytes.fromhex()` rejects outright. Fixed by stripping the prefix before decoding.
2. `gl.get_contract_at` requires an `Address` object, not raw `bytes` (`TypeError: address
   expected` otherwise). Fixed by wrapping the decoded bytes in `Address(...)`.
3. The `_ContractAt.emit_transfer` method in this build does not accept a positional amount
   argument (`TypeError: emit_transfer() takes 1 positional argument but 2 were given`). Fixed by
   calling it with the keyword argument `value=`, matching a pattern documented as working for
   native payouts to claimants in at least one independent, comparable GenLayer project.

After all three fixes, a live call to `withdraw()` returns `SUCCESS` and correctly reports the
withdrawn amount, and correctly zeroes the internal `withdrawable` ledger entry. However, the
receiving wallet's actual balance, observed directly in GenLayer Studio's account list, did not
increase by the withdrawn amount in testing. This result is inconclusive rather than a confirmed
negative, for two reasons. First, the exact call pattern used here matches a pattern an independent
GenLayer project's own documentation describes as its production method for paying claimants,
which argues the code is very likely correct. Second, GenLayer Studio is documented elsewhere as a
local, browser-based practice environment ("Studionet"), distinct from GenLayer's real test
networks (Asimov, Bradbury); it is plausible that Studio's simulated ledger does not fully
replicate the real value-settlement path that a genuine testnet or mainnet deployment would
exercise. This was not independently confirmed by testing on a real testnet as part of this
project. Treat `withdraw()` and `withdraw_protocol_sink()` as unverified for real fund movement
until confirmed on a network with a genuine settlement layer: a clean `SUCCESS` result from either
method does not, by itself, prove the recipient's balance changed.

A separate, deliberately not attempted fix is worth recording: an earlier attempt to use
`@gl.evm.contract_interface`, a pattern documented as the correct mechanism for EOA transfers in
other GenLayer material, failed because the `gl.evm` namespace does not exist in this exact pinned
build. The failure mode was severe: referencing a nonexistent attribute in a decorator crashes the
module at load time, which GenLayer Studio surfaces as "Could not load contract schema" for the
entire contract, not as a runtime error in the one affected method. This was reverted. Do not
reintroduce `gl.evm` or similarly speculative API surface without confirming it exists in the
exact pinned build first; a broken decorator at class-definition time takes down the whole
contract's schema, not just the one method being changed.

## Dispute window and slot-squatting

Evidence authenticity is not independently verified anywhere in this system:
`EvidenceContent.authority_commitment` is opaque and never checked against anything. A claim
satisfying a slot's predicate proves only that its self-hosted evidence is internally consistent
with that predicate, never that the evidence is genuine. Before this round of fixes, whichever
claim first reached a `TRUE` or `FALSE` verdict and called `bind_slot` won that slot permanently,
which made front-running a slot with fabricated but internally-consistent evidence a live risk with
no cost beyond the claim's own deposit.

The mitigation is a bond-escalation dispute window. A `TRUE`/`FALSE` binding moves a slot to
`PENDING` rather than `RESOLVED`, and starts a fixed window (`DISPUTE_WINDOW_SECONDS = 3600`). Any
other already-adjudicated claim may displace the pending one during that window, but only by having
posted a strictly larger deposit; each successful challenge resets the window. `finalize_slot`
locks the slot in as `RESOLVED` once the window elapses with no successful challenge.
`ProcessGraph.finalize_process` refuses to finalize while any reachable slot is `OPEN` or
`PENDING`, so a process cannot bypass an in-progress dispute.

This raises the cost of the attack; it does not eliminate it. A sufficiently well-funded attacker
can still win a slot by posting an arbitrarily large deposit that no legitimate challenger is
willing or able to match. The window length is a fixed constant, not currently policy-configurable,
to avoid re-versioning `PolicyRegistry`'s schema and commitment hash for this fix; a
per-policy-configurable window is a reasonable future improvement, not implemented here.

## Deposit and settlement model

`ClaimEngine.register_claim` requires `gl.message.value >= min_deposit` for the referenced policy,
or the call is rejected (see "Value delivery" above for what happens to the attached value in that
case). `adjudicate_claim` and `expire_claim` settle the deposit exactly once, guarded by
`deposit_settled`: a `TRUE` or `FALSE` outcome refunds the depositor via the withdrawable-balance
mechanism; an `UNKNOWN`, `EXPIRED`, or human-`INVALIDATED` outcome forfeits the deposit to the
protocol sink. Only `admin_address` may withdraw the protocol sink. Depositors pull their own
refund through `withdraw()`, which zeroes the withdrawable balance before attempting to send value
out, following checks-effects-interactions ordering to avoid a reentrancy path even though the
underlying transfer's actual reliability is separately unverified (see "Native value transfer"
above).

## Immutability boundaries

- A policy version, once registered, cannot be mutated; `register_policy` refuses to overwrite an
  existing `(policy_id, version)` pair. Only the `active` flag can change afterward, through
  `set_active`, restricted to the original registrant.
- An evidence record's content fields are immutable once committed. The retrieval hint URI is
  stored alongside the record but is not part of the hashed content, so correcting an unreachable
  or wrong URI means committing a new evidence record with identical content fields (which
  produces the same `evidence_commitment` but a new `evidence_id`), not editing the existing
  record. `set_state` only permits a fixed allow-list of lifecycle transitions and is restricted to
  the record's original creator.
- A claim is identified by the hash of its own content (`claim_hash`); there is no update path,
  only new registration. `register_claim` rejects (via the `"REJECTED: "` path) an attempt to
  create a claim whose content hash already exists.
- Once a `ProcessGraph` process is committed (`commit_process`), its node and edge structure is
  fixed; nodes and claim slots cannot be added afterward.

## Graph integrity checks

`commit_process` validates, before allowing activation, that the graph has no cycles, that its
depth does not exceed the policy's `max_graph_depth`, that its node and edge counts do not exceed
`max_graph_nodes` and `max_graph_edges`, and that every child reference points at a node that
actually exists in the same process. It additionally rejects committing against a policy version
that has been deactivated since the process was created. A process cannot be finalized while any
claim slot reachable from the root is `OPEN` or `PENDING`.

## Checklist this system was reviewed against

- **Unauthorized actor.** Policy and evidence registration are intentionally permissionless.
  Claim adjudication and slot/process advancement are permissionless by design: restricting them
  would create a liveness risk (whoever benefits from delay simply never calls) without adding
  security, since the outcome is fully determined by already-committed state, not by the caller.
  `set_active`, `invalidate_claim`, and `withdraw_protocol_sink` are the only three write methods
  that are access-restricted, because they are the only three operations that affect another
  party's outcome without being fully determined by prior consensus.
- **Malformed or malicious input.** Every `bytes` and `Address` argument is defensively coerced
  (`_coerce_bytes`, `_coerce_address`) before use, rejecting values that cannot be interpreted as
  the expected type; see `KNOWN_ISSUES.md` for why this is necessary in this environment.
  `predicate_unit`, `scope`, `node_type`, and predicate type strings are all validated against a
  fixed enum or allow-list before being trusted. `predicate_value` for quantity predicates is
  checked non-negative.
- **Replay and duplication.** Claim registration is content-addressed, so replaying an identical
  `register_claim` call is a no-op rejection (a `"REJECTED: "` collision result), not a duplicate
  charge, and the attempted deposit is credited back.
- **Stale or substituted evidence.** `adjudicate_claim` always fetches evidence content fresh at
  adjudication time and hash-checks it against the commitment made at registration time; it never
  trusts a cached or previously fetched copy. `bind_slot` independently re-verifies a claim's
  predicate, subject commitment, process commitment, and policy commitment against the slot's own
  definition before accepting it, rejecting predicate substitution.
- **Economic failure.** See "Deposit and settlement model" and "Value delivery" above. No double
  payout path was found once `deposit_settled` and the reject-and-refund pattern were both in
  place; the one remaining open question is whether the underlying native transfer executes at
  all in this environment (see "Native value transfer").

## Accepted, open risks

These were reviewed and deliberately left unfixed in this round, not overlooked:

- **`min_unique_validators` is decorative.** `PolicyRegistry` stores and hashes this field, but
  nothing in this codebase currently uses it to influence how many validators GenVM actually
  assigns to adjudicate a given claim; that sizing is controlled by GenVM itself, outside contract
  code, in this build. A policy author's stated minimum is not currently enforceable from within
  these contracts.
- **`ClaimEngine._send_native` is unverified for real fund movement.** See "Native value transfer"
  above.
- **`admin_address` is a single point of failure.** It is a plain address set once at construction,
  with no rotation mechanism and no multi-signature or timelock protection. Losing control of that
  key means losing the ability to ever withdraw the protocol sink. Changing this to a more robust
  authority model (multi-sig, a role-transfer method, or a DAO-style vote) is a real architecture
  change, out of scope for this round by the project owner's decision, not attempted here.

## Out of scope for this version

- `scope` values other than `"PROCESS"` (`"POLICY"`, `"GLOBAL"`) are defined in the enum but
  explicitly rejected in `register_claim`. Do not enable them without designing the authority
  model they would need first; a policy-scoped or globally-scoped claim implies a different set of
  parties who can be affected by one claim's outcome than a single process does.
- Predicate types other than `QuantityAtLeast` and `QuantityEquals` are defined and have
  prompt-building logic, but are not exercised end to end in `TEST_RESULTS.md`. Review
  `build_proposition_template` and the resulting adjudication prompt for each before relying on
  them in production.
- Registry addresses (`policy_registry_address`, `evidence_registry_address`,
  `claim_engine_address`) are immutable per deployment. There is no on-chain upgrade mechanism for
  a dependency. A compromised or deprecated dependency requires a fresh deployment of every
  contract that pointed at it.
