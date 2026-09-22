# Manual testing guide

This describes how to exercise every public method across all four contracts by hand in GenLayer
Studio, in the order dependencies require, for the post-audit revision. For a worked example with
real values and real outputs, see `TEST_RESULTS.md`.

## Call order for one full claim, through process finalization

```
PolicyRegistry.register_policy
EvidenceRegistry.commit_evidence
ProcessGraph.create_process
ProcessGraph.add_node
ProcessGraph.add_claim_slot
ProcessGraph.commit_process
ProcessGraph.activate_process
ProcessGraph.get_process_commitment          (view; needed for register_claim below)
ClaimEngine.register_claim
ClaimEngine.adjudicate_claim
ProcessGraph.bind_slot                        (moves the slot to PENDING, not RESOLVED)
ProcessGraph.finalize_slot                    (after the dispute window elapses)
ProcessGraph.finalize_process
```

`ProcessGraph.get_process_commitment` only depends on the committed graph structure, so it is
stable from `commit_process` onward; it does not need to be called immediately after
`activate_process`, only before `register_claim`.

## Cross-field constraints

These are not enforced by Studio's form, only by the contracts, and are the most common source of
a rejected or reverted call:

- `ClaimEngine.register_claim`'s `process_commitment` must equal
  `ProcessGraph.get_process_commitment(process_id)` for the process this claim will eventually be
  bound to. This is not the same value as `process_id` itself, and not the same value returned by
  `ProcessGraph.commit_process` (that is the graph commitment, a different hash covering only
  nodes and edges). `bind_slot` recomputes the full process commitment independently and rejects
  the claim if it does not match.
- `register_claim`'s `expected_policy_commitment` must equal
  `PolicyRegistry.get_policy_hash(policy_id, policy_version)` (also returned directly by
  `register_policy` itself).
- `register_claim`'s `expected_evidence_commitment` must equal the commitment returned by
  `EvidenceRegistry.commit_evidence` for the `evidence_id` given.
- `register_claim`'s `predicate_type` must appear in the policy's own `predicate_rules`, checked
  via `PolicyRegistry.get_predicate_rules`, not merely be a valid `PredicateType` value in general.
- `register_claim`'s `predicate_type`, `predicate_value`, `predicate_unit`, `predicate_date`,
  `predicate_attribute_key`, `predicate_attribute_value`, `predicate_substring`, and
  `subject_commitment` must all match, field for field, what was passed to
  `ProcessGraph.add_claim_slot` for the slot this claim will bind to. `bind_slot` checks all of
  them and rejects predicate substitution.
- `register_claim`'s `now` must not be earlier than the referenced evidence's own `submitted_at`.
- `register_claim` is payable; attach a transaction value at least equal to
  `PolicyRegistry.get_min_deposit(policy_id, policy_version)`. In GenLayer Studio's call form, the
  "Value (GEN)" field takes a plain GEN amount, not the base-unit integer used in every other
  numeric field in this system; if `min_deposit` is `1000000000000000000` (one GEN), enter `1` in
  that field, not the base-unit number.
- `ProcessGraph.finalize_slot`'s `now` must be at least `DISPUTE_WINDOW_SECONDS` (3600) later than
  the `now` given to the `bind_slot` call that most recently moved the slot to `PENDING`.

## PolicyRegistry

### register_policy (write)

| Field | Type | Notes |
|---|---|---|
| policy_id | bytes | Caller-chosen identifier; any 32 bytes works well. |
| version | u32 | Start at 1. Registering the same `(policy_id, version)` twice is rejected. |
| predicate_rules | list[str] | Each element must be a `PredicateType` enum value, for example `"QuantityAtLeast"`. This is now actually enforced against claims registered under this policy (see finding #3 in `README.md`); it is not merely stored. |
| min_unique_validators | u32 | Must be `>= 1`. Stored and hashed, but not currently enforced against GenVM's actual validator assignment; see `SECURITY.md`, "Accepted, open risks". |
| evidence_max_age_seconds | u64 | `0` disables the freshness check. |
| evidence_freshness_on_expiry | str | `"UNKNOWN"` or `"INVALIDATED"`. Validated unconditionally now, regardless of `evidence_max_age_seconds`. |
| authority_rules_commitment | bytes | Caller-chosen commitment to an off-chain authority ruleset; not independently verified by this contract. |
| graph_limits | dict[str, int] | Keys: `max_graph_nodes`, `max_graph_edges`, `max_graph_depth`, `max_claims_per_process`, `max_evidence_size`, `max_predicate_size`. |
| protocol_version | str | Free text, for example `"1.0.0"`. |
| schema_version | str | Free text, for example `"1.0.0"`. |
| allow_revocation_retry | bool | |
| min_deposit | u256 | Plain integer in the smallest unit (the wei-equivalent base unit), for example `1000000000000000000` for one GEN. |

Returns the policy commitment hash as a hex string. A policy is active immediately on
registration; `set_active` is not needed unless you want to deactivate it, or reactivate it after
having deactivated it.

### set_active (write)

`set_active(policy_id, version, active)`. Restricted to the original registrant. Deactivating a
policy blocks new claim registrations and new process creation against it; it does not affect
claims or processes already in progress, except that `ProcessGraph.commit_process` re-checks
`is_active` at commit time and will refuse to commit a process against a policy version
deactivated after the process was created.

### Other PolicyRegistry methods

`get_policy_hash`, `is_active`, `verify_commitment(policy_id, version, expected_hash)`,
`get_min_unique_validators`, `get_predicate_rules`, `get_graph_limits`,
`get_allow_revocation_retry`, `get_freshness`, and `get_min_deposit` are all straightforward reads
with no cross-field constraints beyond an existing `(policy_id, version)`.

## EvidenceRegistry

### commit_evidence (write)

| Field | Type | Notes |
|---|---|---|
| artifact_hash | bytes | Must equal the sha256 digest of the exact bytes `gl.nondet.web.render(retrieval_hint_uri)` returns at adjudication time. Getting this wrong is not rejected here (this contract cannot fetch the URI itself to check); it surfaces later, at adjudication time, as `HASH_MISMATCH:<actual hash>`. See "Recovering the real artifact hash" below. |
| artifact_size | u32 | Checked against the policy's `max_evidence_size` at claim registration time, not checked against the real content size here. |
| mime_type | str | Free text. |
| authority_commitment | bytes | Caller-chosen; not independently verified. |
| submitted_at | u64 | Caller-supplied timestamp; see `SECURITY.md`, "Caller-supplied time". |
| scope_commitment | bytes | Caller-chosen. |
| retrieval_hint_uri | str | Must be `http://` or `https://`. Any other scheme, including `ipfs://`, fails at adjudication time with `SCHEMA_FORBIDDEN`. |
| schema_version | str | |

Returns `(evidence_id, evidence_commitment)`. `evidence_commitment` does not depend on
`retrieval_hint_uri` or on `evidence_id`, only on the other six content fields plus the caller's
own address (`creator`); committing the same content from the same address with a corrected URI
produces a new `evidence_id` but the same commitment. Committing from a different address changes
the commitment even with otherwise identical fields.

### Recovering the real artifact hash

If you do not control the exact byte output of `gl.nondet.web.render` for your URI (for example,
an HTML page where the platform's own text extraction is not predictable from outside), do not
guess. Commit evidence with a placeholder hash, register a claim against it, and call
`adjudicate_claim`. If the hash does not match, the equivalence-principle output will read
`HASH_MISMATCH:<actual hash>`. Use that exact value to re-commit evidence, then re-register the
claim.

For a plain `.txt` file served as-is, the hash is simply the sha256 of the file's exact bytes,
which can be computed independently before committing, though even then, differences in how the
hosting service normalizes line endings or adds a trailing newline can produce a mismatch; the
`HASH_MISMATCH` diagnostic is the reliable path either way.

### set_state (write)

`set_state(evidence_id, new_state)`. Restricted to the record's original creator. Only a fixed
allow-list of transitions is permitted: `COMMITTED -> VALID`, `COMMITTED -> INVALID`,
`COMMITTED -> REVOKED`, `VALID -> REVOKED`. Any other transition, including a no-op or a reverse
transition, is rejected.

### Other EvidenceRegistry methods

`get_artifact_hash`, `get_state`, `get_retrieval_hint`, `verify_commitment(evidence_id,
expected_hash, schema_version)`, `get_scope_commitment`, `get_submitted_at`, and
`get_artifact_size` are all straightforward reads.

## ClaimEngine

### register_claim (write, payable)

| Field | Type | Notes |
|---|---|---|
| process_commitment | bytes | See cross-field constraints above; this is `ProcessGraph.get_process_commitment(process_id)`'s return value, not `process_id` itself. |
| policy_id | bytes | |
| policy_version | u32 | |
| expected_policy_commitment | bytes | Must equal `PolicyRegistry.get_policy_hash(policy_id, policy_version)`. |
| subject_commitment | bytes | Caller-chosen commitment to whatever the claim is about. |
| subject_description | str | Free text, counted against `max_predicate_size` together with the other predicate string fields. |
| predicate_type | str | Must be a `PredicateType` enum value AND appear in the policy's own `predicate_rules`. |
| predicate_value | i64 | Used for `QuantityAtLeast` / `QuantityEquals`. Must be `>= 0` for those two types. |
| predicate_unit | str | Only `GRAMS`, `KG`, or `ITEMS` are recognized. |
| predicate_date | i64 | Used for `DateBefore` / `DateEquals`. |
| predicate_attribute_key | str | Leave as an empty string, not the literal text `"null"`, when unused. |
| predicate_attribute_value | str | Same. |
| predicate_substring | str | Same. |
| evidence_id | u32 | |
| expected_evidence_commitment | bytes | Must equal the commitment returned by `commit_evidence`. |
| schema_version | str | |
| scope | str | Only `"PROCESS"` is implemented; `"POLICY"` and `"GLOBAL"` are rejected. |
| now | u64 | Caller-supplied timestamp; must not be earlier than the evidence's own `submitted_at`. |

Attach a transaction value at least equal to `min_deposit` (see the Studio "Value (GEN)" field note
above). On success, returns the claim id as a hex string; this is also the storage key, and is
deterministic (a sha256 of the claim's own content), so registering identical content twice does
not create a duplicate, it is rejected. **On any business-logic rejection, the call still succeeds
as a transaction and returns a string starting with `"REJECTED: "`, after crediting the attached
value to the sender's withdrawable balance; it does not raise.** Check the return value's prefix,
not the transaction's success/failure status, to know whether the claim was actually registered.

### adjudicate_claim (write)

`adjudicate_claim(claim_id, now)`. Rejects if the claim is not in state `REGISTERED`, and if `now`
is earlier than the claim's own `asserted_at`. If the policy's evidence freshness window has
elapsed, settles the claim directly to `UNKNOWN` or `EXPIRED` (depending on the policy's
`evidence_freshness_on_expiry`) without fetching anything. Otherwise, fetches the evidence content,
hash-checks it, and if it matches, builds a prompt from the predicate and asks the validator set
for a verdict under equivalence-principle consensus. Returns the claim's new state (`TRUE`,
`FALSE`, or `UNKNOWN`). The equivalence-principle output shown separately in Studio is one of
`VERDICT:TRUE`, `VERDICT:FALSE`, `VERDICT:UNKNOWN` on a successful fetch and hash match, or
`HASH_MISMATCH:<hash>` if the fetched content's hash does not match what was committed.

### invalidate_claim (write)

`invalidate_claim(claim_id)`. Restricted to the claim's own submitter. Only a `TRUE` claim may be
invalidated, and only if the policy's `allow_revocation_retry` permits it. This closes the
"anyone can invalidate anyone's claim" hole found in the audit; it is not a dispute mechanism, and
does not involve any second round of adjudication over the invalidation itself.

### expire_claim (write)

`expire_claim(claim_id, now)`. Rejects if the claim is in a terminal state already, or if `now` is
earlier than the claim's own `asserted_at`. Succeeds if either the evidence is stale under the
policy's freshness rule (only checked if `evidence_max_age_seconds > 0`), or the claim has been
stuck in `ADJUDICATING` for longer than `STUCK_ADJUDICATION_TIMEOUT_SECONDS` (3600, fixed,
independent of any policy setting). These are two independent conditions; a policy that disables
freshness checking entirely does not also disable the stuck-adjudication recovery path.

### withdraw and withdraw_protocol_sink (write)

`withdraw()` takes no arguments, pays out the caller's own withdrawable balance, and is available
to anyone with a nonzero balance (including a balance credited from a rejected `register_claim`
call). `withdraw_protocol_sink(to)` is restricted to `admin_address` and pays out the entire
protocol sink to the given address. Both return the amount paid. See `SECURITY.md`, "Native value
transfer", for what has and has not been confirmed about whether either method actually moves real
value in this environment.

### Other ClaimEngine methods

`get_withdrawable(address)`, `get_registry_addresses()` (returns
`(policy_registry_address, evidence_registry_address)` as plain strings; see `DEPLOYMENT.md`),
`get_state(claim_id)`, `get_deposit_amount(claim_id)`, `get_provenance(claim_id)`,
`get_predicate_fields(claim_id)`, and `verify_commitment(claim_id)` are all straightforward reads.

## ProcessGraph

### create_process (write)

| Field | Type | Notes |
|---|---|---|
| process_id | bytes | Caller-chosen. Not the same value as `process_commitment` used elsewhere; see cross-field constraints. |
| policy_id | bytes | |
| policy_version | u32 | |
| expected_policy_commitment | bytes | Must match `PolicyRegistry.get_policy_hash`. |
| schema_version | str | |
| now | u64 | Recorded as the process's `created_at`. |

Rejects if the referenced policy is not active.

### add_node and add_claim_slot (write)

Both restricted to the process's own creator, and only while the process is `DRAFT`.

`add_node(process_id, node_id, node_type, children, threshold_k)`: `node_type` is one of `CLAIM`,
`AND`, `OR`, `NOT`, `THRESHOLD`. `children` (a list of node ids) must be empty for `CLAIM`, must
have at least one entry for `AND`/`OR`, must have exactly one entry for `NOT`, and for `THRESHOLD`
must satisfy `1 <= threshold_k <= len(children)`. Adding a node beyond the policy's
`max_graph_nodes` is rejected.

`add_claim_slot(process_id, node_id, slot_id, predicate_type, predicate_value, predicate_unit,
predicate_date, predicate_attribute_key, predicate_attribute_value, predicate_substring,
subject_commitment)`: only valid on a `CLAIM` node that does not already have a slot bound. These
fields must exactly match what will later be registered on the claim bound to this slot; see
cross-field constraints above.

### commit_process (write)

`commit_process(process_id, root_node_id, now)`. Restricted to the process's creator, only while
`DRAFT`. Rejects if `now` is earlier than the process's own `created_at`, if the referenced policy
has since been deactivated, if the graph is empty, if `root_node_id` is not a member of the graph,
if any `CLAIM` node lacks a bound slot, if the edge count exceeds `max_graph_edges`, if the graph
contains a cycle, or if its depth exceeds `max_graph_depth`. On success, computes and stores the
graph commitment, moves the process to `COMMITTED`, and returns the graph commitment as a hex
string. This is a different value from `get_process_commitment`'s return; see cross-field
constraints above.

### activate_process and cancel_process (write)

`activate_process(process_id)` transitions `COMMITTED -> ACTIVE`. `cancel_process(process_id)` is
restricted to the creator and only permitted from `DRAFT`, `COMMITTED`, or `ACTIVE`. Both take no
other arguments.

### bind_slot (write)

`bind_slot(slot_id, claim_id, now)`. Permissionless; the claim's content is independently
re-verified against the slot's own definition and against `ProcessGraph`'s own recomputed process
commitment regardless of who calls it, so there is no benefit to restricting the caller. Behavior
depends on the claim's adjudicated state:

- `TRUE` or `FALSE`, slot currently `OPEN`: opens the dispute window, moves the slot to `PENDING`,
  records `bound_at = now` and the claim's own deposit amount. Does not resolve the slot yet.
- `TRUE` or `FALSE`, slot currently `PENDING` with the same claim already bound: no-op, does not
  reset the window.
- `TRUE` or `FALSE`, slot currently `PENDING` with a different claim bound, and the window has not
  elapsed: the new claim displaces the pending one only if its own deposit is strictly larger; the
  window resets. If the deposit is not strictly larger, the call is rejected.
- `TRUE` or `FALSE`, slot currently `PENDING`, and the window has already elapsed: rejected; call
  `finalize_slot` instead.
- `INVALIDATED` or `EXPIRED`: binds the claim and sets the slot to `OPEN` if the process's policy
  allows revocation retry, or `LOCKED` otherwise. No dispute window applies to this path.
- Any other state (`REGISTERED`, `ADJUDICATING`, `UNKNOWN`): binds the claim and sets the slot to
  `OPEN`.

Returns the slot's resulting state as a string.

### finalize_slot (write)

`finalize_slot(slot_id, now)`. Permissionless. Only valid on a `PENDING` slot, and only once `now`
is at least `DISPUTE_WINDOW_SECONDS` (3600) past the slot's `bound_at`. Moves the slot to
`RESOLVED` and returns that state.

### evaluate (view) and finalize_process (write)

`evaluate(process_id)` computes the current boolean result of the graph without changing any
state, treating a `PENDING` slot the same as an unresolved one (`UNKNOWN`), since its outcome could
still be displaced by a challenger.

`finalize_process(process_id, now)` rejects if the process is already `FINALIZED` or `CANCELLED`,
if it is not in a state that can be finalized, if `now` is earlier than the process's own
`committed_at`, or if any claim slot reachable from the root is still `OPEN` or `PENDING`. On
success, records and returns the final result.

### Other ProcessGraph methods

`get_process_commitment(process_id)`, `get_state(process_id)`, `get_final_result(process_id)`
(only valid once `FINALIZED`), and `get_slot_state(slot_id)` are all straightforward reads.

## Security and boundary test suggestions

- Call `PolicyRegistry.set_active`, `ClaimEngine.invalidate_claim`, and
  `ClaimEngine.withdraw_protocol_sink` from an account other than the one authorized for each; all
  three must be rejected.
- Call `register_policy` twice with the same `(policy_id, version)`; must be rejected.
- Call `adjudicate_claim` a second time on an already-adjudicated claim; must be rejected (state is
  no longer `REGISTERED`).
- Register a claim with `expected_policy_commitment` or `expected_evidence_commitment` that does
  not match the real committed value; must return `"REJECTED: ..."` with the attached deposit
  credited back, not silently accepted.
- Register a claim whose `predicate_type` is a valid `PredicateType` but is not in the policy's own
  `predicate_rules`; must be rejected with the predicate-rules message specifically, not a generic
  one.
- Send `predicate_value = -1` for `QuantityAtLeast`; must be rejected before reaching adjudication.
- Send `artifact_hash = 0x00...00` (32 zero bytes) to `commit_evidence`; confirm `_coerce_bytes`
  preserves all 32 bytes on later retrieval rather than collapsing leading zero bytes to a shorter
  value.
- Send a `register_claim` transaction value one unit below the policy's `min_deposit`; must be
  rejected via the `"REJECTED: "` path, with the value refunded, not raised as an exception.
- Call `add_node` with `threshold_k` greater than `len(children)` for a `THRESHOLD` node; must be
  rejected.
- Attempt to displace a `PENDING` slot with a claim whose deposit is equal to, not strictly greater
  than, the currently pending claim's deposit; must be rejected.
- Attempt `bind_slot` on a `PENDING` slot after the dispute window has already elapsed, instead of
  calling `finalize_slot`; must be rejected with a message pointing at `finalize_slot`.
- Attempt `finalize_process` while any reachable slot is `PENDING` (not just `OPEN`); must be
  rejected.
- Call `withdraw()` twice in a row for the same address with no new deposit credited in between;
  the second call should either return zero or reject with "nothing to withdraw", never pay out
  twice.
