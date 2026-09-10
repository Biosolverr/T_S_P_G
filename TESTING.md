# Manual testing guide

This describes how to exercise every public method across all four contracts by hand in GenLayer
Studio, in the order dependencies require. For a worked example with real values and real outputs,
see `TEST_RESULTS.md`.

## Call order for one full claim

```
PolicyRegistry.register_policy
PolicyRegistry.get_policy_hash            (or use register_policy's own return value)
EvidenceRegistry.commit_evidence
ClaimEngine.register_claim
ClaimEngine.adjudicate_claim
ProcessGraph.create_process
ProcessGraph.add_node
ProcessGraph.add_claim_slot
ProcessGraph.commit_process
ProcessGraph.activate_process
ProcessGraph.get_process_commitment       (needed for a correct register_claim; see note below)
ProcessGraph.bind_slot
ProcessGraph.evaluate                     (optional, read only)
ProcessGraph.finalize_process
```

`ProcessGraph.get_process_commitment` is listed after `activate_process` but the value it returns
only depends on the committed graph structure, so it is stable from `commit_process` onward. Call
it any time after `commit_process` to get the value `register_claim`'s `process_commitment` field
must match.

## Cross-field constraints

These are not enforced by Studio's form, only by the contracts, and are the most common source of
a failed transaction:

- `ClaimEngine.register_claim`'s `process_commitment` must equal
  `ProcessGraph.get_process_commitment(process_id)` for the process this claim will eventually be
  bound to, not the `process_id` itself. `bind_slot` recomputes the graph commitment and rejects
  the claim if it does not match.
- `register_claim`'s `expected_policy_commitment` must equal `PolicyRegistry.get_policy_hash(policy_id, policy_version)`.
- `register_claim`'s `expected_evidence_commitment` must equal the commitment returned by
  `EvidenceRegistry.commit_evidence` for the `evidence_id` you pass.
- `register_claim`'s `predicate_type`, `predicate_value`, `predicate_unit`, `predicate_date`,
  `predicate_attribute_key`, `predicate_attribute_value`, `predicate_substring`, and
  `subject_commitment` must all match, field for field, what you pass to
  `ProcessGraph.add_claim_slot` for the slot this claim will bind to. `bind_slot` checks all of
  them.
- `register_claim` is payable; attach a transaction value at least equal to
  `PolicyRegistry.get_min_deposit(policy_id, policy_version)`.

## PolicyRegistry

### register_policy (write)

| Field | Type | Notes |
|---|---|---|
| policy_id | bytes | Caller-chosen identifier, any 32 bytes works well. |
| version | u32 | Start at 1. Registering the same `(policy_id, version)` twice fails. |
| predicate_rules | list[str] | Each element must be a value from the `PredicateType` enum, for example `"QuantityAtLeast"`. |
| min_unique_validators | u32 | |
| evidence_max_age_seconds | u64 | 0 disables the freshness check. |
| evidence_freshness_on_expiry | str | `"UNKNOWN"` or `"INVALIDATED"`. |
| authority_rules_commitment | bytes | Caller-chosen commitment to an off-chain authority ruleset; not independently verified by this contract. |
| graph_limits | dict[str, int] | Keys: `max_graph_nodes`, `max_graph_edges`, `max_graph_depth`, `max_claims_per_process`, `max_evidence_size`, `max_predicate_size`. |
| protocol_version | str | Free text, for example `"1.0.0"`. |
| schema_version | str | Free text, for example `"1.0.0"`. |
| allow_revocation_retry | bool | |
| min_deposit | u256 | Plain integer, smallest unit (wei-equivalent). |

Returns the policy commitment hash as a hex string.

### Other PolicyRegistry methods

`set_active(policy_id, version, active)`, `get_policy_hash`, `is_active`,
`verify_commitment(policy_id, version, expected_hash)`, `get_min_unique_validators`,
`get_graph_limits`, `get_allow_revocation_retry`, `get_freshness`, `get_min_deposit` are all
straightforward reads or a single admin-independent write with no cross-field constraints.

## EvidenceRegistry

### commit_evidence (write)

| Field | Type | Notes |
|---|---|---|
| artifact_hash | bytes | Must equal the sha256 digest of the exact bytes `gl.nondet.web.render(retrieval_hint_uri)` will return at adjudication time. Getting this wrong produces `HASH_MISMATCH:<actual hash>` at adjudication time (see below) rather than a rejection here, since this contract cannot fetch the URI itself to check. |
| artifact_size | u32 | Checked against the policy's `max_evidence_size` at claim registration, not checked against the real content size here. |
| mime_type | str | Free text. |
| authority_commitment | bytes | Caller-chosen, not independently verified. |
| submitted_at | u64 | Caller-supplied timestamp; see `SECURITY.md`. |
| scope_commitment | bytes | Caller-chosen. |
| retrieval_hint_uri | str | Must be `http://` or `https://`. `ipfs://` and other schemes fail at adjudication time with `SCHEMA_FORBIDDEN`. |
| schema_version | str | |

Returns `(evidence_id, evidence_commitment)`. `evidence_commitment` does not depend on
`retrieval_hint_uri`, only on the other seven fields, so committing the same content with a
corrected URI produces a new `evidence_id` but the same commitment.

### Getting the real artifact hash without guessing

If you do not control the exact byte output of `gl.nondet.web.render` for your URI (for example,
an HTML page where text extraction is not obviously predictable), do not guess. Commit evidence
with any placeholder hash, register a claim against it, and call `adjudicate_claim`. If the hash is
wrong you will get `HASH_MISMATCH:<actual hash>` in the equivalence principle output. Use that
exact value to re-commit evidence, then re-register the claim.

For a plain `.txt` file served as is, the hash is simply the sha256 of the file's exact bytes,
which you can compute yourself before committing.

## ClaimEngine

### register_claim (write, payable)

| Field | Type | Notes |
|---|---|---|
| process_commitment | bytes | See cross-field constraints above. |
| policy_id | bytes | |
| policy_version | u32 | |
| expected_policy_commitment | bytes | Must equal `PolicyRegistry.get_policy_hash(policy_id, policy_version)`. |
| subject_commitment | bytes | Caller-chosen commitment to whatever the claim is about. |
| subject_description | str | Free text, counted against `max_predicate_size`. |
| predicate_type | str | One of the `PredicateType` enum values. |
| predicate_value | i64 | Used for `QuantityAtLeast` / `QuantityEquals`. |
| predicate_unit | str | Only `GRAMS`, `KG`, or `ITEMS` are recognized. |
| predicate_date | i64 | Used for `DateBefore` / `DateEquals`. |
| predicate_attribute_key | str | Leave empty, not the string `"null"`, when unused. |
| predicate_attribute_value | str | Same. |
| predicate_substring | str | Same. |
| evidence_id | u32 | |
| expected_evidence_commitment | bytes | Must equal the commitment returned by `commit_evidence`. |
| schema_version | str | |
| scope | str | Only `"PROCESS"` is implemented; `"POLICY"` and `"GLOBAL"` are rejected. |
| now | u64 | Caller-supplied timestamp; see `SECURITY.md`. |

Attach a transaction value at least equal to `min_deposit`. Returns the claim id as a hex string;
this is also the storage key, and is deterministic (sha256 of the claim's own content), so
registering identical content twice fails with a collision rather than creating a duplicate.

### adjudicate_claim (write)

Fetches the evidence content, hash-checks it, and if the hash matches, builds a prompt from the
predicate and asks the validator set for a verdict under equivalence-principle consensus. Returns
the claim's new state (`TRUE`, `FALSE`, or `UNKNOWN`). The raw equivalence principle output (shown
separately in Studio) is either `VERDICT:TRUE` / `VERDICT:FALSE` / `VERDICT:UNKNOWN` on a
successful fetch and hash match, or `HASH_MISMATCH:<hash>` if the fetched content's hash does not
match what was committed.

### Other ClaimEngine methods

`invalidate_claim(claim_id)`, `expire_claim(claim_id, now)`, `withdraw()`,
`withdraw_protocol_sink(to)` (admin only), and the view methods `get_withdrawable`, `get_state`,
`get_provenance`, `get_predicate_fields`, `verify_commitment` need no special handling beyond the
`bytes` and timestamp notes above.

## ProcessGraph

### create_process (write)

| Field | Type | Notes |
|---|---|---|
| process_id | bytes | Caller-chosen. Not the same thing as `process_commitment` used elsewhere; see cross-field constraints. |
| policy_id | bytes | |
| policy_version | u32 | |
| expected_policy_commitment | bytes | Must match `PolicyRegistry.get_policy_hash`. |
| schema_version | str | |
| now | u64 | |

### add_node (write)

`node_id: bytes`, `node_type: str` (`CLAIM`, `AND`, `OR`, `NOT`, `THRESHOLD`), `children: list[bytes]`
(must be empty for `CLAIM` nodes, non-empty for `AND`/`OR`/`THRESHOLD`, exactly one for `NOT`),
`threshold_k: u32` (only meaningful for `THRESHOLD` nodes, must satisfy `1 <= threshold_k <= len(children)`).

### add_claim_slot (write)

Only valid on a `CLAIM` node. Fields must match the claim you will later bind to this slot; see
cross-field constraints above.

### commit_process, activate_process (write)

`commit_process(process_id, root_node_id, now)` freezes the graph structure after validating it
has no cycles and respects the policy's size and depth limits. `activate_process(process_id)` has
no additional arguments.

### bind_slot (write)

`bind_slot(slot_id, claim_id)`. Resolves the slot to `RESOLVED` if the claim's adjudicated state is
`TRUE` or `FALSE`; leaves it `OPEN` if the claim is still `UNKNOWN`, `REGISTERED`, or
`ADJUDICATING`. A slot left `OPEN` blocks `finalize_process` for any process where that slot is
reachable from the root.

### evaluate, finalize_process (write for finalize_process, view for evaluate)

`evaluate(process_id)` computes the current boolean result without changing state. `finalize_process(process_id, now)`
does the same computation and, if no reachable slot is still `OPEN`, records and returns the final
result.

## Security and boundary test suggestions

- Call `set_active` and `withdraw_protocol_sink` from a non-admin account; both must be rejected.
- Call `register_policy` twice with the same `(policy_id, version)`; must be rejected.
- Call `adjudicate_claim` a second time on an already-finalized claim; must be rejected.
- Call `bind_slot` twice on the same slot with the same claim; second call should be rejected or a
  no-op depending on the slot's resulting state, not a silent double-resolve.
- Register a claim with `expected_policy_commitment` or `expected_evidence_commitment` that does
  not match the real committed value; must be rejected before any state is written.
- Register a claim whose `evidence_id` is valid but whose `expected_evidence_commitment` belongs to
  a different evidence record; must be rejected.
- Send `predicate_value = -1` for `QuantityAtLeast`; confirm the comparison logic in the
  adjudication prompt handles a negative value sensibly rather than throwing.
- Send `artifact_hash = 0x00...00` (32 zero bytes); confirm the bytes coercion helper preserves all
  32 bytes rather than collapsing leading zero bytes to a shorter value.
- Send a `min_deposit` in `register_claim`'s attached value that is one unit below the policy's
  `min_deposit`; must be rejected.
- Call `add_node` with `threshold_k` greater than `len(children)` for a `THRESHOLD` node; must be
  rejected.
- Call `withdraw()` twice in a row for the same address; the second call should return zero or
  reject, never pay out twice.
