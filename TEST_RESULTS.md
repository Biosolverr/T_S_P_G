# End-to-end test results

Environment: GenLayer Studio, `py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6`,
Normal (Full Consensus) execution mode. This is the successful run of the post-audit contracts,
after every fix in `KNOWN_ISSUES.md` and `SECURITY.md` had been applied and a fresh deployment of
all four contracts had been made. Earlier attempts against this same scenario, and against earlier
pre-audit and pre-fix contract versions, failed at various steps before each corresponding fix;
the more informative failures are summarized at the end rather than reproduced in full.

## Scenario

A procurement claim: ACME Logistics must deliver at least 500 items against purchase order
PO#2026-08421. Evidence is a delivery confirmation document, hosted as a public GitHub Gist,
stating that 750 units were delivered.

## 1. PolicyRegistry.register_policy

Input:

```
policy_id: 0x1980d07b10fb96ea16cc2fb9c73ab810e419158aace2aae6e5ba5cb73df8e6e5
version: 1
predicate_rules: ["QuantityAtLeast"]
min_unique_validators: 3
evidence_max_age_seconds: 1788684041
evidence_freshness_on_expiry: UNKNOWN
authority_rules_commitment: 0x5549d05a38b595a2074fc1ff08cc88ba2ee18ecc7590267f7cee1dbda95b5f8d
graph_limits: {max_claims_per_process:20, max_evidence_size:5242880, max_graph_depth:10, max_graph_edges:100, max_graph_nodes:50, max_predicate_size:4096}
protocol_version: 1.0.0
schema_version: 1.0.0
allow_revocation_retry: false
min_deposit: 1000000000000000000
```

Result: SUCCESS, FINALIZED.
Output (policy commitment): `0xbe2e7f7b8e2695c6a9b450091a9e34875ad2e7f341c399c4b2833c750db168a9`

Note: `evidence_max_age_seconds` was entered as `1788684041` (a copy-paste error, reusing the
session's `now` value) instead of the intended `2592000` (thirty days). This was not corrected;
the run proceeded with an effectively-unbounded freshness window instead. This does not exercise
the freshness path meaningfully, but does not invalidate anything else in this run, since no step
below depends on the freshness window actually expiring.

## 2. EvidenceRegistry.commit_evidence

Input:

```
artifact_hash: 0xc0535e4be2b79ffd93291305436bf889314e4a3faec05ecffcbb7df31ad9e51a  (see note below)
artifact_size: 445
mime_type: text/plain
authority_commitment: 0x883b4e58592d47b0fcf877274a5d7b911732eb70197433631d6a1902c6791250
submitted_at: 1788684041
scope_commitment: 0xc17e3a0b439497fcf810a13f1c644b24886681f9f7f92cb257f50ec04981af3e
retrieval_hint_uri: https://gist.githubusercontent.com/Biosolverr/73bf862b1ac706ce08c906acf4c9e6d8/raw/a158d8e75e3ec72168922a0ddd46451e99343e30/delivery_confirmation.txt
schema_version: 1.0.0
```

Result: SUCCESS, FINALIZED.
Output: `evidence_id = 1`, `evidence_commitment = 0x10d6eed4cb316c5cd9fe021c59d139dc927e30f8f9e3b05c7e08ddeedc4b6515`

`artifact_hash` here is the real sha256 digest of the Gist's raw content, obtained from an earlier
attempt's `HASH_MISMATCH:<hash>` diagnostic output against this exact URL, rather than guessed; see
`TESTING.md`, "Recovering the real artifact hash", and the failed-attempts summary below.

## 3. ProcessGraph graph construction

```
create_process(process_id=0xcd3bd00ebf5c26b752bc2c0191229f6b9cdecaad8c11e730e39f0a5e111da20e,
                policy_id=0x1980d07b10fb96ea16cc2fb9c73ab810e419158aace2aae6e5ba5cb73df8e6e5,
                policy_version=1,
                expected_policy_commitment=0xbe2e7f7b8e2695c6a9b450091a9e34875ad2e7f341c399c4b2833c750db168a9,
                schema_version=1.0.0, now=1788684041)
-> SUCCESS

add_node(process_id=..., node_id=0x1046da30d3f852fce19562c3ed3c9671e5a33378ca878fe319d7487eacac6be7,
         node_type=CLAIM, children=[], threshold_k=0)
-> SUCCESS

add_claim_slot(process_id=..., node_id=..., slot_id=0xdbdb9c8588618f26b977f4b6b0d83ab639f6ac954f249153058fce659f11e4d7,
               predicate_type=QuantityAtLeast, predicate_value=500, predicate_unit=ITEMS,
               predicate_date=0, predicate_attribute_key="", predicate_attribute_value="",
               predicate_substring="", subject_commitment=0xf9d3af1daba426ce2749dd39712cb546a51c3e2a0a11a3f00281ff93d929c491)
-> SUCCESS

commit_process(process_id=..., root_node_id=0x1046da30d3f852fce19562c3ed3c9671e5a33378ca878fe319d7487eacac6be7, now=1788684041)
-> SUCCESS, graph commitment 0x267771c69fb71589a17fa404bb4249070dd8c33e0f66d5b19ace38dc43976591

activate_process(process_id=...)
-> SUCCESS
```

```
get_process_commitment(process_id=0xcd3bd00ebf5c26b752bc2c0191229f6b9cdecaad8c11e730e39f0a5e111da20e)
-> 0x05b6bd13391abdcf40d0dc3d098bad19ccb861cca817c0a058b356570257032c
```

Note the graph commitment returned by `commit_process` (`0x267771c6...`) and the process
commitment returned by `get_process_commitment` (`0x05b6bd13...`) are different values, as expected;
see `TESTING.md`, cross-field constraints. Only the latter is used in step 4 below.

## 4. ClaimEngine.register_claim

Input:

```
process_commitment: 0x05b6bd13391abdcf40d0dc3d098bad19ccb861cca817c0a058b356570257032c
policy_id: 0x1980d07b10fb96ea16cc2fb9c73ab810e419158aace2aae6e5ba5cb73df8e6e5
policy_version: 1
expected_policy_commitment: 0xbe2e7f7b8e2695c6a9b450091a9e34875ad2e7f341c399c4b2833c750db168a9
subject_commitment: 0xf9d3af1daba426ce2749dd39712cb546a51c3e2a0a11a3f00281ff93d929c491
subject_description: ACME Logistics, PO#2026-08421 delivery to Warehouse 4
predicate_type: QuantityAtLeast
predicate_value: 500
predicate_unit: ITEMS
predicate_date: 0
predicate_attribute_key: (empty)
predicate_attribute_value: (empty)
predicate_substring: (empty)
evidence_id: 1
expected_evidence_commitment: 0x10d6eed4cb316c5cd9fe021c59d139dc927e30f8f9e3b05c7e08ddeedc4b6515
schema_version: 1.0.0
scope: PROCESS
now: 1788684041
```

Value attached: 1 GEN (entered as `1` in Studio's Value field, equal to the policy's `min_deposit`
of `1000000000000000000` base units).

Result: SUCCESS, FINALIZED.
Output (claim id): `0x5986386dbf2e021aa255e1dd6037ab880111eade2fdc53f057145a26967900eb`

## 5. ClaimEngine.adjudicate_claim

Input: `claim_id = 0x5986386dbf2e021aa255e1dd6037ab880111eade2fdc53f057145a26967900eb`,
`now = 1788684041`.

Result: SUCCESS, FINALIZED.
Output (claim state): `TRUE`
Equivalence principle output: `VERDICT:TRUE`

The validator set fetched the Gist content over `gl.nondet.web.render`, confirmed its sha256 digest
matched the committed `artifact_hash`, and reached consensus that the content supports "quantity
delivered is at least 500 ITEMS" (the content states 750 units delivered).

## 6. ProcessGraph.bind_slot

Input: `slot_id = 0xdbdb9c8588618f26b977f4b6b0d83ab639f6ac954f249153058fce659f11e4d7`,
`claim_id = 0x5986386dbf2e021aa255e1dd6037ab880111eade2fdc53f057145a26967900eb`, `now = 1788684041`.

Result: SUCCESS, FINALIZED.
Output (slot state): `PENDING`

This confirms the post-audit dispute-window behavior: a first `TRUE`/`FALSE` binding no longer
resolves a slot immediately.

## 7. ProcessGraph.finalize_slot

Input: `slot_id = 0xdbdb9c8588618f26b977f4b6b0d83ab639f6ac954f249153058fce659f11e4d7`,
`now = 1788687642` (`1788684041 + 3601`, one second past the dispute window).

Result: SUCCESS, FINALIZED.
Output (slot state): `RESOLVED`

## 8. ProcessGraph.finalize_process

Input: `process_id = 0xcd3bd00ebf5c26b752bc2c0191229f6b9cdecaad8c11e730e39f0a5e111da20e`,
`now = 1788687642`.

Result: SUCCESS, FINALIZED.
Output (final result): `TRUE`

This is the full post-audit pipeline, confirmed working end to end, including the new dispute
window and the earlier fixes to cross-contract calldata handling, timestamps, and hashing.

## Separate test: reject-and-refund on register_claim

A second scenario confirmed the fix described in `SECURITY.md`, "Value delivery and rejected
payable calls". A policy was deliberately deactivated (`set_active(..., false)`), then
`register_claim` was called against it with 2 GEN attached.

Result: SUCCESS, FINALIZED.
Output: `"REJECTED: policy version is not active - cannot register new claims against it"`

Immediately after, `get_withdrawable(sender_address)` returned `2000000000000000000` (2 GEN),
confirming the attached value was credited rather than lost. This is a direct comparison against
the pre-fix behavior, tested earlier in the same session on the same scenario: before this fix, an
identical rejected call left no record anywhere that the sender was owed anything, and the value
was unrecoverable through any method on the contract.

## Separate test: native value transfer (inconclusive)

Following the reject-and-refund test above, `withdraw()` was called by the same address with a
withdrawable balance of 2 GEN.

Result: SUCCESS, FINALIZED.
Output: `2000000000000000000` (the correct amount, and `get_withdrawable` for that address
correctly returned `0` afterward).

However, the receiving wallet's real balance, checked directly in GenLayer Studio's account list,
did not increase. This result is recorded as inconclusive, not as a confirmed defect; see
`SECURITY.md`, "Native value transfer", for the reasoning (an independent GenLayer project
documents the identical call pattern as its production method for paying claimants, and GenLayer
Studio's own documentation describes it as a local practice environment, distinct from real test
networks, which may not fully simulate native value settlement). This was not re-tested against a
real GenLayer test network as part of this project.

## Summary of failed attempts against this same scenario, and why

For completeness, and because each one drove a fix now recorded in `KNOWN_ISSUES.md` or
`SECURITY.md`:

1. `register_policy` failed with a `DynArray` construction error before `KNOWN_ISSUES.md` item 1's
   fix.
2. `register_policy` and `create_process` failed with a `TreeMap` assignment error before
   `KNOWN_ISSUES.md` item 2's fix (in `process_graph.py`; `policy_registry.py`'s equivalent line
   has not reproduced this failure, see the note under item 2).
3. Early testing failed with `bytes`/`Address` constructor and method arguments arriving as `int`
   before `KNOWN_ISSUES.md` item 3's fix.
4. `adjudicate_claim` failed with `AttributeError: module 'genlayer.gl' has no attribute 'block'`
   before `KNOWN_ISSUES.md` item 5's fix (caller-supplied `now`).
5. `register_claim` failed with `invalid scope` when a free-text scope was used instead of
   `PROCESS`.
6. `adjudicate_claim` failed with `PredicateError: unknown unit 'units'` before `predicate_unit`
   was corrected to `ITEMS`.
7. `adjudicate_claim` failed with `SCHEMA_FORBIDDEN` while `retrieval_hint_uri` was an `ipfs://`
   URL; corrected to an `https://` URL (`KNOWN_ISSUES.md` item 6).
8. `adjudicate_claim` returned `HASH_MISMATCH` (later `HASH_MISMATCH:<hash>` once the diagnostic
   was added) against both a placeholder hash for a generic test page and a guessed hash for real
   content before its exact byte encoding was confirmed.
9. `bind_slot` failed with `claim.process_commitment does not match this process`, for two
   different reasons on two different attempts: first because `process_commitment` was set to an
   arbitrary `process_id`-like value instead of the graph's real process commitment, and separately
   because of the `str` vs `bytes` comparison bug described in `KNOWN_ISSUES.md` item 4, which was
   masking the correctness of the first fix until both were resolved.
10. `bind_slot` failed with `unknown slot_id` after `process_graph.py` was redeployed to apply a
    fix, since the graph-construction steps had to be repeated against the new deployment's empty
    storage; this is expected behavior given `DEPLOYMENT.md`'s redeploy discipline, not a defect.
11. `register_claim` failed once with `claim_id collision on registration`, because the exact same
    content had already been registered successfully in an earlier session whose Studio-side
    transaction history had been cleared by a page reload. The existing claim id was recomputed
    independently from the contract's own canonicalization logic and confirmed with
    `verify_commitment` rather than re-registered.
12. `withdraw()` failed three times in sequence against three distinct defects in `_send_native`,
    each fixed before the next was found: a `0x`-prefix `bytes.fromhex` crash, a `TypeError:
    address expected` from passing raw bytes instead of an `Address`, and a `TypeError` from
    passing the transfer amount positionally instead of as the `value=` keyword. See
    `KNOWN_ISSUES.md` items 3 and 8, and `SECURITY.md`, "Native value transfer".
13. A speculative fix attempt using `@gl.evm.contract_interface` crashed contract schema loading
    entirely (`KNOWN_ISSUES.md` item 9) and was reverted before redeployment.
14. Multiple `register_claim` attempts against a deliberately deactivated policy, before the
    reject-and-refund fix, permanently forfeited their attached deposits with no record of the
    debt; this is the defect described in `SECURITY.md`, "Value delivery and rejected payable
    calls", and is the one confirmed to be fixed by the test recorded above.
