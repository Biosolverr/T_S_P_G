# End-to-end test results

Environment: GenLayer Studio, `py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6`,
Normal (Full Consensus) execution mode. This is the successful run, after the fixes in
`KNOWN_ISSUES.md` were applied. Earlier attempts against the same scenario failed at several of
these steps before each corresponding fix; those are not reproduced here in full, only summarized
at the end.

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
evidence_max_age_seconds: 2592000
evidence_freshness_on_expiry: UNKNOWN
authority_rules_commitment: 0x5549d05a38b595a2074fc1ff08cc88ba2ee18ecc7590267f7cee1dbda95b5f8d
graph_limits: {max_claims_per_process:20, max_evidence_size:5242880, max_graph_depth:10, max_graph_edges:100, max_graph_nodes:50, max_predicate_size:4096}
protocol_version: 1.0.0
schema_version: 1.0.0
allow_revocation_retry: false
min_deposit: 1000000000000000000
```

Result: SUCCESS, FINALIZED.
Output (policy commitment): `0xd876e1de00601114315455f5503eee57335a8ef84a41646b2979e0a06a2ded01`

## 2. EvidenceRegistry.commit_evidence

Input:

```
artifact_hash: 0xe670e0b29a3d01f689521c5584d7529349bab70331ddd2401d9d6ec8041b0996
artifact_size: 445
mime_type: text/plain
authority_commitment: 0x883b4e58592d47b0fcf877274a5d7b911732eb70197433631d6a1902c6791250
submitted_at: 1788684041
scope_commitment: 0xc17e3a0b439497fcf810a13f1c644b24886681f9f7f92cb257f50ec04981af3e
retrieval_hint_uri: https://gist.githubusercontent.com/Biosolverr/73bf862b1ac706ce08c906acf4c9e6d8/raw/a158d8e75e3ec72168922a0ddd46451e99343e30/delivery_confirmation.txt
schema_version: 1.0.0
```

Result: SUCCESS, FINALIZED.
Output: `evidence_id = 6`, `evidence_commitment = 0x4d79ee6843fe1286da368edfd5ec87c76c001763a5b404cb2d7c24a6e8023da5`

`artifact_hash` here is the real sha256 digest of the Gist's raw content, obtained from a prior
attempt's `HASH_MISMATCH:<hash>` diagnostic output rather than guessed; see the failed-attempts
summary below.

## 3. ProcessGraph graph construction

```
create_process(process_id=0xcd3bd00ebf5c26b752bc2c0191229f6b9cdecaad8c11e730e39f0a5e111da20e,
                policy_id=0x1980d07b10fb96ea16cc2fb9c73ab810e419158aace2aae6e5ba5cb73df8e6e5,
                policy_version=1,
                expected_policy_commitment=0xd876e1de00601114315455f5503eee57335a8ef84a41646b2979e0a06a2ded01,
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
-> SUCCESS, graph commitment 0x267771c69fb71589a17fa404bb4249070dd8c33e0f66d5b19ace38dc43976591 (from the run that built this exact graph structure; regenerated as 0x5f0d49418e7297c1fbfcfb7e839d30441d2bb4d632ef7055c7256c47bc7d7705 after a later redeploy of process_graph.py with the same graph, see note below)

activate_process(process_id=...)
-> SUCCESS
```

Note: `process_graph.py` was redeployed once between the first `commit_process` call above and the
final `register_claim` below (to fix the bug described in `KNOWN_ISSUES.md` item 4). The graph was
rebuilt identically on the new deployment, and its commitment was re-read with
`get_process_commitment` immediately before registering the claim, rather than reused from the
first deployment's output. The value actually used downstream is:

```
get_process_commitment(process_id=0xcd3bd00ebf5c26b752bc2c0191229f6b9cdecaad8c11e730e39f0a5e111da20e)
-> 0x5f0d49418e7297c1fbfcfb7e839d30441d2bb4d632ef7055c7256c47bc7d7705
```

## 4. ClaimEngine.register_claim

Input:

```
process_commitment: 0x5f0d49418e7297c1fbfcfb7e839d30441d2bb4d632ef7055c7256c47bc7d7705
policy_id: 0x1980d07b10fb96ea16cc2fb9c73ab810e419158aace2aae6e5ba5cb73df8e6e5
policy_version: 1
expected_policy_commitment: 0xd876e1de00601114315455f5503eee57335a8ef84a41646b2979e0a06a2ded01
subject_commitment: 0xf9d3af1daba426ce2749dd39712cb546a51c3e2a0a11a3f00281ff93d929c491
subject_description: ACME Logistics, PO#2026-08421 delivery to Warehouse 4
predicate_type: QuantityAtLeast
predicate_value: 500
predicate_unit: ITEMS
predicate_date: 0
predicate_attribute_key: (empty)
predicate_attribute_value: (empty)
predicate_substring: (empty)
evidence_id: 6
expected_evidence_commitment: 0x4d79ee6843fe1286da368edfd5ec87c76c001763a5b404cb2d7c24a6e8023da5
schema_version: 1.0.0
scope: PROCESS
now: 1788684041
```

Value attached: `1000000000000000000` (equal to `min_deposit`).

Result: SUCCESS, ACCEPTED then FINALIZED.
Output (claim id): `0x361c848d5bcf8816e3b8ea2f83ace7e007c626076bb7fa37de8788e924da0fc6`

## 5. ClaimEngine.adjudicate_claim

Input: `claim_id = 0x361c848d5bcf8816e3b8ea2f83ace7e007c626076bb7fa37de8788e924da0fc6`, `now = 1788684041`.

Result: SUCCESS, FINALIZED.
Output (claim state): `TRUE`
Equivalence principle output: `VERDICT:TRUE`

The validator set fetched the Gist content over `gl.nondet.web.render`, confirmed its sha256 digest
matched the committed `artifact_hash`, and reached consensus that the content supports "quantity
delivered is at least 500 ITEMS" (the content states 750 units delivered).

## 6. ProcessGraph.bind_slot

Input: `slot_id = 0xdbdb9c8588618f26b977f4b6b0d83ab639f6ac954f249153058fce659f11e4d7`,
`claim_id = 0x361c848d5bcf8816e3b8ea2f83ace7e007c626076bb7fa37de8788e924da0fc6`.

Result: SUCCESS, FINALIZED.
Output (slot state): `RESOLVED`

## 7. ProcessGraph.finalize_process

Input: `process_id = 0xcd3bd00ebf5c26b752bc2c0191229f6b9cdecaad8c11e730e39f0a5e111da20e`, `now = 1788684041`.

Result: SUCCESS, FINALIZED.
Output (final result): `TRUE`

## Summary of failed attempts against this same scenario, and why

For completeness, and because each of these drove a fix now in `KNOWN_ISSUES.md`:

1. `register_policy` failed with a `DynArray` construction error before the item 1 fix.
2. `register_policy` failed with a `TreeMap` assignment error before the item 2 fix.
3. `register_claim` failed with a `bytes`-as-`int` error on `policy_registry_address` before the
   item 3 fix existed on the constructors.
4. `adjudicate_claim` failed with `AttributeError: module 'genlayer.gl' has no attribute 'block'`
   before the item 5 fix (`now` parameters).
5. `register_claim` failed with `invalid scope` when a free-text scope was used instead of
   `PROCESS`.
6. `adjudicate_claim` failed with `PredicateError: unknown unit 'units'` before `predicate_unit`
   was corrected to `ITEMS`.
7. `adjudicate_claim` failed with `SCHEMA_FORBIDDEN` while `retrieval_hint_uri` was an `ipfs://`
   URL; corrected to an `https://` URL.
8. `adjudicate_claim` returned `HASH_MISMATCH` (then, after item 8's fix,
   `HASH_MISMATCH:<real hash>`) twice: once against a placeholder `artifact_hash` for a generic
   `hello.html` test page, and once against a guessed `artifact_hash` for the real Gist content
   before its exact byte-encoding was confirmed.
9. `bind_slot` failed with `claim.process_commitment does not match this process` twice: once
   because `process_commitment` was set to an arbitrary `process_id` value instead of the graph's
   real commitment, and once (after that fix) because of the item 4 (`str` vs `bytes` comparison)
   bug, which was masking the first fix's correctness.
10. `bind_slot` failed with `unknown slot_id` after `process_graph.py` was redeployed to apply the
    item 4 fix, since graph steps 3 above had to be repeated against the new deployment's empty
    storage.
11. `register_claim` failed once with `claim_id collision on registration`, because the exact same
    content had already been registered successfully in an earlier session whose Studio-side
    transaction history was lost to a page reload; the existing claim id was recomputed locally
    from the contract's own canonicalization logic and confirmed with `verify_commitment` rather
    than re-registered.
