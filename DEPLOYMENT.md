# Deployment

## Required order

Deploy in this exact order. Each later contract needs the address of an earlier one.

1. `policy_registry.py`, no constructor arguments.
2. `evidence_registry.py`, no constructor arguments.
3. `claim_engine.py`, constructor: `(policy_registry_address: Address, evidence_registry_address: Address, admin_address: str)`.
4. `process_graph.py`, constructor: `(policy_registry_address: Address, claim_engine_address: Address)`.

`admin_address` gates `PolicyRegistry.set_active` style calls and `ClaimEngine.withdraw_protocol_sink`.
Pass the deploying account's address as a plain string, for example `0xd3e5F03720031D71A7c6766C39f36dD7ef3F28B8`.

## Redeploy discipline

Redeploying any of the four files produces a new address and empty storage. If you redeploy
`policy_registry.py` or `evidence_registry.py`, you must redeploy `claim_engine.py` and
`process_graph.py` with the new addresses in their constructors, and re-run every step from
scratch (policy registration, evidence commit, claim registration, graph construction). There is
no migration path between deployments.

If you redeploy only `claim_engine.py`, you must redeploy `process_graph.py` too, since its
constructor points at the old `claim_engine` address.

## Filling constructor address fields in GenLayer Studio

Studio's deploy form fields for `Address` typed constructor arguments accept a plain `0x...`
string. Paste the address with no extra characters, no quotes. See `KNOWN_ISSUES.md` for a
runtime quirk this triggers and why the contracts already defend against it (`_coerce_address`).

## Environment

All four contracts are pinned to:

```
# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
```

Do not change this pin without re-running the full manual test suite in `TESTING.md`. Several
workarounds in the contract code (see `KNOWN_ISSUES.md`) are specific to bugs in this exact build
and may not be needed, or may need to be replaced with something else, on a different build.

## Before you call any write method

Read `TESTING.md` in full before making calls. In particular:

- Every `bytes` typed argument can be typed into Studio's form as a `0x...` hex string; the
  contracts internally normalize whatever representation Studio actually sends.
- Timestamps are caller supplied (a `now: u64` argument on every method that needs the current
  time), not read from the chain. See `SECURITY.md` for why, and for the trust implication.
- `scope` on `ClaimEngine.register_claim` only accepts `"PROCESS"` in this version; `"POLICY"` and
  `"GLOBAL"` are defined but explicitly rejected as not implemented.
- `predicate_unit` only accepts `GRAMS`, `KG`, or `ITEMS`.
- `retrieval_hint_uri` on `EvidenceRegistry.commit_evidence` must be `http://` or `https://`.
  GenVM's non-deterministic web fetch does not support `ipfs://` or other schemes.
- `ClaimEngine.register_claim` is payable. Attach a transaction value at least equal to the
  policy's `min_deposit`, or the call reverts.
