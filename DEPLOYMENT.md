# Deployment

## Required order

Deploy in this exact order. Each later contract needs the address of an earlier one.

1. `policy_registry.py`. Constructor takes no arguments.
2. `evidence_registry.py`. Constructor takes no arguments.
3. `claim_engine.py`. Constructor: `(policy_registry_address: Address, evidence_registry_address: Address, admin_address: str)`.
4. `process_graph.py`. Constructor: `(policy_registry_address: Address, claim_engine_address: Address)`.

`admin_address` gates `PolicyRegistry`-independent admin actions on `ClaimEngine`, specifically
`withdraw_protocol_sink`. Pass the deploying account's address as a plain string, for example
`0xd3e5F03720031D71A7c6766C39f36dD7ef3F28B8`.

If you lose track of which addresses a deployed `ClaimEngine` was actually given (for example after
a long session, or if Studio's own transaction history for that contract has been cleared), call
its view method `get_registry_addresses()`, which returns
`(policy_registry_address, evidence_registry_address)` as plain strings. There is no equivalent
getter on `ProcessGraph` for its own two constructor addresses at this time; if in doubt, redeploy
it with addresses you have verified independently.

## Redeploy discipline

Redeploying any of the four files produces a new address and empty storage. If you redeploy
`policy_registry.py` or `evidence_registry.py`, you must redeploy `claim_engine.py` and
`process_graph.py` with the new addresses in their constructors, and re-run every step from
scratch: policy registration, evidence commit, claim registration, graph construction. There is no
migration path between deployments.

If you redeploy only `claim_engine.py`, you must redeploy `process_graph.py` too, since its
constructor points at the old `claim_engine` address, and any process, node, slot, or claim state
held by the old deployment is gone.

Two things are easy to lose track of across a long session and are worth checking explicitly before
assuming a redeploy is clean:

- A contract tab left open in Studio from an earlier deployment can silently continue pointing at
  an old address after you believe you have redeployed. If a call behaves as though state exists
  that you did not expect (an unexpected `evidence_id` counter value, a policy that is inexplicably
  inactive), check the actual deployed address in Studio's contract details rather than assuming
  the tab reflects your latest deployment.
- A freshly deployed `EvidenceRegistry` always issues `evidence_id` starting at `1`. If a
  `commit_evidence` call on what you believe is a fresh deployment returns any other starting
  value, that deployment is not actually fresh; check the same thing.

## Filling constructor address fields in GenLayer Studio

Studio's deploy form fields for `Address` typed constructor arguments accept a plain `0x...`
string; paste it with no extra characters and no quotes. See `KNOWN_ISSUES.md` for the calldata
quirk this triggers on the wire, and why the contracts already defend against it internally
(`_coerce_address`).

## Environment

All four contracts are pinned to:

```
# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
```

Do not change this pin without re-running the full manual test suite in `TESTING.md`. Several
workarounds described in `KNOWN_ISSUES.md` are specific to defects in this exact build and may not
be needed, or may need to be replaced with something else entirely, on a different build.

## Before calling any write method

Read `TESTING.md` in full before making calls. In particular:

- Every `bytes` and `Address` typed argument can be typed into Studio's form as a `0x...` hex
  string; the contracts internally normalize whatever representation Studio actually sends on the
  wire (see `KNOWN_ISSUES.md`).
- Timestamps are caller-supplied (an explicit `now: u64` argument) on every method that needs the
  current time, not read from the chain. See `SECURITY.md`, "Caller-supplied time", for why, and
  for what this does and does not protect against.
- `ClaimEngine.register_claim`'s `scope` argument only accepts `"PROCESS"` in this version;
  `"POLICY"` and `"GLOBAL"` are defined in the enum but explicitly rejected as not implemented.
- `predicate_unit` only accepts `GRAMS`, `KG`, or `ITEMS`.
- `retrieval_hint_uri` on `EvidenceRegistry.commit_evidence` must be `http://` or `https://`.
  GenVM's non-deterministic web fetch does not support `ipfs://` or any other scheme.
- `ClaimEngine.register_claim` is payable. Attach a transaction value at least equal to the
  policy's `min_deposit`. In GenLayer Studio, the "Value (GEN)" field on the call form takes a
  plain GEN amount (for example `1` for one GEN), not the raw base-unit integer used everywhere
  else in this system's fields; do not confuse the two. As of this revision, a `register_claim`
  call that is rejected after value was attached does not raise an exception; it returns a string
  starting with `"REJECTED: "` and credits the sent value to the sender's withdrawable balance,
  recoverable via `withdraw()`. See `SECURITY.md` for why this is necessary and what it does not
  cover.
- `ProcessGraph.bind_slot` no longer resolves a slot immediately on a `TRUE`/`FALSE` verdict; it
  opens a dispute window and moves the slot to `PENDING`. Call `ProcessGraph.finalize_slot` after
  `DISPUTE_WINDOW_SECONDS` (3600) has elapsed, using a caller-supplied `now` at least that far past
  the `now` given to `bind_slot`, to move the slot to `RESOLVED`. `finalize_process` will refuse to
  finalize while any reachable slot is `OPEN` or `PENDING`.
