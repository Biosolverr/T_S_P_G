# TSPG — Steward Request Resubmission: Verification Results

This document records the on-chain verification performed on GenLayer Studio for each of the
five points raised in the steward's "Action needed" request on **Trust Semantic Process Graph**
(contribution ID `6c747760…`), after the corresponding fixes were applied to the contracts.

All transactions below are FINALIZED on GenLayer Studio. Addresses, process/node/slot/claim ids
and transaction hashes are as actually produced by the deployment; nothing here is simulated.

---

## Summary

| # | Steward's point | Status | Evidence |
|---|---|---|---|
| 1 | Evidence-state eligibility not enforced | **Fixed & verified** | §1 below |
| 2 | Validator requirement configured but not effective | **Removed (field deleted)** | §2 below |
| 3 | Caller-controlled dispute/freshness timing | **Fixed & verified** | §3 below |
| 4 | Challenge deposits refundable while still counted as bonds | **Fixed & verified** | §4 below |
| 5 | Withdrawals could consume credit without moving value | **Fixed & verified** | §5 below |

---

## Deployed contracts (this test run)

| Contract | Role |
|---|---|
| PolicyRegistry | unchanged logic, `min_unique_validators` field removed |
| EvidenceRegistry | `commit_evidence` no longer takes `submitted_at`; added `is_eligible` |
| ClaimEngine | no caller-supplied `now`; added `get_bond`, `is_evidence_eligible`, `release_deposit`, `set_process_graph`; verified payout path |
| ProcessGraph | no caller-supplied `now`; `bind_slot`/`finalize_slot` now consult evidence eligibility and the claim's held bond |

`ClaimEngine.set_process_graph` was called once (admin) to wire the reverse link needed by
`release_deposit`'s dispute-lock check.

Policy used throughout:

```
policy_id: 0x1980d07b10fb96ea16cc2fb9c73ab810e419158aace2aae6e5ba5cb73df8e6e5
version: 1
predicate_rules: ["QuantityAtLeast"]
evidence_max_age_seconds: 2592000
evidence_freshness_on_expiry: UNKNOWN
graph_limits: max_claims_per_process=20, max_evidence_size=5242880, max_graph_depth=10,
              max_graph_edges=100, max_graph_nodes=50, max_predicate_size=4096
protocol_version / schema_version: 1.0.0
allow_revocation_retry: false
min_deposit: 1000000000000000000 (1 GEN)
```

`register_policy` tx: `0xd3627bc9737dc5350afcabc6ab013ef2158899e15f1aa53f21845fb0465a37a2`
`POLICY_COMMIT`: `0x2294dadaefb578e672dea7026463ae42a44dd3a6c7d850111e798f54c0ab2e88`

Register call carried **no `min_unique_validators` argument** — see §2.

---

## §1 — Evidence-state eligibility (point 1)

Two parallel runs were made to show the contrast: same process logic, same predicate, only the
evidence's lifecycle state differs.

### Run A — evidence gets REVOKED after a TRUE verdict

1. `EvidenceRegistry.commit_evidence` (evidence_id **2**)
   tx `0x370ed7f5ee8628179c4bec7e2deadc3eece38838361ee25543015f2b9ec9dafb`
2. `ClaimEngine.register_claim` against evidence_id 2 → claim
   `0x2618a239f00f29e5c35b9c8269a116a79f55615c5167715edd48f4a54f8527cc`
   tx `0xfa46bb311e07b36d7159fb8e8d59ea2343d3c2edc19791134b17b76a5efd62ac`
3. `ClaimEngine.adjudicate_claim` → **TRUE**
   tx `0x942b3b63a1019352fad5956c3b65c8affe29695ca8b64628736a61699cfe3932`
4. `ProcessGraph.bind_slot` (slot `0xdbdb9c85…1e4d7`) → **PENDING**
   tx `0x728942544542a1a5e24183acd83fb2b383a1fdf59fa1383b4e14eecf93a7d107`
5. `EvidenceRegistry.set_state(evidence_id=2, REVOKED)` — **applied to the evidence backing the
   already-bound TRUE claim**
   tx `0x9f27b8a650a64adae2afb44ba95ccac3d52919d62e0926ff7e4174e8d9b5a8f4`
6. After the dispute window elapsed, `ProcessGraph.finalize_slot(slot 0xdbdb9c85…)`:
   **result `LOCKED`, NOT `RESOLVED`**
   tx `0x847314c52aa74a50f272f1b1b1eeebbc07ef1f3003f0cb209e7e70101db1550e`

   This is the direct evidence that eligibility is enforced where it matters: a slot cannot
   lock in a verdict whose backing evidence has since been revoked. `allow_revocation_retry` is
   `false` on this policy, so the slot locked rather than reopening — matching spec.

7. `ClaimEngine.release_deposit` on the now-unlocked claim → `SUCCESS`, `1000000000000000000`
   returned (tx `0x547edf25d1d0d9eae280e2e7786778ecb82e69ec6d3fe7d5ee6f2b923fe0de94`)

### Run B — control, evidence stays valid

1. `EvidenceRegistry.commit_evidence` (evidence_id **3**, same artifact, never revoked)
   tx `0xb5305a3187368cf81367f002a10d274ae0e41c1c76bcc0b43a9126d67f134076`
2. `ClaimEngine.register_claim` → claim
   `0xcbba7a4201c60be18ba1f1f648c2b3e63b000aeb35500c6803272e9e41cec60b`
   tx `0x6c7684c9a5b8687796fb1b595558c395a90d9c369b5ff192c721a83754948a7b`
3. `adjudicate_claim` → **TRUE** (tx `0x4bfeec1a88bf9441ad73b3f3c7f1b8bb5cdc4ff56fd36bbf414bae9baed93985`)
4. `bind_slot` on a second process (slot `0x1f9e9327…e7c3d`) → **PENDING**
   tx `0x5ac691c7afc863e5c8324719c8f03c6320118ca9e21ff4fea29d78199f4d7731`
5. After the window elapsed, `finalize_slot` → **`RESOLVED`**
   tx `0xc9785777682204218dc746b507d93c51dc05e917491d3de4db09c0b6534eb518`
6. `finalize_process` → **`TRUE`**
   tx `0xaec6b5fee4ff357d67d0ded02dc7155aca4fa7faa0b87d3c299a9f6e5f493c06`

Same mechanism, different evidence state, different (correct) outcome: **`LOCKED` vs
`RESOLVED`→`TRUE`**.

---

## §2 — Validator requirement (point 2)

The `min_unique_validators` field, its `QuorumRules` type, and its getter were removed entirely
from `PolicyRegistry` and from the hashed `PolicyContent`. It could never be enforced — contract
code cannot see or count which validators voted on a `gl.eq_principle.strict_eq` round — so
instead of leaving a configurable-but-unenforceable field in place, it was deleted. The
`register_policy` call above (tx `0xd3627bc9…`) carries no such argument, confirming the field is
gone from the live deployment.

---

## §3 — Caller-controlled timing (point 3)

No method on any of the four contracts accepts a caller-supplied `now` any more. All timing
(`created_at`, `asserted_at`, evidence `submitted_at`, the dispute window, the stuck-adjudication
timeout) is read from `gl.message_raw["datetime"]` — the consensus transaction datetime, fixed by
the round and identical for every validator.

Direct proof it cannot be bypassed:

- `ProcessGraph.finalize_slot` called **before** the window elapsed → reverted with
  `dispute window has not elapsed yet`, agreed by all responding validators
  (tx `0xa4e37f64d81b610d7da973e4ec17e8b71c8135b691120c345216d2432d8c582e`).
- `EvidenceRegistry.get_submitted_at(1)` returned `1790621790` — a real, current unix timestamp —
  with no timestamp ever supplied by the caller in `commit_evidence`.

---

## §4 — Challenge deposits locked until dispute resolution (point 4)

- While the slot was `PENDING` (Run A, after step 4 above), `ClaimEngine.release_deposit` was
  called on the bound claim and **reverted**:
  `deposit is locked: this claim is the pending candidate of a slot whose dispute is unresolved`
  (tx `0x8d89d7099f3804c0a1b7694bfdf3e8858e9132c4e35e8702051a543da469a228`, agreed by 4/4
  responding validators). `get_withdrawable` was confirmed `0` immediately after.
- `ClaimEngine.get_bond` on the pending claim returned the full
  `1000000000000000000` while `PENDING` (tx result, see transcript), proving the deposit is
  still being counted as a bond, not sitting refunded.
- Once the slot left `PENDING` (via `finalize_slot`, either outcome), `is_claim_locked` flipped to
  `false` and `release_deposit` succeeded in full for both runs:
  - Run A: tx `0x547edf25d1d0d9eae280e2e7786778ecb82e69ec6d3fe7d5ee6f2b923fe0de94`
  - Run B: tx `0x555422162a03fe97c566d9763ecef18ed4bf9ffd5fdc776d801ac412340d2a89`
  - `get_bond` on both claims returned `0` afterward, confirming a released deposit can never be
    double-counted as a bond.

---

## §5 — Withdrawals use a verified transfer path (point 5)

`ClaimEngine.withdraw` now refuses to debit a user's credited balance unless the documented
EVM-interface payout path (`gl.evm.contract_interface` → `emit_transfer`) is available in the
runtime, the contract's own balance covers the amount, and — after the emit — the balance has
actually dropped by exactly that amount. The old `gl.get_contract_at(eoa).emit_transfer(...)`
form, which silently moves nothing to a wallet, is no longer used anywhere.

On this deployment:

- `get_withdrawable` showed `2000000000000000000` (2 GEN, from the two `release_deposit` calls
  above).
- `ClaimEngine.withdraw()` → **SUCCESS**, returned `2000000000000000000`
  (tx `0xa02315d409df268e532afefc4d1c792ddf4bb69834527ea987f453ce081dbaef`), confirming
  `gl.evm.contract_interface` is available on this build.
- `get_withdrawable` immediately after → `0`. The credit was only zeroed once the verified
  transfer path actually ran, not before.

---

## Transaction index (chronological)

| Step | Method | Tx hash |
|---|---|---|
| register_policy | PolicyRegistry | 0xd3627bc9737dc5350afcabc6ab013ef2158899e15f1aa53f21845fb0465a37a2 |
| commit_evidence (id 1, superseded — hash mismatch, see below) | EvidenceRegistry | 0x370ed7f5ee8628179c4bec7e2deadc3eece38838361ee25543015f2b9ec9dafb |
| create_process (run A) | ProcessGraph | (see get_process_commitment below) |
| get_process_commitment (run A) | ProcessGraph | result: 0xd7ec4222aa7a6f5fc142b6b428c7aaf1af8e5a11c9ead644498288d6fe268249 |
| register_claim (id 1, rejected hash mismatch, deposit forfeited) | ClaimEngine | 0x92ff34f3fcb6876e11e84b6a9c2caa3bb64a63d6f73af59189c6ba38aa3af8cc |
| adjudicate_claim → UNKNOWN (HASH_MISMATCH, deposit forfeited to sink) | ClaimEngine | 0xba87edf0f173b4303169a6e43a0bab1a1c7720cf42444beea27a10765a61bb97 |
| commit_evidence (id 2, correct hash) | EvidenceRegistry | 0x9d7bc9db5baeab0827ef486fae4960ff996865a186fe71ac8bdeebb3986bf429 |
| register_claim (id 2) → claim 0x2618a239… | ClaimEngine | 0xfa46bb311e07b36d7159fb8e8d59ea2343d3c2edc19791134b17b76a5efd62ac |
| adjudicate_claim → TRUE | ClaimEngine | 0x942b3b63a1019352fad5956c3b65c8affe29695ca8b64628736a61699cfe3932 |
| bind_slot → PENDING | ProcessGraph | 0x728942544542a1a5e24183acd83fb2b383a1fdf59fa1383b4e14eecf93a7d107 |
| release_deposit (reverted — locked) | ClaimEngine | 0x8d89d7099f3804c0a1b7694bfdf3e8858e9132c4e35e8702051a543da469a228 |
| finalize_slot (reverted — window not elapsed) | ProcessGraph | 0xa4e37f64d81b610d7da973e4ec17e8b71c8135b691120c345216d2432d8c582e |
| set_state(evidence 2 → REVOKED) | EvidenceRegistry | 0x9f27b8a650a64adae2afb44ba95ccac3d52919d62e0926ff7e4174e8d9b5a8f4 |
| finalize_slot → LOCKED | ProcessGraph | 0x847314c52aa74a50f272f1b1b1eeebbc07ef1f3003f0cb209e7e70101db1550e |
| release_deposit → SUCCESS, 1 GEN | ClaimEngine | 0x547edf25d1d0d9eae280e2e7786778ecb82e69ec6d3fe7d5ee6f2b923fe0de94 |
| commit_evidence (id 3, control) | EvidenceRegistry | 0xb5305a3187368cf81367f002a10d274ae0e41c1c76bcc0b43a9126d67f134076 |
| create_process (run B) | ProcessGraph | 0x998e58d9add0adb3b0b29550e15748e66355fcfca3c222c224ffc5be1de914e6 |
| add_node | ProcessGraph | 0xb4d456d70d91faf701209fd96c1da8833ead78e5df6c0e68407818fa3bd790eb |
| add_claim_slot | ProcessGraph | 0x0e17ade032ca03f5b37ab4c957b198d2d18e4e4d80fb55cb1a409c1d8f77819d |
| commit_process | ProcessGraph | 0xbdaf934b47cfd44bc348224121721ad4cb2c77fef9b2bf61fe51c1d568608bfa |
| activate_process | ProcessGraph | 0x0b2527ab302a11a625999bb7ca74103c33dc997de0632bbc77fb618f03560051 |
| register_claim (id 3) → claim 0xcbba7a42… | ClaimEngine | 0x6c7684c9a5b8687796fb1b595558c395a90d9c369b5ff192c721a83754948a7b |
| adjudicate_claim → TRUE | ClaimEngine | 0x4bfeec1a88bf9441ad73b3f3c7f1b8bb5cdc4ff56fd36bbf414bae9baed93985 |
| bind_slot → PENDING | ProcessGraph | 0x5ac691c7afc863e5c8324719c8f03c6320118ca9e21ff4fea29d78199f4d7731 |
| finalize_slot → RESOLVED | ProcessGraph | 0xc9785777682204218dc746b507d93c51dc05e917491d3de4db09c0b6534eb518 |
| release_deposit → SUCCESS, 1 GEN | ClaimEngine | 0x555422162a03fe97c566d9763ecef18ed4bf9ffd5fdc776d801ac412340d2a89 |
| finalize_process → TRUE | ProcessGraph | 0xaec6b5fee4ff357d67d0ded02dc7155aca4fa7faa0b87d3c299a9f6e5f493c06 |
| withdraw → SUCCESS, 2 GEN | ClaimEngine | 0xa02315d409df268e532afefc4d1c792ddf4bb69834527ea987f453ce081dbaef |

Note: the first `register_claim`/`adjudicate_claim` pair (evidence_id 1) resolved to `UNKNOWN` on
a `HASH_MISMATCH` — the gist's rendered content had changed since the artifact hash was first
computed, unrelated to the contract fix. That deposit was correctly forfeited to the protocol
sink, which is itself a working piece of the deposit-settlement logic. It was superseded by
evidence_id 2 with the up-to-date hash, used in Run A above.
