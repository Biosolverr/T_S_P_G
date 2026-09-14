"""
Direct Mode tests for ProcessGraph -- SINGLE-CONTRACT SCOPE ONLY.

Same constraint as test_claim_engine.py: `create_process` reaches
`gl.get_contract_at(self.policy_registry_address)` immediately, before
any local validation runs, so no process can ever be created in this
environment, and everything downstream of a process existing
(`add_node`, `add_claim_slot`, `commit_process`, `bind_slot`, `evaluate`,
`finalize_process`'s actual graph-evaluation logic) is unreachable here.

What IS verified here, for real: constructor behaviour and address
coercion, and the "unknown process_id" / "unknown slot_id" guard clause
that every one of those methods checks FIRST, before touching anything
else -- since `self.processes` / `self.slots` can never contain anything
in this environment, every one of those guard clauses is reliably
exercised.

The actual graph semantics (AND/OR/NOT/THRESHOLD evaluation, cycle
detection, depth/edge limits, bind_slot's cross-contract predicate
verification) are verified live against GenLayer Studio instead -- see
TEST_RESULTS.md.

Run with:
    pip install genlayer-test
    pytest tests/test_process_graph.py -v
"""

CONTRACT_PATH = "contracts/process_graph.py"
SDK_VERSION = "v0.2.16"


def _ensure_sdk_loaded():
    from pathlib import Path

    from gltest.direct.sdk_loader import setup_sdk_paths

    setup_sdk_paths(Path(CONTRACT_PATH), SDK_VERSION)


def _addr(seed: str):
    _ensure_sdk_loaded()
    from gltest.direct.loader import create_address

    return create_address(seed)


def _deploy(direct_deploy, policy_registry_address, claim_engine_address):
    return direct_deploy(
        CONTRACT_PATH,
        policy_registry_address,
        claim_engine_address,
        sdk_version=SDK_VERSION,
    )


def _deploy_default(direct_deploy):
    policy_addr = _addr("policy_registry")
    claim_addr = _addr("claim_engine")
    contract = _deploy(direct_deploy, policy_addr, claim_addr)
    return contract, policy_addr, claim_addr


# --------------------------------------------------------------------- #
# constructor
# --------------------------------------------------------------------- #


def test_constructor_succeeds(direct_vm, direct_deploy):
    contract, *_ = _deploy_default(direct_deploy)
    assert contract is not None


def test_constructor_accepts_addresses_as_plain_int(direct_vm, direct_deploy):
    """Regression test for the documented Studio bug: Address-typed
    constructor arguments arrive as plain int."""
    policy_addr = _addr("policy_registry")
    claim_addr = _addr("claim_engine")
    policy_int = int.from_bytes(policy_addr.as_bytes, "big")
    claim_int = int.from_bytes(claim_addr.as_bytes, "big")
    contract = _deploy(direct_deploy, policy_int, claim_int)
    assert contract is not None


# --------------------------------------------------------------------- #
# every write method's "unknown process_id" / "unknown slot_id" guard --
# reliably reachable since no process/slot can ever exist here
# --------------------------------------------------------------------- #


def test_add_node_unknown_process_reverts(direct_vm, direct_deploy):
    contract, *_ = _deploy_default(direct_deploy)
    with direct_vm.expect_revert("unknown process_id"):
        contract.add_node(b"\x99" * 32, b"\x01" * 32, "CLAIM", [], 0)


def test_add_claim_slot_unknown_process_reverts(direct_vm, direct_deploy):
    contract, *_ = _deploy_default(direct_deploy)
    with direct_vm.expect_revert("unknown process_id"):
        contract.add_claim_slot(
            b"\x99" * 32, b"\x01" * 32, b"\x02" * 32,
            "QuantityAtLeast", 500, "ITEMS", 0, "", "", "",
            b"\x03" * 32,
        )


def test_commit_process_unknown_process_reverts(direct_vm, direct_deploy):
    contract, *_ = _deploy_default(direct_deploy)
    with direct_vm.expect_revert("unknown process_id"):
        contract.commit_process(b"\x99" * 32, b"\x01" * 32, 1_788_684_041)


def test_activate_process_unknown_process_reverts(direct_vm, direct_deploy):
    contract, *_ = _deploy_default(direct_deploy)
    with direct_vm.expect_revert("unknown process_id"):
        contract.activate_process(b"\x99" * 32)


def test_cancel_process_unknown_process_reverts(direct_vm, direct_deploy):
    contract, *_ = _deploy_default(direct_deploy)
    with direct_vm.expect_revert("unknown process_id"):
        contract.cancel_process(b"\x99" * 32)


def test_bind_slot_unknown_slot_reverts(direct_vm, direct_deploy):
    contract, *_ = _deploy_default(direct_deploy)
    with direct_vm.expect_revert("unknown slot_id"):
        contract.bind_slot(b"\x99" * 32, b"\x01" * 32, 1_788_684_041)


def test_finalize_slot_unknown_slot_reverts(direct_vm, direct_deploy):
    """finalize_slot (added alongside the dispute-window fix for finding
    #2, session 2026-09-14) -- unreachable past this guard for the same
    reason as everything else in this file: no slot can ever exist in
    Direct Mode."""
    contract, *_ = _deploy_default(direct_deploy)
    with direct_vm.expect_revert("unknown slot_id"):
        contract.finalize_slot(b"\x99" * 32, 1_788_684_041)


def test_evaluate_unknown_process_reverts(direct_vm, direct_deploy):
    contract, *_ = _deploy_default(direct_deploy)
    with direct_vm.expect_revert("unknown process_id"):
        contract.evaluate(b"\x99" * 32)


def test_finalize_process_unknown_process_reverts(direct_vm, direct_deploy):
    contract, *_ = _deploy_default(direct_deploy)
    with direct_vm.expect_revert("unknown process_id"):
        contract.finalize_process(b"\x99" * 32, 1_788_684_041)


def test_get_process_commitment_unknown_process_reverts(direct_vm, direct_deploy):
    contract, *_ = _deploy_default(direct_deploy)
    with direct_vm.expect_revert("unknown process_id"):
        contract.get_process_commitment(b"\x99" * 32)


def test_get_state_unknown_process_reverts(direct_vm, direct_deploy):
    contract, *_ = _deploy_default(direct_deploy)
    with direct_vm.expect_revert("unknown process_id"):
        contract.get_state(b"\x99" * 32)


def test_get_final_result_unknown_process_reverts(direct_vm, direct_deploy):
    contract, *_ = _deploy_default(direct_deploy)
    with direct_vm.expect_revert("unknown process_id"):
        contract.get_final_result(b"\x99" * 32)


def test_get_slot_state_unknown_slot_reverts(direct_vm, direct_deploy):
    contract, *_ = _deploy_default(direct_deploy)
    with direct_vm.expect_revert("unknown slot_id"):
        contract.get_slot_state(b"\x99" * 32)


def test_process_id_accepted_as_plain_int(direct_vm, direct_deploy):
    """Regression test: bytes-typed arguments accepted as plain int,
    still reverting with the same clean message rather than a coercion
    error."""
    contract, *_ = _deploy_default(direct_deploy)
    unknown_process_as_int = int.from_bytes(b"\x99" * 32, "big")
    with direct_vm.expect_revert("unknown process_id"):
        contract.get_state(unknown_process_as_int)
