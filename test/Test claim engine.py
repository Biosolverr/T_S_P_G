"""
Direct Mode tests for ClaimEngine -- SINGLE-CONTRACT SCOPE ONLY.

Same real, verified constraint as the parent project's
tests/test_process_graph_router.py: GenVM allows only one contract per
process in Direct Mode, and Direct Mode's pytest fixtures do not install
a cross-contract call hook. Every one of ClaimEngine's write methods
except the very first guard clauses reaches `gl.get_contract_at(...)`
(PolicyRegistry / EvidenceRegistry) before doing anything else, so the
actual business logic of `register_claim` (deposit/limit checks,
storage) and `adjudicate_claim` (the `gl.eq_principle.strict_eq` fetch +
LLM adjudication path) is NOT exercised by this file and cannot be, in
Direct Mode.

What IS verified here, for real: constructor behaviour and address
coercion, and every guard clause that fires BEFORE any cross-contract
call -- which turns out to be all of `invalidate_claim`, `expire_claim`,
`withdraw`, `withdraw_protocol_sink`, every view, and the
`PredicateType` / `scope` validation at the top of `register_claim`.

Cross-contract-dependent behavior (a real register_claim + adjudicate_claim
end to end, including the strict_eq / VERDICT / HASH_MISMATCH /
SIZE_EXCEEDED paths) is verified live against GenLayer Studio instead --
see TEST_RESULTS.md.

Run with:
    pip install genlayer-test
    pytest tests/test_claim_engine.py -v
"""

CONTRACT_PATH = "contracts/claim_engine.py"
SDK_VERSION = "v0.2.16"


def _ensure_sdk_loaded():
    """`create_address` resolves to raw `bytes` instead of a real
    `Address` if called before the SDK paths are set up (which normally
    happens as a side effect of the first `direct_deploy()` call) --
    same documented quirk as the parent project's other Direct Mode
    test files. Force setup explicitly so `_addr()` always returns a
    real `Address`, regardless of call order within a test."""
    from pathlib import Path

    from gltest.direct.sdk_loader import setup_sdk_paths

    setup_sdk_paths(Path(CONTRACT_PATH), SDK_VERSION)


def _addr(seed: str):
    _ensure_sdk_loaded()
    from gltest.direct.loader import create_address

    return create_address(seed)


def _deploy(direct_deploy, policy_registry_address, evidence_registry_address, admin_address):
    return direct_deploy(
        CONTRACT_PATH,
        policy_registry_address,
        evidence_registry_address,
        admin_address,
        sdk_version=SDK_VERSION,
    )


def _deploy_default(direct_deploy):
    policy_addr = _addr("policy_registry")
    evidence_addr = _addr("evidence_registry")
    admin = _addr("admin")
    contract = _deploy(direct_deploy, policy_addr, evidence_addr, str(admin))
    return contract, policy_addr, evidence_addr, admin


REGISTER_CLAIM_ARGS = dict(
    process_commitment=b"\x01" * 32,
    policy_id=b"\x02" * 32,
    policy_version=1,
    expected_policy_commitment=b"\x03" * 32,
    subject_commitment=b"\x04" * 32,
    subject_description="500 items of product X200",
    predicate_type="QuantityAtLeast",
    predicate_value=500,
    predicate_unit="ITEMS",
    predicate_date=0,
    predicate_attribute_key="",
    predicate_attribute_value="",
    predicate_substring="",
    evidence_id=1,
    expected_evidence_commitment=b"\x05" * 32,
    schema_version="1.0.0",
    scope="PROCESS",
    now=1_788_684_041,
)


def _register_claim(contract, **overrides):
    args = dict(REGISTER_CLAIM_ARGS)
    args.update(overrides)
    return contract.register_claim(
        args["process_commitment"],
        args["policy_id"],
        args["policy_version"],
        args["expected_policy_commitment"],
        args["subject_commitment"],
        args["subject_description"],
        args["predicate_type"],
        args["predicate_value"],
        args["predicate_unit"],
        args["predicate_date"],
        args["predicate_attribute_key"],
        args["predicate_attribute_value"],
        args["predicate_substring"],
        args["evidence_id"],
        args["expected_evidence_commitment"],
        args["schema_version"],
        args["scope"],
        args["now"],
    )


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
    evidence_addr = _addr("evidence_registry")
    admin = _addr("admin")
    policy_int = int.from_bytes(policy_addr.as_bytes, "big")
    evidence_int = int.from_bytes(evidence_addr.as_bytes, "big")
    contract = _deploy(direct_deploy, policy_int, evidence_int, str(admin))
    assert contract is not None


# --------------------------------------------------------------------- #
# register_claim: validation that happens BEFORE any cross-contract call
# --------------------------------------------------------------------- #


def test_register_claim_rejects_unknown_predicate_type_before_any_cross_contract_call(direct_vm, direct_deploy):
    """`PredicateType(predicate_type)` is the very first thing
    `register_claim` does after coercing its bytes arguments -- this
    fires before `gl.get_contract_at(...)` is ever reached, so it is
    genuinely exercisable in Direct Mode."""
    contract, *_ = _deploy_default(direct_deploy)
    alice = _addr("alice")
    with direct_vm.prank(alice):
        with direct_vm.expect_revert():
            _register_claim(contract, predicate_type="NotARealPredicate")


def test_register_claim_rejects_negative_quantity_before_any_cross_contract_call(direct_vm, direct_deploy):
    """Regression test for finding #8 (session 2026-09-14): the
    predicate_value >= 0 check for QuantityAtLeast/QuantityEquals sits
    right after the PredicateType check, also before any cross-contract
    call, so it's exercisable here too."""
    contract, *_ = _deploy_default(direct_deploy)
    alice = _addr("alice")
    with direct_vm.prank(alice):
        with direct_vm.expect_revert("predicate_value must be >= 0"):
            _register_claim(contract, predicate_type="QuantityAtLeast", predicate_value=-500)


# --------------------------------------------------------------------- #
# invalidate_claim / expire_claim: "unknown claim_id" fires before any
# cross-contract call, and claims can never exist in this environment
# --------------------------------------------------------------------- #


def test_invalidate_unknown_claim_reverts(direct_vm, direct_deploy):
    contract, *_ = _deploy_default(direct_deploy)
    with direct_vm.expect_revert("unknown claim_id"):
        contract.invalidate_claim(b"\x99" * 32)


def test_expire_unknown_claim_reverts(direct_vm, direct_deploy):
    contract, *_ = _deploy_default(direct_deploy)
    with direct_vm.expect_revert("unknown claim_id"):
        contract.expire_claim(b"\x99" * 32, 1_788_684_041)


def test_adjudicate_unknown_claim_reverts(direct_vm, direct_deploy):
    contract, *_ = _deploy_default(direct_deploy)
    with direct_vm.expect_revert("unknown claim_id"):
        contract.adjudicate_claim(b"\x99" * 32, 1_788_684_041)


# --------------------------------------------------------------------- #
# withdraw / withdraw_protocol_sink: no cross-contract calls at all
# --------------------------------------------------------------------- #


def test_withdraw_nothing_reverts(direct_vm, direct_deploy):
    contract, *_ = _deploy_default(direct_deploy)
    alice = _addr("alice")
    with direct_vm.prank(alice):
        with direct_vm.expect_revert("nothing to withdraw"):
            contract.withdraw()


def test_get_withdrawable_zero_for_unknown_address(direct_vm, direct_deploy):
    contract, *_ = _deploy_default(direct_deploy)
    alice = _addr("alice")
    assert int(contract.get_withdrawable(str(alice))) == 0


def test_withdraw_protocol_sink_rejects_non_admin(direct_vm, direct_deploy):
    contract, _, _, admin = _deploy_default(direct_deploy)
    mallory = _addr("mallory")
    with direct_vm.prank(mallory):
        with direct_vm.expect_revert("only admin"):
            contract.withdraw_protocol_sink(str(mallory))


def test_withdraw_protocol_sink_empty_reverts_for_admin(direct_vm, direct_deploy):
    contract, _, _, admin = _deploy_default(direct_deploy)
    with direct_vm.prank(admin):
        with direct_vm.expect_revert("protocol sink is empty"):
            contract.withdraw_protocol_sink(str(admin))


# --------------------------------------------------------------------- #
# views on an unknown claim_id
# --------------------------------------------------------------------- #


def test_get_state_unknown_claim_reverts(direct_vm, direct_deploy):
    contract, *_ = _deploy_default(direct_deploy)
    with direct_vm.expect_revert("unknown claim_id"):
        contract.get_state(b"\x99" * 32)


def test_get_provenance_unknown_claim_reverts(direct_vm, direct_deploy):
    contract, *_ = _deploy_default(direct_deploy)
    with direct_vm.expect_revert("unknown claim_id"):
        contract.get_provenance(b"\x99" * 32)


def test_get_predicate_fields_unknown_claim_reverts(direct_vm, direct_deploy):
    contract, *_ = _deploy_default(direct_deploy)
    with direct_vm.expect_revert("unknown claim_id"):
        contract.get_predicate_fields(b"\x99" * 32)


def test_get_deposit_amount_unknown_claim_reverts(direct_vm, direct_deploy):
    """get_deposit_amount was added for ProcessGraph's dispute-window
    bond comparison (finding #2, session 2026-09-14)."""
    contract, *_ = _deploy_default(direct_deploy)
    with direct_vm.expect_revert("unknown claim_id"):
        contract.get_deposit_amount(b"\x99" * 32)


def test_verify_commitment_false_for_unknown_claim(direct_vm, direct_deploy):
    contract, *_ = _deploy_default(direct_deploy)
    assert contract.verify_commitment(b"\x99" * 32) is False


def test_claim_id_accepted_as_plain_int_in_views(direct_vm, direct_deploy):
    """Regression test: bytes-typed view arguments also go through
    `_coerce_bytes`, so an unknown claim expressed as a plain int should
    revert with the same clean message as bytes, not a coercion error."""
    contract, *_ = _deploy_default(direct_deploy)
    unknown_claim_as_int = int.from_bytes(b"\x99" * 32, "big")
    with direct_vm.expect_revert("unknown claim_id"):
        contract.get_state(unknown_claim_as_int)
