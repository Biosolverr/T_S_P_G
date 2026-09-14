"""
Direct Mode tests for PolicyRegistry.

Framework: `genlayer-test` (pip install genlayer-test), Direct Mode.
Verified in this session against genlayer-test==0.29.2 / genvm v0.2.16,
matching the pinned build in KNOWN_ISSUES.md
(py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6).

PolicyRegistry has no cross-contract dependencies, so unlike ClaimEngine
and ProcessGraph, its entire write surface is exercisable here -- this
file is NOT limited to guard-clause/constructor coverage.

Run with:
    pip install genlayer-test
    pytest tests/test_policy_registry.py -v
"""

CONTRACT_PATH = "contracts/policy_registry.py"
SDK_VERSION = "v0.2.16"


def _addr(seed: str):
    from gltest.direct.loader import create_address

    return create_address(seed)


def _deploy(direct_deploy):
    return direct_deploy(CONTRACT_PATH, sdk_version=SDK_VERSION)


GRAPH_LIMITS = {
    "max_graph_nodes": 50,
    "max_graph_edges": 100,
    "max_graph_depth": 10,
    "max_claims_per_process": 20,
    "max_evidence_size": 5_242_880,
    "max_predicate_size": 4096,
}


def _register(
    contract,
    policy_id=b"\x01" * 32,
    version=1,
    predicate_rules=None,
    min_unique_validators=3,
    evidence_max_age_seconds=2_592_000,
    evidence_freshness_on_expiry="UNKNOWN",
    authority_rules_commitment=b"\x02" * 32,
    graph_limits=None,
    protocol_version="1.0.0",
    schema_version="1.0.0",
    allow_revocation_retry=False,
    min_deposit=10**18,
):
    return contract.register_policy(
        policy_id,
        version,
        predicate_rules if predicate_rules is not None else ["QuantityAtLeast"],
        min_unique_validators,
        evidence_max_age_seconds,
        evidence_freshness_on_expiry,
        authority_rules_commitment,
        graph_limits if graph_limits is not None else dict(GRAPH_LIMITS),
        protocol_version,
        schema_version,
        allow_revocation_retry,
        min_deposit,
    )


# --------------------------------------------------------------------- #
# register_policy: happy path + immutability
# --------------------------------------------------------------------- #


def test_register_policy_returns_commitment(direct_vm, direct_deploy):
    contract = _deploy(direct_deploy)
    alice = _addr("alice")
    with direct_vm.prank(alice):
        policy_hash = _register(contract)
    assert isinstance(policy_hash, str)
    assert len(policy_hash) == 64  # sha256 hex digest, no 0x prefix
    assert contract.get_policy_hash(b"\x01" * 32, 1) == policy_hash


def test_register_policy_is_active_by_default(direct_vm, direct_deploy):
    contract = _deploy(direct_deploy)
    alice = _addr("alice")
    with direct_vm.prank(alice):
        _register(contract)
    assert contract.is_active(b"\x01" * 32, 1) is True


def test_cannot_overwrite_existing_version(direct_vm, direct_deploy):
    contract = _deploy(direct_deploy)
    alice = _addr("alice")
    with direct_vm.prank(alice):
        _register(contract)
        with direct_vm.expect_revert("already registered"):
            _register(contract)


def test_same_policy_id_different_version_allowed(direct_vm, direct_deploy):
    contract = _deploy(direct_deploy)
    alice = _addr("alice")
    with direct_vm.prank(alice):
        h1 = _register(contract, version=1)
        h2 = _register(contract, version=2, min_unique_validators=5)
    assert h1 != h2
    assert contract.is_active(b"\x01" * 32, 1) is True
    assert contract.is_active(b"\x01" * 32, 2) is True


def test_different_policy_id_same_version_allowed(direct_vm, direct_deploy):
    contract = _deploy(direct_deploy)
    alice = _addr("alice")
    with direct_vm.prank(alice):
        _register(contract, policy_id=b"\x01" * 32, version=1)
        _register(contract, policy_id=b"\x03" * 32, version=1)
    assert contract.is_active(b"\x01" * 32, 1) is True
    assert contract.is_active(b"\x03" * 32, 1) is True


def test_policy_id_accepted_as_plain_int(direct_vm, direct_deploy):
    """Regression test for the documented Studio bug (KNOWN_ISSUES.md #3):
    bytes-typed arguments arrive as plain int from Studio's calldata
    builder."""
    contract = _deploy(direct_deploy)
    alice = _addr("alice")
    policy_id_bytes = b"\x01" * 32
    policy_id_int = int.from_bytes(policy_id_bytes, "big")
    with direct_vm.prank(alice):
        _register(contract, policy_id=policy_id_int)
    assert contract.is_active(policy_id_bytes, 1) is True


# --------------------------------------------------------------------- #
# register_policy: validation
# --------------------------------------------------------------------- #


def test_min_unique_validators_must_be_positive(direct_vm, direct_deploy):
    contract = _deploy(direct_deploy)
    alice = _addr("alice")
    with direct_vm.prank(alice):
        with direct_vm.expect_revert("min_unique_validators"):
            _register(contract, min_unique_validators=0)


def test_unknown_predicate_type_rejected(direct_vm, direct_deploy):
    contract = _deploy(direct_deploy)
    alice = _addr("alice")
    with direct_vm.prank(alice):
        with direct_vm.expect_revert():
            _register(contract, predicate_rules=["NotARealPredicate"])


def test_unknown_freshness_on_expiry_rejected_when_freshness_enabled(direct_vm, direct_deploy):
    """FreshnessOnExpiry is only validated when evidence_max_age_seconds > 0
    (spec S21 -- see the enum's docstring: it must never be able to
    resolve to FALSE)."""
    contract = _deploy(direct_deploy)
    alice = _addr("alice")
    with direct_vm.prank(alice):
        with direct_vm.expect_revert():
            _register(
                contract,
                evidence_max_age_seconds=1000,
                evidence_freshness_on_expiry="FALSE",
            )


def test_unknown_freshness_rejected_even_when_freshness_disabled(direct_vm, direct_deploy):
    """Regression test: `evidence_freshness_on_expiry` is part of the
    hashed PolicyContent regardless of whether evidence_max_age_seconds
    is 0, so it must be validated unconditionally, with a clean
    gl.vm.UserError-style message -- not left to fail a few lines later
    as a raw, uncaught ValueError out of `_to_content`. (Found via this
    test originally failing against the unfixed contract; see the
    comment above the fix in register_policy.)"""
    contract = _deploy(direct_deploy)
    alice = _addr("alice")
    with direct_vm.prank(alice):
        with direct_vm.expect_revert("invalid evidence_freshness_on_expiry"):
            _register(
                contract,
                evidence_max_age_seconds=0,
                evidence_freshness_on_expiry="literally anything",
            )


# --------------------------------------------------------------------- #
# set_active: authorization + effect
# --------------------------------------------------------------------- #


def test_only_registrant_can_deactivate(direct_vm, direct_deploy):
    contract = _deploy(direct_deploy)
    alice, mallory = _addr("alice"), _addr("mallory")
    with direct_vm.prank(alice):
        _register(contract)
    with direct_vm.prank(mallory):
        with direct_vm.expect_revert("only the original registrant"):
            contract.set_active(b"\x01" * 32, 1, False)
    assert contract.is_active(b"\x01" * 32, 1) is True


def test_registrant_can_deactivate_and_reactivate(direct_vm, direct_deploy):
    contract = _deploy(direct_deploy)
    alice = _addr("alice")
    with direct_vm.prank(alice):
        _register(contract)
        contract.set_active(b"\x01" * 32, 1, False)
    assert contract.is_active(b"\x01" * 32, 1) is False
    with direct_vm.prank(alice):
        contract.set_active(b"\x01" * 32, 1, True)
    assert contract.is_active(b"\x01" * 32, 1) is True


def test_set_active_on_unknown_version_reverts(direct_vm, direct_deploy):
    contract = _deploy(direct_deploy)
    alice = _addr("alice")
    with direct_vm.prank(alice):
        with direct_vm.expect_revert("unknown policy version"):
            contract.set_active(b"\x99" * 32, 1, False)


def test_deactivating_does_not_change_the_hash(direct_vm, direct_deploy):
    """policy_hash covers only immutable content (see commit_policy's
    docstring: 'never the mutable active flag')."""
    contract = _deploy(direct_deploy)
    alice = _addr("alice")
    with direct_vm.prank(alice):
        before = contract.get_policy_hash(b"\x01" * 32, 1) if False else None
        h = _register(contract)
        contract.set_active(b"\x01" * 32, 1, False)
    assert contract.get_policy_hash(b"\x01" * 32, 1) == h


# --------------------------------------------------------------------- #
# views: unknown-version behavior and correctness against stored content
# --------------------------------------------------------------------- #


def test_is_active_false_for_unknown_version(direct_vm, direct_deploy):
    contract = _deploy(direct_deploy)
    assert contract.is_active(b"\x99" * 32, 1) is False


def test_verify_commitment_false_for_unknown_version(direct_vm, direct_deploy):
    contract = _deploy(direct_deploy)
    assert contract.verify_commitment(b"\x99" * 32, 1, b"\x00" * 32) is False


def test_verify_commitment_true_for_correct_hash(direct_vm, direct_deploy):
    contract = _deploy(direct_deploy)
    alice = _addr("alice")
    with direct_vm.prank(alice):
        h = _register(contract)
    assert contract.verify_commitment(b"\x01" * 32, 1, bytes.fromhex(h)) is True


def test_verify_commitment_false_for_wrong_hash(direct_vm, direct_deploy):
    contract = _deploy(direct_deploy)
    alice = _addr("alice")
    with direct_vm.prank(alice):
        _register(contract)
    assert contract.verify_commitment(b"\x01" * 32, 1, b"\xff" * 32) is False


def test_get_min_unique_validators_matches_input(direct_vm, direct_deploy):
    contract = _deploy(direct_deploy)
    alice = _addr("alice")
    with direct_vm.prank(alice):
        _register(contract, min_unique_validators=7)
    assert contract.get_min_unique_validators(b"\x01" * 32, 1) == 7


def test_get_graph_limits_matches_input(direct_vm, direct_deploy):
    contract = _deploy(direct_deploy)
    alice = _addr("alice")
    with direct_vm.prank(alice):
        _register(contract)
    limits = contract.get_graph_limits(b"\x01" * 32, 1)
    assert tuple(limits) == (50, 100, 10, 20, 5_242_880, 4096)


def test_get_freshness_matches_input(direct_vm, direct_deploy):
    contract = _deploy(direct_deploy)
    alice = _addr("alice")
    with direct_vm.prank(alice):
        _register(contract, evidence_max_age_seconds=999, evidence_freshness_on_expiry="INVALIDATED")
    max_age, on_expiry = contract.get_freshness(b"\x01" * 32, 1)
    assert int(max_age) == 999
    assert on_expiry == "INVALIDATED"


def test_get_min_deposit_matches_input(direct_vm, direct_deploy):
    contract = _deploy(direct_deploy)
    alice = _addr("alice")
    with direct_vm.prank(alice):
        _register(contract, min_deposit=42)
    assert int(contract.get_min_deposit(b"\x01" * 32, 1)) == 42


def test_get_allow_revocation_retry_matches_input(direct_vm, direct_deploy):
    contract = _deploy(direct_deploy)
    alice = _addr("alice")
    with direct_vm.prank(alice):
        _register(contract, allow_revocation_retry=True)
    assert contract.get_allow_revocation_retry(b"\x01" * 32, 1) is True


def test_views_revert_on_unknown_version(direct_vm, direct_deploy):
    contract = _deploy(direct_deploy)
    for method, args in [
        ("get_policy_hash", (b"\x99" * 32, 1)),
        ("get_min_unique_validators", (b"\x99" * 32, 1)),
        ("get_graph_limits", (b"\x99" * 32, 1)),
        ("get_allow_revocation_retry", (b"\x99" * 32, 1)),
        ("get_freshness", (b"\x99" * 32, 1)),
        ("get_min_deposit", (b"\x99" * 32, 1)),
    ]:
        with direct_vm.expect_revert("unknown policy version"):
            getattr(contract, method)(*args)
