"""
Direct Mode tests for EvidenceRegistry.

Framework: `genlayer-test` (pip install genlayer-test), Direct Mode.
Verified in this session against genlayer-test==0.29.2 / genvm v0.2.16.

EvidenceRegistry has no cross-contract dependencies, so its entire write
surface is exercisable here.

Run with:
    pip install genlayer-test
    pytest test/test_evidence_registry.py -v
"""

CONTRACT_PATH = "contracts/evidense_registry.py"
SDK_VERSION = "v0.2.16"


def _addr(seed: str):
    from gltest.direct.loader import create_address

    return create_address(seed)


def _deploy(direct_deploy):
    return direct_deploy(CONTRACT_PATH, sdk_version=SDK_VERSION)


def _commit(
    contract,
    artifact_hash=b"\x11" * 32,
    artifact_size=445,
    mime_type="text/plain",
    authority_commitment=b"\x22" * 32,
    scope_commitment=b"\x33" * 32,
    retrieval_hint_uri="https://example.com/evidence.txt",
    schema_version="1.0.0",
):
    return contract.commit_evidence(
        artifact_hash,
        artifact_size,
        mime_type,
        authority_commitment,
        scope_commitment,
        retrieval_hint_uri,
        schema_version,
    )


def _param_names(method_name):
    """Parameter names of a contract method, read from the contract source
    (Direct Mode proxies do not expose signatures)."""
    import ast
    tree = ast.parse(open(CONTRACT_PATH).read())
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == method_name:
            return [a.arg for a in node.args.args]
    raise AssertionError(f"{method_name} not found in {CONTRACT_PATH}")


def _set_tx_time(direct_vm, iso):
    """Direct Mode's warp() does not refresh gl.message_raw['datetime'],
    which is what the contracts read -- patch it explicitly as well."""
    direct_vm.warp(iso)
    from genlayer import gl
    gl.message_raw["datetime"] = iso


# --------------------------------------------------------------------- #
# commit_evidence: happy path, identity, and monotonically increasing ids
# --------------------------------------------------------------------- #


def test_commit_evidence_returns_id_and_commitment(direct_vm, direct_deploy):
    contract = _deploy(direct_deploy)
    alice = _addr("alice")
    with direct_vm.prank(alice):
        evidence_id, commitment = _commit(contract)
    assert int(evidence_id) == 1
    assert isinstance(commitment, str)
    assert len(commitment) == 64


def test_evidence_ids_increment(direct_vm, direct_deploy):
    contract = _deploy(direct_deploy)
    alice = _addr("alice")
    with direct_vm.prank(alice):
        id1, _ = _commit(contract, artifact_hash=b"\x11" * 32)
        id2, _ = _commit(contract, artifact_hash=b"\x12" * 32)
    assert int(id2) == int(id1) + 1


def test_commit_evidence_records_creator(direct_vm, direct_deploy):
    """`creator` isn't independently exposed by any getter, but
    `set_state`'s authorization check depends on it -- verified
    indirectly below in the set_state tests."""
    contract = _deploy(direct_deploy)
    alice = _addr("alice")
    with direct_vm.prank(alice):
        evidence_id, _ = _commit(contract)
    assert contract.get_state(evidence_id) == "COMMITTED"


def test_empty_artifact_hash_rejected(direct_vm, direct_deploy):
    contract = _deploy(direct_deploy)
    alice = _addr("alice")
    with direct_vm.prank(alice):
        with direct_vm.expect_revert("artifact_hash must not be empty"):
            _commit(contract, artifact_hash=b"")


def test_zero_artifact_size_rejected(direct_vm, direct_deploy):
    contract = _deploy(direct_deploy)
    alice = _addr("alice")
    with direct_vm.prank(alice):
        with direct_vm.expect_revert("artifact_size must be > 0"):
            _commit(contract, artifact_size=0)


def test_artifact_hash_accepted_as_plain_int(direct_vm, direct_deploy):
    """Regression test for the documented Studio bug (bytes arrive as
    int)."""
    contract = _deploy(direct_deploy)
    alice = _addr("alice")
    artifact_hash_bytes = b"\x11" * 32
    artifact_hash_int = int.from_bytes(artifact_hash_bytes, "big")
    with direct_vm.prank(alice):
        evidence_id, _ = _commit(contract, artifact_hash=artifact_hash_int)
    assert contract.get_artifact_hash(evidence_id) == artifact_hash_bytes.hex()


# --------------------------------------------------------------------- #
# set_state: allowed transitions, authorization, illegal transitions
# --------------------------------------------------------------------- #


def test_committed_to_valid_allowed(direct_vm, direct_deploy):
    contract = _deploy(direct_deploy)
    alice = _addr("alice")
    with direct_vm.prank(alice):
        evidence_id, _ = _commit(contract)
        contract.set_state(evidence_id, "VALID")
    assert contract.get_state(evidence_id) == "VALID"


def test_committed_to_invalid_allowed(direct_vm, direct_deploy):
    contract = _deploy(direct_deploy)
    alice = _addr("alice")
    with direct_vm.prank(alice):
        evidence_id, _ = _commit(contract)
        contract.set_state(evidence_id, "INVALID")
    assert contract.get_state(evidence_id) == "INVALID"


def test_committed_to_revoked_allowed(direct_vm, direct_deploy):
    contract = _deploy(direct_deploy)
    alice = _addr("alice")
    with direct_vm.prank(alice):
        evidence_id, _ = _commit(contract)
        contract.set_state(evidence_id, "REVOKED")
    assert contract.get_state(evidence_id) == "REVOKED"


def test_valid_to_revoked_allowed(direct_vm, direct_deploy):
    contract = _deploy(direct_deploy)
    alice = _addr("alice")
    with direct_vm.prank(alice):
        evidence_id, _ = _commit(contract)
        contract.set_state(evidence_id, "VALID")
        contract.set_state(evidence_id, "REVOKED")
    assert contract.get_state(evidence_id) == "REVOKED"


def test_invalid_to_valid_rejected(direct_vm, direct_deploy):
    """Not in the allow-list -- INVALID is meant to be closer to
    terminal than a stepping stone back to VALID."""
    contract = _deploy(direct_deploy)
    alice = _addr("alice")
    with direct_vm.prank(alice):
        evidence_id, _ = _commit(contract)
        contract.set_state(evidence_id, "INVALID")
        with direct_vm.expect_revert("illegal evidence state transition"):
            contract.set_state(evidence_id, "VALID")


def test_revoked_to_anything_rejected(direct_vm, direct_deploy):
    """REVOKED is terminal -- not the source of any allowed transition."""
    contract = _deploy(direct_deploy)
    alice = _addr("alice")
    with direct_vm.prank(alice):
        evidence_id, _ = _commit(contract)
        contract.set_state(evidence_id, "REVOKED")
        with direct_vm.expect_revert("illegal evidence state transition"):
            contract.set_state(evidence_id, "VALID")


def test_committed_to_committed_rejected(direct_vm, direct_deploy):
    """Not a real transition -- also excludes accidental no-op calls
    from silently succeeding."""
    contract = _deploy(direct_deploy)
    alice = _addr("alice")
    with direct_vm.prank(alice):
        evidence_id, _ = _commit(contract)
        with direct_vm.expect_revert("illegal evidence state transition"):
            contract.set_state(evidence_id, "COMMITTED")


def test_only_creator_can_set_state(direct_vm, direct_deploy):
    contract = _deploy(direct_deploy)
    alice, mallory = _addr("alice"), _addr("mallory")
    with direct_vm.prank(alice):
        evidence_id, _ = _commit(contract)
    with direct_vm.prank(mallory):
        with direct_vm.expect_revert("only the original creator"):
            contract.set_state(evidence_id, "VALID")
    assert contract.get_state(evidence_id) == "COMMITTED"


def test_set_state_on_unknown_id_reverts(direct_vm, direct_deploy):
    contract = _deploy(direct_deploy)
    alice = _addr("alice")
    with direct_vm.prank(alice):
        with direct_vm.expect_revert("unknown evidence_id"):
            contract.set_state(999, "VALID")


# --------------------------------------------------------------------- #
# views
# --------------------------------------------------------------------- #


def test_get_artifact_hash_matches_input(direct_vm, direct_deploy):
    contract = _deploy(direct_deploy)
    alice = _addr("alice")
    artifact_hash = b"\xab" * 32
    with direct_vm.prank(alice):
        evidence_id, _ = _commit(contract, artifact_hash=artifact_hash)
    assert contract.get_artifact_hash(evidence_id) == artifact_hash.hex()


def test_get_retrieval_hint_matches_input(direct_vm, direct_deploy):
    contract = _deploy(direct_deploy)
    alice = _addr("alice")
    with direct_vm.prank(alice):
        evidence_id, _ = _commit(contract, retrieval_hint_uri="https://example.com/x")
    assert contract.get_retrieval_hint(evidence_id) == "https://example.com/x"


def test_get_scope_commitment_matches_input(direct_vm, direct_deploy):
    contract = _deploy(direct_deploy)
    alice = _addr("alice")
    scope_commitment = b"\xcd" * 32
    with direct_vm.prank(alice):
        evidence_id, _ = _commit(contract, scope_commitment=scope_commitment)
    assert contract.get_scope_commitment(evidence_id) == scope_commitment.hex()


def test_submitted_at_is_consensus_transaction_time(direct_vm, direct_deploy):
    """submitted_at is no longer a caller argument: it is parsed from
    gl.message_raw["datetime"] (2026-09-27T09:14:14Z == 1790500454)."""
    contract = _deploy(direct_deploy)
    alice = _addr("alice")
    _set_tx_time(direct_vm, "2026-09-27T09:14:14.081651Z")
    with direct_vm.prank(alice):
        evidence_id, _ = _commit(contract)
    assert int(contract.get_submitted_at(evidence_id)) == 1790500454


def test_commit_evidence_has_no_caller_time_argument(direct_vm, direct_deploy):
    assert "submitted_at" not in _param_names("commit_evidence")


def test_is_eligible_follows_evidence_state(direct_vm, direct_deploy):
    contract = _deploy(direct_deploy)
    alice = _addr("alice")
    with direct_vm.prank(alice):
        evidence_id, _ = _commit(contract)
        assert contract.is_eligible(evidence_id) is True          # COMMITTED
        contract.set_state(evidence_id, "VALID")
        assert contract.is_eligible(evidence_id) is True          # VALID
        contract.set_state(evidence_id, "REVOKED")
        assert contract.is_eligible(evidence_id) is False         # REVOKED
    assert contract.is_eligible(999) is False                     # unknown id


def test_is_eligible_false_for_invalid_evidence(direct_vm, direct_deploy):
    contract = _deploy(direct_deploy)
    alice = _addr("alice")
    with direct_vm.prank(alice):
        evidence_id, _ = _commit(contract)
        contract.set_state(evidence_id, "INVALID")
    assert contract.is_eligible(evidence_id) is False


def test_get_artifact_size_matches_input(direct_vm, direct_deploy):
    contract = _deploy(direct_deploy)
    alice = _addr("alice")
    with direct_vm.prank(alice):
        evidence_id, _ = _commit(contract, artifact_size=999)
    assert int(contract.get_artifact_size(evidence_id)) == 999


def test_verify_commitment_true_for_correct_hash(direct_vm, direct_deploy):
    contract = _deploy(direct_deploy)
    alice = _addr("alice")
    with direct_vm.prank(alice):
        evidence_id, commitment = _commit(contract)
    assert contract.verify_commitment(evidence_id, bytes.fromhex(commitment), "1.0.0") is True


def test_verify_commitment_false_for_wrong_hash(direct_vm, direct_deploy):
    contract = _deploy(direct_deploy)
    alice = _addr("alice")
    with direct_vm.prank(alice):
        evidence_id, _ = _commit(contract)
    assert contract.verify_commitment(evidence_id, b"\xff" * 32, "1.0.0") is False


def test_verify_commitment_false_for_unknown_id(direct_vm, direct_deploy):
    contract = _deploy(direct_deploy)
    assert contract.verify_commitment(999, b"\x00" * 32, "1.0.0") is False


def test_views_revert_on_unknown_id(direct_vm, direct_deploy):
    contract = _deploy(direct_deploy)
    for method in (
        "get_artifact_hash",
        "get_state",
        "get_retrieval_hint",
        "get_scope_commitment",
        "get_submitted_at",
        "get_artifact_size",
    ):
        with direct_vm.expect_revert("unknown evidence_id"):
            getattr(contract, method)(999)
