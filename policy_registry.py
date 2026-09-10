# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
from genlayer import *
# policy_registry.py -- single-file GenVM build. See project chat history for design notes.
import dataclasses
from dataclasses import dataclass
import enum
import hashlib
from typing import Any


# =====================================================================
# Inlined from tspg/canonicalization.py - keep in sync by hand.
# =====================================================================

class CanonicalizationError(ValueError):
    """Raised on any input that cannot be canonicalized deterministically."""


_TAG_NONE = b"\x00"
_TAG_BOOL = b"\x01"
_TAG_INT = b"\x02"
_TAG_STR = b"\x03"
_TAG_BYTES = b"\x04"
_TAG_ENUM = b"\x05"
_TAG_SEQ = b"\x06"
_TAG_MAP = b"\x07"
_TAG_DATACLASS = b"\x08"


def _length_prefixed(b: bytes) -> bytes:
    return len(b).to_bytes(4, "big") + b


def canonicalize(value: Any) -> bytes:
    if isinstance(value, bool):
        return _TAG_BOOL + (b"\x01" if value else b"\x00")
    if value is None:
        return _TAG_NONE
    if isinstance(value, float):
        raise CanonicalizationError(
            "float encountered during canonicalization - use integer/"
            "fixed-point representations only (spec S14)"
        )
    if isinstance(value, int):
        sign = b"\x01" if value < 0 else b"\x00"
        magnitude = abs(value).to_bytes((abs(value).bit_length() + 7) // 8 or 1, "big")
        return _TAG_INT + sign + _length_prefixed(magnitude)
    if isinstance(value, str):
        return _TAG_STR + _length_prefixed(value.encode("utf-8"))
    if isinstance(value, (bytes, bytearray)):
        return _TAG_BYTES + _length_prefixed(bytes(value))
    if isinstance(value, enum.Enum):
        qualified_name = f"{type(value).__module__}.{type(value).__qualname__}"
        return (
            _TAG_ENUM
            + _length_prefixed(qualified_name.encode("utf-8"))
            + _length_prefixed(str(value.value).encode("utf-8"))
        )
    if isinstance(value, (tuple, list)):
        parts = [canonicalize(item) for item in value]
        body = b"".join(_length_prefixed(p) for p in parts)
        return _TAG_SEQ + len(parts).to_bytes(4, "big") + body
    if isinstance(value, dict):
        if not all(isinstance(k, str) for k in value.keys()):
            raise CanonicalizationError(
                f"dict keys must be str for canonicalization - got a non-str key in {value!r}"
            )
        items = sorted(value.items(), key=lambda kv: kv[0])
        body = b"".join(
            _length_prefixed(canonicalize(k)) + _length_prefixed(canonicalize(v))
            for k, v in items
        )
        return _TAG_MAP + len(items).to_bytes(4, "big") + body
    if dataclasses.is_dataclass(value):
        fields = dataclasses.fields(value)
        body = b"".join(
            _length_prefixed(f.name.encode("utf-8"))
            + _length_prefixed(canonicalize(getattr(value, f.name)))
            for f in fields
        )
        return _TAG_DATACLASS + len(fields).to_bytes(4, "big") + body
    raise CanonicalizationError(
        f"no canonical encoding defined for type {type(value)!r} - "
        "add explicit handling rather than falling back to str()/repr()"
    )


# =====================================================================
# Inlined from tspg/models.py - only what this contract needs.
# =====================================================================

class PredicateType(str, enum.Enum):
    QUANTITY_AT_LEAST = "QuantityAtLeast"
    QUANTITY_EQUALS = "QuantityEquals"
    DATE_BEFORE = "DateBefore"
    DATE_EQUALS = "DateEquals"
    ATTRIBUTE_EQUALS = "AttributeEquals"
    ARTIFACT_CONTAINS = "ArtifactContains"


class FreshnessOnExpiry(str, enum.Enum):
    """Never FALSE - see spec S21."""
    UNKNOWN = "UNKNOWN"
    INVALIDATED = "INVALIDATED"


@dataclasses.dataclass(frozen=True)
class QuorumRules:
    min_unique_validators: int


@dataclasses.dataclass(frozen=True)
class GraphLimits:
    max_graph_nodes: int
    max_graph_edges: int
    max_graph_depth: int
    max_claims_per_process: int
    max_evidence_size: int
    max_predicate_size: int


@dataclasses.dataclass(frozen=True)
class PolicyContent:
    """The immutable, hashed payload of a policy version. Binds
    policy_id and version into the hash itself. `authority_rules_commitment`
    is opaque bytes - authority resolution is out of scope for this MVP."""
    policy_id: bytes
    version: int
    predicate_rules: tuple
    quorum_rules: QuorumRules
    evidence_max_age_seconds: int
    evidence_freshness_on_expiry: FreshnessOnExpiry
    authority_rules_commitment: bytes
    graph_limits: GraphLimits
    protocol_version: str
    schema_version: str
    allow_revocation_retry: bool
    min_deposit: int


# =====================================================================
# Inlined from tspg/commitments.py - only commit_policy.
# =====================================================================

_DOMAIN_POLICY = b"TSPG:POLICY:v1"


def commit_policy(content: PolicyContent) -> bytes:
    """Hashes ONLY the immutable PolicyContent - never the mutable
    `active` flag."""
    payload = _DOMAIN_POLICY + b":" + content.schema_version.encode("utf-8") + b":" + canonicalize(content)
    return hashlib.sha256(payload).digest()


# =====================================================================
# Contract-specific storage + logic (unchanged from the multi-file build)
# =====================================================================

@allow_storage
@dataclass
class StoredGraphLimits:
    max_graph_nodes: u32
    max_graph_edges: u32
    max_graph_depth: u32
    max_claims_per_process: u32
    max_evidence_size: u32
    max_predicate_size: u32


@allow_storage
@dataclass
class StoredPolicyRecord:
    policy_id: bytes
    version: u32
    registrant: str                               # gates set_active()
    predicate_rules: str  # comma-joined PredicateType values; DynArray[str] cannot be freshly constructed in this runtime
    min_unique_validators: u32
    evidence_max_age_seconds: u64
    evidence_freshness_on_expiry: str
    authority_rules_commitment: bytes
    graph_limits: StoredGraphLimits
    protocol_version: str
    schema_version: str
    allow_revocation_retry: bool
    min_deposit: u256
    policy_hash: bytes
    active: bool


def _policy_key(policy_id: bytes) -> str:
    return policy_id.hex()


def _to_content(stored: StoredPolicyRecord) -> PolicyContent:
    return PolicyContent(
        policy_id=stored.policy_id,
        version=int(stored.version),
        predicate_rules=tuple(PredicateType(p) for p in stored.predicate_rules.split(",") if p),
        quorum_rules=QuorumRules(min_unique_validators=int(stored.min_unique_validators)),
        evidence_max_age_seconds=int(stored.evidence_max_age_seconds),
        evidence_freshness_on_expiry=FreshnessOnExpiry(stored.evidence_freshness_on_expiry),
        authority_rules_commitment=stored.authority_rules_commitment,
        graph_limits=GraphLimits(
            max_graph_nodes=int(stored.graph_limits.max_graph_nodes),
            max_graph_edges=int(stored.graph_limits.max_graph_edges),
            max_graph_depth=int(stored.graph_limits.max_graph_depth),
            max_claims_per_process=int(stored.graph_limits.max_claims_per_process),
            max_evidence_size=int(stored.graph_limits.max_evidence_size),
            max_predicate_size=int(stored.graph_limits.max_predicate_size),
        ),
        protocol_version=stored.protocol_version,
        schema_version=stored.schema_version,
        allow_revocation_retry=stored.allow_revocation_retry,
        min_deposit=int(stored.min_deposit),
    )


def _coerce_bytes(val, length: int = 32) -> bytes:
    """Defensive coercion for bytes-typed public method arguments.

    VERIFIED NEEDED (Studio): the call/deploy form serializes a pasted hex
    value as a plain int for bytes-typed fields (same root cause as
    _coerce_address in this codebase) -- GenVM does not coerce the
    incoming value to the annotated type at the call boundary. Reconstructs
    to a fixed `length`-byte big-endian representation (32 = the sha256
    digest size used throughout this file) so a hash with leading zero
    bytes round-trips correctly instead of being silently truncated.
    """
    if isinstance(val, (bytes, bytearray, memoryview)):
        return bytes(val)
    if isinstance(val, bool):
        raise gl.vm.UserError(f"invalid bytes value: {val!r}")
    if isinstance(val, int):
        try:
            return val.to_bytes(length, "big")
        except OverflowError:
            raise gl.vm.UserError(f"invalid bytes value: {val!r}")
    if isinstance(val, str):
        s = val[2:] if val.startswith(("0x", "0X")) else val
        try:
            return bytes.fromhex(s)
        except ValueError:
            return val.encode("utf-8")
    raise gl.vm.UserError(f"unsupported bytes value type: {type(val)}")


class PolicyRegistry(gl.Contract):
    policies: TreeMap[str, TreeMap[u32, StoredPolicyRecord]]

    def __init__(self):
        pass

    @gl.public.write
    def register_policy(
        self,
        policy_id: bytes,
        version: u32,
        predicate_rules: list[str],
        min_unique_validators: u32,
        evidence_max_age_seconds: u64,
        evidence_freshness_on_expiry: str,
        authority_rules_commitment: bytes,
        graph_limits: dict[str, int],
        protocol_version: str,
        schema_version: str,
        allow_revocation_retry: bool,
        min_deposit: u256,
    ) -> str:
        """Register a brand-new immutable policy version. NEVER allows
        overwriting an existing (policy_id, version) pair (spec S3)."""
        policy_id = _coerce_bytes(policy_id)
        authority_rules_commitment = _coerce_bytes(authority_rules_commitment)
        key = _policy_key(policy_id)

        if key in self.policies and version in self.policies[key]:
            raise Exception("policy version already registered - cannot mutate an existing version")

        if int(min_unique_validators) < 1:
            raise Exception("min_unique_validators must be >= 1 (spec S36)")

        for pr in predicate_rules:
            PredicateType(pr)  # fail closed on unknown predicate type

        if evidence_max_age_seconds > 0:
            FreshnessOnExpiry(evidence_freshness_on_expiry)

        predicate_rules_str = ",".join(predicate_rules)

        stored = StoredPolicyRecord(
            policy_id=policy_id,
            version=version,
            registrant=str(gl.message.sender_address),
            predicate_rules=predicate_rules_str,
            min_unique_validators=min_unique_validators,
            evidence_max_age_seconds=evidence_max_age_seconds,
            evidence_freshness_on_expiry=evidence_freshness_on_expiry,
            authority_rules_commitment=authority_rules_commitment,
            graph_limits=StoredGraphLimits(
                max_graph_nodes=u32(graph_limits["max_graph_nodes"]),
                max_graph_edges=u32(graph_limits["max_graph_edges"]),
                max_graph_depth=u32(graph_limits["max_graph_depth"]),
                max_claims_per_process=u32(graph_limits["max_claims_per_process"]),
                max_evidence_size=u32(graph_limits["max_evidence_size"]),
                max_predicate_size=u32(graph_limits["max_predicate_size"]),
            ),
            protocol_version=protocol_version,
            schema_version=schema_version,
            allow_revocation_retry=allow_revocation_retry,
            min_deposit=min_deposit,
            policy_hash=b"",
            active=True,
        )

        content = _to_content(stored)
        policy_hash = commit_policy(content)
        stored.policy_hash = policy_hash

        if key not in self.policies:
            self.policies[key] = TreeMap[u32, StoredPolicyRecord]()
        self.policies[key][version] = stored

        return policy_hash.hex()

    @gl.public.write
    def set_active(self, policy_id: bytes, version: u32, active: bool) -> None:
        """Toggle eligibility for NEW process commitments only -
        restricted to the original registrant."""
        policy_id = _coerce_bytes(policy_id)
        key = _policy_key(policy_id)
        if key not in self.policies or version not in self.policies[key]:
            raise Exception("unknown policy version")
        record = self.policies[key][version]
        if str(gl.message.sender_address) != record.registrant:
            raise Exception("only the original registrant may change a policy version's active flag")
        record.active = active

    @gl.public.view
    def get_policy_hash(self, policy_id: bytes, version: u32) -> str:
        policy_id = _coerce_bytes(policy_id)
        key = _policy_key(policy_id)
        if key not in self.policies or version not in self.policies[key]:
            raise Exception("unknown policy version")
        return self.policies[key][version].policy_hash.hex()

    @gl.public.view
    def is_active(self, policy_id: bytes, version: u32) -> bool:
        policy_id = _coerce_bytes(policy_id)
        key = _policy_key(policy_id)
        if key not in self.policies or version not in self.policies[key]:
            return False
        return self.policies[key][version].active

    @gl.public.view
    def verify_commitment(self, policy_id: bytes, version: u32, expected_hash: bytes) -> bool:
        policy_id = _coerce_bytes(policy_id)
        expected_hash = _coerce_bytes(expected_hash)
        key = _policy_key(policy_id)
        if key not in self.policies or version not in self.policies[key]:
            return False
        stored = self.policies[key][version]
        recomputed = commit_policy(_to_content(stored))
        return recomputed == expected_hash

    @gl.public.view
    def get_min_unique_validators(self, policy_id: bytes, version: u32) -> u32:
        policy_id = _coerce_bytes(policy_id)
        key = _policy_key(policy_id)
        if key not in self.policies or version not in self.policies[key]:
            raise Exception("unknown policy version")
        return self.policies[key][version].min_unique_validators

    @gl.public.view
    def get_graph_limits(self, policy_id: bytes, version: u32) -> tuple[u32, u32, u32, u32, u32, u32]:
        policy_id = _coerce_bytes(policy_id)
        key = _policy_key(policy_id)
        if key not in self.policies or version not in self.policies[key]:
            raise Exception("unknown policy version")
        gl_ = self.policies[key][version].graph_limits
        return (
            gl_.max_graph_nodes, gl_.max_graph_edges, gl_.max_graph_depth,
            gl_.max_claims_per_process, gl_.max_evidence_size, gl_.max_predicate_size,
        )

    @gl.public.view
    def get_allow_revocation_retry(self, policy_id: bytes, version: u32) -> bool:
        policy_id = _coerce_bytes(policy_id)
        key = _policy_key(policy_id)
        if key not in self.policies or version not in self.policies[key]:
            raise Exception("unknown policy version")
        return self.policies[key][version].allow_revocation_retry

    @gl.public.view
    def get_freshness(self, policy_id: bytes, version: u32) -> tuple[u64, str]:
        policy_id = _coerce_bytes(policy_id)
        key = _policy_key(policy_id)
        if key not in self.policies or version not in self.policies[key]:
            raise Exception("unknown policy version")
        s = self.policies[key][version]
        return (s.evidence_max_age_seconds, s.evidence_freshness_on_expiry)

    @gl.public.view
    def get_min_deposit(self, policy_id: bytes, version: u32) -> u256:
        policy_id = _coerce_bytes(policy_id)
        key = _policy_key(policy_id)
        if key not in self.policies or version not in self.policies[key]:
            raise Exception("unknown policy version")
        return self.policies[key][version].min_deposit
