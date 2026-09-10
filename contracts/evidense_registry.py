# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
from genlayer import *
# evidence_registry.py -- single-file GenVM build. See project chat history for design notes.
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

class EvidenceState(str, enum.Enum):
    COMMITTED = "COMMITTED"
    VALID = "VALID"
    REVOKED = "REVOKED"
    INVALID = "INVALID"


@dataclasses.dataclass(frozen=True)
class EvidenceContent:
    """Immutable, hashed identity of a piece of evidence. `artifact_hash`
    is the ONLY thing that establishes what artifact this is - a URL is
    never identity (spec S10). `evidence_id` is deliberately NOT part of
    this content: it's a contract-assigned storage key, not semantic
    identity."""
    artifact_hash: bytes
    artifact_size: int
    mime_type: str
    creator: str
    authority_commitment: bytes  # opaque in this MVP - see SECURITY.md
    submitted_at: int
    scope_commitment: bytes


# =====================================================================
# Inlined from tspg/commitments.py - only commit_evidence, with its
# fixed domain tag. Domain-separated per Patch 5 - never reuse this
# tag for another entity type.
# =====================================================================

_DOMAIN_EVIDENCE = b"TSPG:EVIDENCE:v1"


def commit_evidence(content: EvidenceContent, schema_version: str) -> bytes:
    """Hashes ONLY the immutable EvidenceContent - never `state` or
    `retrieval_hint_uri`."""
    payload = _DOMAIN_EVIDENCE + b":" + schema_version.encode("utf-8") + b":" + canonicalize(content)
    return hashlib.sha256(payload).digest()


# =====================================================================
# Contract-specific storage + logic (unchanged from the multi-file build)
# =====================================================================

@allow_storage
@dataclass
class StoredEvidenceContent:
    artifact_hash: bytes
    artifact_size: u32
    mime_type: str
    creator: str
    authority_commitment: bytes
    submitted_at: u64
    scope_commitment: bytes


@allow_storage
@dataclass
class StoredEvidenceRecord:
    content: StoredEvidenceContent
    evidence_commitment: bytes
    state: str            # EvidenceState.value
    retrieval_hint_uri: str


def _to_content(stored: StoredEvidenceContent) -> EvidenceContent:
    return EvidenceContent(
        artifact_hash=stored.artifact_hash,
        artifact_size=int(stored.artifact_size),
        mime_type=stored.mime_type,
        creator=stored.creator,
        authority_commitment=stored.authority_commitment,
        submitted_at=int(stored.submitted_at),
        scope_commitment=stored.scope_commitment,
    )


_ALLOWED_TRANSITIONS = {
    (EvidenceState.COMMITTED.value, EvidenceState.VALID.value),
    (EvidenceState.COMMITTED.value, EvidenceState.INVALID.value),
    (EvidenceState.COMMITTED.value, EvidenceState.REVOKED.value),
    (EvidenceState.VALID.value, EvidenceState.REVOKED.value),
}


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


class EvidenceRegistry(gl.Contract):
    evidence: TreeMap[u32, StoredEvidenceRecord]
    next_evidence_id: u32

    def __init__(self):
        self.next_evidence_id = u32(1)

    @gl.public.write
    def commit_evidence(
        self,
        artifact_hash: bytes,
        artifact_size: u32,
        mime_type: str,
        authority_commitment: bytes,
        submitted_at: u64,
        scope_commitment: bytes,
        retrieval_hint_uri: str,
        schema_version: str,
    ) -> tuple[u32, str]:
        """Commit a new, immutable piece of evidence identity. Returns
        (evidence_id, evidence_commitment). `creator` is
        `gl.message.sender_address` - immutable from this point on (S9)."""
        artifact_hash = _coerce_bytes(artifact_hash)
        authority_commitment = _coerce_bytes(authority_commitment)
        scope_commitment = _coerce_bytes(scope_commitment)
        if len(artifact_hash) == 0:
            raise Exception("artifact_hash must not be empty - a URL alone is never identity (spec S10)")
        if int(artifact_size) == 0:
            raise Exception("artifact_size must be > 0")

        content = StoredEvidenceContent(
            artifact_hash=artifact_hash,
            artifact_size=artifact_size,
            mime_type=mime_type,
            creator=str(gl.message.sender_address),
            authority_commitment=authority_commitment,
            submitted_at=submitted_at,
            scope_commitment=scope_commitment,
        )

        commitment = commit_evidence(_to_content(content), schema_version)

        record = StoredEvidenceRecord(
            content=content,
            evidence_commitment=commitment,
            state=EvidenceState.COMMITTED.value,
            retrieval_hint_uri=retrieval_hint_uri,
        )

        evidence_id = self.next_evidence_id
        self.evidence[evidence_id] = record
        self.next_evidence_id = u32(int(evidence_id) + 1)

        return (evidence_id, commitment.hex())

    @gl.public.write
    def set_state(self, evidence_id: u32, new_state: str) -> None:
        """Explicit, allow-listed lifecycle transition only. No generic
        setter - every jump not on the allow-list is rejected."""
        if evidence_id not in self.evidence:
            raise Exception("unknown evidence_id")
        record = self.evidence[evidence_id]

        if str(gl.message.sender_address) != record.content.creator:
            raise Exception("only the original creator may change evidence state in this MVP")

        transition = (record.state, new_state)
        if transition not in _ALLOWED_TRANSITIONS:
            raise Exception(f"illegal evidence state transition: {record.state} -> {new_state}")

        record.state = new_state

    @gl.public.view
    def get_artifact_hash(self, evidence_id: u32) -> str:
        if evidence_id not in self.evidence:
            raise Exception("unknown evidence_id")
        return self.evidence[evidence_id].content.artifact_hash.hex()

    @gl.public.view
    def get_state(self, evidence_id: u32) -> str:
        if evidence_id not in self.evidence:
            raise Exception("unknown evidence_id")
        return self.evidence[evidence_id].state

    @gl.public.view
    def get_retrieval_hint(self, evidence_id: u32) -> str:
        """NEVER treat this as identity - it exists only so a caller
        knows where to try fetching bytes from (spec S10)."""
        if evidence_id not in self.evidence:
            raise Exception("unknown evidence_id")
        return self.evidence[evidence_id].retrieval_hint_uri

    @gl.public.view
    def verify_commitment(self, evidence_id: u32, expected_hash: bytes, schema_version: str) -> bool:
        """Re-derive the commitment from currently-stored immutable
        content and compare - never trust a caller-supplied
        evidence_commitment blindly (spec S31)."""
        expected_hash = _coerce_bytes(expected_hash)
        if evidence_id not in self.evidence:
            return False
        record = self.evidence[evidence_id]
        recomputed = commit_evidence(_to_content(record.content), schema_version)
        return recomputed == expected_hash

    @gl.public.view
    def get_scope_commitment(self, evidence_id: u32) -> str:
        if evidence_id not in self.evidence:
            raise Exception("unknown evidence_id")
        return self.evidence[evidence_id].content.scope_commitment.hex()

    @gl.public.view
    def get_submitted_at(self, evidence_id: u32) -> u64:
        """Needed by ClaimEngine's freshness check (Patch 4) - staleness
        must be measured against when the EVIDENCE was committed."""
        if evidence_id not in self.evidence:
            raise Exception("unknown evidence_id")
        return self.evidence[evidence_id].content.submitted_at

    @gl.public.view
    def get_artifact_size(self, evidence_id: u32) -> u32:
        """Needed to enforce policy.max_evidence_size - see Finding 11
        in the review history: the REAL check must happen against
        actually-fetched bytes in ClaimEngine, not against this
        caller-asserted number alone, since this contract never fetches
        content itself and cannot verify this value against reality."""
        if evidence_id not in self.evidence:
            raise Exception("unknown evidence_id")
        return self.evidence[evidence_id].content.artifact_size
