# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
from genlayer import *
# process_graph.py -- single-file GenVM build. See project chat history for design notes.
import dataclasses
from dataclasses import dataclass
import enum
import hashlib
from typing import Any, Optional


# =====================================================================
# Inlined from tspg/canonicalization.py - keep in sync by hand.
# =====================================================================

class CanonicalizationError(ValueError):
    pass


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
        raise CanonicalizationError("float encountered during canonicalization (spec S14)")
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
            raise CanonicalizationError(f"dict keys must be str, got non-str key in {value!r}")
        items = sorted(value.items(), key=lambda kv: kv[0])
        body = b"".join(
            _length_prefixed(canonicalize(k)) + _length_prefixed(canonicalize(v)) for k, v in items
        )
        return _TAG_MAP + len(items).to_bytes(4, "big") + body
    if dataclasses.is_dataclass(value):
        fields = dataclasses.fields(value)
        body = b"".join(
            _length_prefixed(f.name.encode("utf-8")) + _length_prefixed(canonicalize(getattr(value, f.name)))
            for f in fields
        )
        return _TAG_DATACLASS + len(fields).to_bytes(4, "big") + body
    raise CanonicalizationError(f"no canonical encoding defined for type {type(value)!r}")


# =====================================================================
# Inlined from tspg/models.py - only what this contract needs.
# =====================================================================

class ThreeValued(str, enum.Enum):
    TRUE = "TRUE"
    FALSE = "FALSE"
    UNKNOWN = "UNKNOWN"


class ClaimState(str, enum.Enum):
    REGISTERED = "REGISTERED"
    ADJUDICATING = "ADJUDICATING"
    TRUE = "TRUE"
    FALSE = "FALSE"
    UNKNOWN = "UNKNOWN"
    INVALIDATED = "INVALIDATED"
    EXPIRED = "EXPIRED"


class SlotState(str, enum.Enum):
    OPEN = "OPEN"
    PENDING = "PENDING"
    RESOLVED = "RESOLVED"
    LOCKED = "LOCKED"


# Economic defense against slot-squatting / claim front-running (finding
# #2, session 2026-09-14): register_claim is permissionless and evidence
# authenticity (EvidenceContent.authority_commitment) is not verified
# anywhere in this MVP -- a claim satisfying a slot's predicate proves
# only that its self-hosted evidence is internally consistent with the
# predicate, never that it is genuine. Previously, whichever claim first
# called bind_slot with a TRUE/FALSE verdict won the slot permanently.
# Now, a TRUE/FALSE binding opens a fixed dispute window during which a
# DIFFERENT claim can displace it, but only by posting a strictly larger
# deposit (bond escalation, resetting the window on every successful
# challenge) -- see bind_slot and finalize_slot. This raises the cost of
# the attack (an attacker must be willing to outbid every legitimate
# challenger's deposit) but does not eliminate it: a well-funded attacker
# can still win by posting an arbitrarily large deposit. Not
# policy-configurable in this fix -- a fixed value, to avoid re-versioning
# PolicyRegistry's schema/hash for this.
DISPUTE_WINDOW_SECONDS = 3600


class ProcessState(str, enum.Enum):
    DRAFT = "DRAFT"
    COMMITTED = "COMMITTED"
    ACTIVE = "ACTIVE"
    RESOLVING = "RESOLVING"
    FINALIZED = "FINALIZED"
    CANCELLED = "CANCELLED"
    EXPIRED = "EXPIRED"


class NodeType(str, enum.Enum):
    CLAIM = "CLAIM"
    AND = "AND"
    OR = "OR"
    NOT = "NOT"
    THRESHOLD = "THRESHOLD"


class PredicateType(str, enum.Enum):
    QUANTITY_AT_LEAST = "QuantityAtLeast"
    QUANTITY_EQUALS = "QuantityEquals"
    DATE_BEFORE = "DateBefore"
    DATE_EQUALS = "DateEquals"
    ATTRIBUTE_EQUALS = "AttributeEquals"
    ARTIFACT_CONTAINS = "ArtifactContains"


@dataclasses.dataclass(frozen=True)
class GraphNode:
    node_id: bytes
    node_type: NodeType
    children: tuple
    threshold_k: Optional[int] = None
    claim_slot_id: Optional[bytes] = None


@dataclasses.dataclass(frozen=True)
class Process:
    process_id: bytes
    creator: str
    policy_commitment: bytes
    graph_commitment: bytes
    root_node_id: bytes
    graph_version: int
    created_at: int
    committed_at: Optional[int]


# =====================================================================
# Inlined from tspg/commitments.py - commit_process, commit_graph.
# =====================================================================

_DOMAIN_PROCESS = b"TSPG:PROCESS:v1"
_DOMAIN_GRAPH = b"TSPG:GRAPH:v1"


def commit_process(process: Process, schema_version: str) -> bytes:
    payload = _DOMAIN_PROCESS + b":" + schema_version.encode("utf-8") + b":" + canonicalize(process)
    return hashlib.sha256(payload).digest()


def commit_graph(nodes: tuple, root_node_id: bytes, schema_version: str) -> bytes:
    payload = _DOMAIN_GRAPH + b":" + schema_version.encode("utf-8") + b":" + canonicalize((root_node_id, nodes))
    return hashlib.sha256(payload).digest()


# =====================================================================
# Contract-specific storage + logic (unchanged from the multi-file build)
# =====================================================================

@allow_storage
@dataclass
class StoredGraphNode:
    node_id: bytes
    node_type: str
    children: str  # comma-joined hex-encoded node ids; DynArray[bytes] cannot be freshly constructed in this runtime
    threshold_k: u32
    claim_slot_id: bytes


@allow_storage
@dataclass
class StoredClaimSlot:
    slot_id: bytes
    process_id: bytes
    predicate_type: str
    predicate_value: i64
    predicate_unit: str
    predicate_date: i64
    predicate_attribute_key: str
    predicate_attribute_value: str
    predicate_substring: str
    subject_commitment: bytes
    current_claim_id: bytes
    state: str
    # Added for the bond-escalation dispute window (finding #2, session
    # 2026-09-14): `bound_at` is when `current_claim_id` became the
    # PENDING candidate; `bound_deposit` is that claim's own deposit,
    # cached here so a challenger's deposit can be compared without an
    # extra cross-contract round-trip. Both are meaningless (left at 0)
    # once state is OPEN/RESOLVED/LOCKED.
    bound_at: u64
    bound_deposit: u256


@allow_storage
@dataclass
class StoredProcess:
    process_id: bytes
    creator: str
    policy_id: bytes
    policy_version: u32
    policy_commitment: bytes
    graph_commitment: bytes
    root_node_id: bytes
    schema_version: str
    allow_revocation_retry: bool
    max_graph_nodes: u32
    max_graph_edges: u32
    max_graph_depth: u32
    node_count: u32
    node_ids: str  # comma-joined hex node keys; replaces the nested TreeMap this SDK build can't construct
    created_at: u64
    committed_at: u64
    finalized_at: u64
    final_result: str
    state: str


_ALLOWED_PROCESS_TRANSITIONS = {
    (ProcessState.DRAFT.value, ProcessState.COMMITTED.value),
    (ProcessState.COMMITTED.value, ProcessState.ACTIVE.value),
    (ProcessState.ACTIVE.value, ProcessState.RESOLVING.value),
    (ProcessState.RESOLVING.value, ProcessState.FINALIZED.value),
    (ProcessState.DRAFT.value, ProcessState.CANCELLED.value),
    (ProcessState.COMMITTED.value, ProcessState.CANCELLED.value),
    (ProcessState.ACTIVE.value, ProcessState.CANCELLED.value),
    (ProcessState.ACTIVE.value, ProcessState.EXPIRED.value),
    (ProcessState.RESOLVING.value, ProcessState.EXPIRED.value),
}


def _three_valued_not(v: str) -> str:
    return {
        ThreeValued.TRUE.value: ThreeValued.FALSE.value,
        ThreeValued.FALSE.value: ThreeValued.TRUE.value,
        ThreeValued.UNKNOWN.value: ThreeValued.UNKNOWN.value,
    }[v]


def _threshold(k: int, child_results: list) -> str:
    true_count = sum(1 for r in child_results if r == ThreeValued.TRUE.value)
    false_count = sum(1 for r in child_results if r == ThreeValued.FALSE.value)
    n = len(child_results)
    if true_count >= k:
        return ThreeValued.TRUE.value
    if (n - false_count) < k:
        return ThreeValued.FALSE.value
    return ThreeValued.UNKNOWN.value


def _has_cycle(node_map) -> bool:
    WHITE, GRAY, BLACK = 0, 1, 2
    color = {nk: WHITE for nk in node_map.keys()}
    for start in node_map.keys():
        if color[start] != WHITE:
            continue
        stack = [(start, iter(_decode_children(node_map[start].children)))]
        color[start] = GRAY
        while stack:
            node_key, child_iter = stack[-1]
            advanced = False
            for child in child_iter:
                child_key = child.hex()
                if color[child_key] == GRAY:
                    return True
                if color[child_key] == WHITE:
                    color[child_key] = GRAY
                    stack.append((child_key, iter(_decode_children(node_map[child_key].children))))
                    advanced = True
                    break
            if not advanced:
                color[node_key] = BLACK
                stack.pop()
    return False


def _longest_path_from(node_map, root_key: str) -> int:
    memo = {}

    def visit(node_key: str) -> int:
        if node_key in memo:
            return memo[node_key]
        node = node_map[node_key]
        node_children = _decode_children(node.children)
        if len(node_children) == 0:
            memo[node_key] = 1
            return 1
        best = 1 + max(visit(c.hex()) for c in node_children)
        memo[node_key] = best
        return best

    return visit(root_key)


def _as_off_chain_process(stored: StoredProcess) -> Process:
    return Process(
        process_id=stored.process_id,
        creator=stored.creator,
        policy_commitment=stored.policy_commitment,
        graph_commitment=stored.graph_commitment,
        root_node_id=stored.root_node_id,
        graph_version=1,
        created_at=int(stored.created_at),
        committed_at=(int(stored.committed_at) if int(stored.committed_at) > 0 else None),
    )


def _decode_children(s: str) -> list[bytes]:
    return [bytes.fromhex(x) for x in s.split(",") if x]


# =====================================================================
# Consensus-backed transaction time (replaces every caller-supplied `now`).
# =====================================================================
# gl.message_raw["datetime"] is the transaction's datetime, fixed by the
# consensus round and identical for leader and validators -- no caller can
# choose it. Format: fixed-width ISO-8601 UTC, e.g. "2026-09-27T09:14:14.081651Z".
# Parsed with integer math because the `datetime` module is not usable
# inside contracts. Accessed lazily (inside a function, never at import
# time) so that a runtime lacking it fails this call, not schema loading.

def _days_from_civil(y: int, m: int, d: int) -> int:
    y -= 1 if m <= 2 else 0
    era = (y if y >= 0 else y - 399) // 400
    yoe = y - era * 400
    doy = (153 * (m + (-3 if m > 2 else 9)) + 2) // 5 + d - 1
    doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    return era * 146097 + doe - 719468


def _tx_now_or_none():
    try:
        s = str(gl.message_raw["datetime"])
        if len(s) < 19 or s[4] != "-" or s[7] != "-" or s[10] not in ("T", " ") or s[13] != ":" or s[16] != ":":
            return None
        y, mo, d = int(s[0:4]), int(s[5:7]), int(s[8:10])
        hh, mi, ss = int(s[11:13]), int(s[14:16]), int(s[17:19])
        if not (1 <= mo <= 12 and 1 <= d <= 31 and hh < 24 and mi < 60 and ss < 61):
            return None
        return _days_from_civil(y, mo, d) * 86400 + hh * 3600 + mi * 60 + ss
    except Exception:
        return None


def _tx_now() -> int:
    v = _tx_now_or_none()
    if v is None:
        raise gl.vm.UserError("consensus transaction time (gl.message_raw['datetime']) is unavailable in this runtime")
    return v


def _coerce_address(val) -> Address:
    """Defensive coercion for any Address-typed argument coming in from a
    public write/constructor call.

    VERIFIED NEEDED (Studio): the deploy-form's constructor-arg widget for
    Address-typed fields serializes a pasted hex address as a plain int
    (not as bytes/hex), regardless of the declared parameter type, so the
    contract receives a raw int at __init__ time and must convert it
    itself -- the type hint is not enforced/coerced by GenVM at the call
    boundary. Same fix as applied in CertificationGate/ProcessGraphRouter.
    """
    if hasattr(val, "as_bytes"):
        return val
    if isinstance(val, bool):
        raise gl.vm.UserError(f"invalid address value: {val!r}")
    if isinstance(val, int):
        try:
            return Address(val.to_bytes(Address.SIZE, "big"))
        except (OverflowError, ValueError):
            raise gl.vm.UserError(f"invalid address value: {val!r}")
    if isinstance(val, (bytes, bytearray, memoryview)):
        return Address(bytes(val))
    if isinstance(val, str):
        return Address(val)
    raise gl.vm.UserError(f"unsupported address value type: {type(val)}")


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


class ProcessGraph(gl.Contract):
    policy_registry_address: Address
    claim_engine_address: Address

    processes: TreeMap[str, StoredProcess]
    nodes: TreeMap[str, StoredGraphNode]  # keyed by "process_key:node_key" -- flat, no nested TreeMap construction needed
    slots: TreeMap[str, StoredClaimSlot]
    claim_slots: TreeMap[str, str]  # claim_id hex -> slot_id hex it was bound to as a TRUE/FALSE candidate

    def __init__(self, policy_registry_address: Address, claim_engine_address: Address):
        self.policy_registry_address = _coerce_address(policy_registry_address)
        self.claim_engine_address = _coerce_address(claim_engine_address)

    @gl.public.write
    def create_process(
        self,
        process_id: bytes,
        policy_id: bytes,
        policy_version: u32,
        expected_policy_commitment: bytes,
        schema_version: str,
    ) -> None:
        process_id = _coerce_bytes(process_id)
        policy_id = _coerce_bytes(policy_id)
        expected_policy_commitment = _coerce_bytes(expected_policy_commitment)
        key = process_id.hex()
        if key in self.processes:
            raise gl.vm.UserError("process_id already exists")

        policy_registry = gl.get_contract_at(self.policy_registry_address)
        if not policy_registry.view().verify_commitment(policy_id, policy_version, expected_policy_commitment):
            raise gl.vm.UserError("policy_commitment does not match PolicyRegistry's committed content")
        if not policy_registry.view().is_active(policy_id, policy_version):
            raise gl.vm.UserError("policy version is not active")

        limits = policy_registry.view().get_graph_limits(policy_id, policy_version)
        allow_revocation_retry = policy_registry.view().get_allow_revocation_retry(policy_id, policy_version)

        now = _tx_now()  # consensus time -- not caller-controlled

        record = StoredProcess(
            process_id=process_id,
            creator=str(gl.message.sender_address),
            policy_id=policy_id,
            policy_version=policy_version,
            policy_commitment=expected_policy_commitment,
            graph_commitment=b"",
            root_node_id=b"",
            schema_version=schema_version,
            allow_revocation_retry=allow_revocation_retry,
            max_graph_nodes=limits[0],
            max_graph_edges=limits[1],
            max_graph_depth=limits[2],
            node_count=u32(0),
            node_ids="",
            created_at=u64(int(now)),
            committed_at=u64(0),
            finalized_at=u64(0),
            final_result="",
            state=ProcessState.DRAFT.value,
        )
        self.processes[key] = record

    @gl.public.write
    def add_node(
        self,
        process_id: bytes,
        node_id: bytes,
        node_type: str,
        children: list[bytes],
        threshold_k: u32,
    ) -> None:
        process_id = _coerce_bytes(process_id)
        node_id = _coerce_bytes(node_id)
        key = process_id.hex()
        if key not in self.processes:
            raise gl.vm.UserError("unknown process_id")
        process = self.processes[key]
        if str(gl.message.sender_address) != process.creator:
            raise gl.vm.UserError("only the creator may add nodes to this process")
        if process.state != ProcessState.DRAFT.value:
            raise gl.vm.UserError("nodes can only be added while process is DRAFT")

        NodeType(node_type)
        node_key = node_id.hex()
        flat_key = f"{key}:{node_key}"
        if flat_key in self.nodes:
            raise gl.vm.UserError("node_id already exists in this process")

        if int(process.node_count) + 1 > int(process.max_graph_nodes):
            raise gl.vm.UserError("adding this node would exceed policy max_graph_nodes")

        if node_type == NodeType.THRESHOLD.value:
            if int(threshold_k) < 1 or int(threshold_k) > len(children):
                raise gl.vm.UserError("THRESHOLD k must satisfy 1 <= k <= len(children)")
        if node_type == NodeType.CLAIM.value and len(children) != 0:
            raise gl.vm.UserError("CLAIM nodes must have no children")
        if node_type in (NodeType.AND.value, NodeType.OR.value, NodeType.NOT.value) and len(children) == 0:
            raise gl.vm.UserError(f"{node_type} nodes require at least one child")
        if node_type == NodeType.NOT.value and len(children) != 1:
            raise gl.vm.UserError("NOT nodes must have exactly one child")

        children_str = ",".join(c.hex() for c in children)

        stored = StoredGraphNode(
            node_id=node_id,
            node_type=node_type,
            children=children_str,
            threshold_k=threshold_k,
            claim_slot_id=b"",
        )
        self.nodes[flat_key] = stored
        process.node_count = u32(int(process.node_count) + 1)
        process.node_ids = (process.node_ids + "," + node_key) if process.node_ids else node_key

    @gl.public.write
    def add_claim_slot(
        self,
        process_id: bytes,
        node_id: bytes,
        slot_id: bytes,
        predicate_type: str,
        predicate_value: i64,
        predicate_unit: str,
        predicate_date: i64,
        predicate_attribute_key: str,
        predicate_attribute_value: str,
        predicate_substring: str,
        subject_commitment: bytes,
    ) -> None:
        process_id = _coerce_bytes(process_id)
        node_id = _coerce_bytes(node_id)
        slot_id = _coerce_bytes(slot_id)
        subject_commitment = _coerce_bytes(subject_commitment)
        key = process_id.hex()
        if key not in self.processes:
            raise gl.vm.UserError("unknown process_id")
        process = self.processes[key]
        if str(gl.message.sender_address) != process.creator:
            raise gl.vm.UserError("only the creator may add claim slots to this process")
        if process.state != ProcessState.DRAFT.value:
            raise gl.vm.UserError("claim slots can only be added while process is DRAFT")

        node_key = node_id.hex()
        flat_key = f"{key}:{node_key}"
        if flat_key not in self.nodes:
            raise gl.vm.UserError("unknown node_id")
        node = self.nodes[flat_key]
        if node.node_type != NodeType.CLAIM.value:
            raise gl.vm.UserError("claim slots may only attach to CLAIM nodes")
        if len(node.claim_slot_id) != 0:
            raise gl.vm.UserError("this CLAIM node already has a slot bound")

        PredicateType(predicate_type)

        slot_key = slot_id.hex()
        if slot_key in self.slots:
            raise gl.vm.UserError("slot_id already exists")

        slot = StoredClaimSlot(
            slot_id=slot_id,
            process_id=process_id,
            predicate_type=predicate_type,
            predicate_value=predicate_value,
            predicate_unit=predicate_unit,
            predicate_date=predicate_date,
            predicate_attribute_key=predicate_attribute_key,
            predicate_attribute_value=predicate_attribute_value,
            predicate_substring=predicate_substring,
            subject_commitment=subject_commitment,
            current_claim_id=b"",
            state=SlotState.OPEN.value,
            bound_at=u64(0),
            bound_deposit=u256(0),
        )
        self.slots[slot_key] = slot
        node.claim_slot_id = slot_id

    @gl.public.write
    def commit_process(self, process_id: bytes, root_node_id: bytes) -> str:
        process_id = _coerce_bytes(process_id)
        root_node_id = _coerce_bytes(root_node_id)
        key = process_id.hex()
        if key not in self.processes:
            raise gl.vm.UserError("unknown process_id")
        process = self.processes[key]
        if str(gl.message.sender_address) != process.creator:
            raise gl.vm.UserError("only the creator may commit this process")
        if process.state != ProcessState.DRAFT.value:
            raise gl.vm.UserError("only a DRAFT process can be committed")

        now = _tx_now()  # consensus time -- not caller-controlled

        stored_node_keys = [nk for nk in process.node_ids.split(",") if nk]
        node_map = {nk: self.nodes[f"{key}:{nk}"] for nk in stored_node_keys}
        node_ids = list(node_map.keys())

        policy_registry = gl.get_contract_at(self.policy_registry_address)
        if not policy_registry.view().is_active(process.policy_id, process.policy_version):
            raise gl.vm.UserError("policy version was deactivated since this process was created - cannot commit")

        if len(node_ids) == 0:
            raise gl.vm.UserError("cannot commit an empty graph")

        root_key = root_node_id.hex()
        if root_key not in node_map:
            raise gl.vm.UserError("root_node_id is not a member of this process's graph")

        edge_count = 0
        for nk in node_ids:
            node = node_map[nk]
            node_children = _decode_children(node.children)
            edge_count += len(node_children)
            for child in node_children:
                if child.hex() not in node_map:
                    raise gl.vm.UserError(f"node references a nonexistent child: {child.hex()}")
            if node.node_type == NodeType.CLAIM.value and len(node.claim_slot_id) == 0:
                raise gl.vm.UserError(f"CLAIM node {nk} has no bound claim slot")

        if edge_count > int(process.max_graph_edges):
            raise gl.vm.UserError("graph exceeds policy max_graph_edges")

        if _has_cycle(node_map):
            raise gl.vm.UserError("graph contains a cycle - must be a DAG")

        depth = _longest_path_from(node_map, root_key)
        if depth > int(process.max_graph_depth):
            raise gl.vm.UserError("graph exceeds policy max_graph_depth")

        ordered_nodes = tuple(
            GraphNode(
                node_id=node_map[nk].node_id,
                node_type=NodeType(node_map[nk].node_type),
                children=tuple(_decode_children(node_map[nk].children)),
                threshold_k=(int(node_map[nk].threshold_k) if node_map[nk].node_type == NodeType.THRESHOLD.value else None),
                claim_slot_id=(node_map[nk].claim_slot_id if len(node_map[nk].claim_slot_id) > 0 else None),
            )
            for nk in sorted(node_ids)
        )
        graph_commitment = commit_graph(ordered_nodes, root_node_id, process.schema_version)

        process.graph_commitment = graph_commitment
        process.root_node_id = root_node_id
        process.committed_at = u64(int(now))
        process.state = ProcessState.COMMITTED.value

        return graph_commitment.hex()

    @gl.public.write
    def activate_process(self, process_id: bytes) -> None:
        process_id = _coerce_bytes(process_id)
        self._transition(process_id, ProcessState.COMMITTED.value, ProcessState.ACTIVE.value)

    @gl.public.write
    def cancel_process(self, process_id: bytes) -> None:
        process_id = _coerce_bytes(process_id)
        key = process_id.hex()
        if key not in self.processes:
            raise gl.vm.UserError("unknown process_id")
        process = self.processes[key]
        if str(gl.message.sender_address) != process.creator:
            raise gl.vm.UserError("only the creator may cancel a process")
        if (process.state, ProcessState.CANCELLED.value) not in _ALLOWED_PROCESS_TRANSITIONS:
            raise gl.vm.UserError(f"cannot cancel a process in state {process.state!r}")
        process.state = ProcessState.CANCELLED.value

    def _transition(self, process_id: bytes, expected_from: str, to: str) -> None:
        key = process_id.hex()
        if key not in self.processes:
            raise gl.vm.UserError("unknown process_id")
        process = self.processes[key]
        if str(gl.message.sender_address) != process.creator:
            raise gl.vm.UserError("only the creator may transition this process")
        if process.state != expected_from:
            raise gl.vm.UserError(f"expected state {expected_from!r}, got {process.state!r}")
        if (process.state, to) not in _ALLOWED_PROCESS_TRANSITIONS:
            raise gl.vm.UserError(f"illegal transition {process.state!r} -> {to!r}")
        process.state = to

    @gl.public.write
    def bind_slot(self, slot_id: bytes, claim_id: bytes) -> str:
        """Permissionless (content is independently verified below
        regardless of caller). A TRUE/FALSE binding does not resolve the
        slot immediately -- it opens a dispute window (see finalize_slot).
        Time is the consensus transaction time, not a caller argument.
        A binding or challenge is only accepted from a claim whose deposit
        is still HELD (get_bond) and whose evidence is still eligible; while
        it is the pending candidate its deposit is locked in ClaimEngine
        (is_claim_locked / release_deposit)."""
        slot_id = _coerce_bytes(slot_id)
        claim_id = _coerce_bytes(claim_id)
        now = u64(_tx_now())
        slot_key = slot_id.hex()
        if slot_key not in self.slots:
            raise gl.vm.UserError("unknown slot_id")
        slot = self.slots[slot_key]
        if slot.state not in (SlotState.OPEN.value, SlotState.PENDING.value):
            raise gl.vm.UserError(f"slot is not OPEN or PENDING (state={slot.state!r}) - cannot reassign")

        process_key = slot.process_id.hex()
        process = self.processes[process_key]
        if process.state == ProcessState.DRAFT.value:
            raise gl.vm.UserError("cannot bind claims until the process has been committed")

        claim_engine = gl.get_contract_at(self.claim_engine_address)

        provenance = claim_engine.view().get_provenance(claim_id)
        claim_process_commitment = _coerce_bytes(provenance[0])
        claim_policy_commitment = _coerce_bytes(provenance[1])
        if claim_process_commitment != commit_process(_as_off_chain_process(process), process.schema_version):
            raise gl.vm.UserError("claim.process_commitment does not match this process")
        if claim_policy_commitment != process.policy_commitment:
            raise gl.vm.UserError("claim.policy_commitment does not match this process's policy")

        pred = claim_engine.view().get_predicate_fields(claim_id)
        if (
            pred[0] != slot.predicate_type
            or pred[1] != slot.predicate_value
            or pred[2] != slot.predicate_unit
            or pred[3] != slot.predicate_date
            or pred[4] != slot.predicate_attribute_key
            or pred[5] != slot.predicate_attribute_value
            or pred[6] != slot.predicate_substring
            or _coerce_bytes(pred[7]) != slot.subject_commitment
        ):
            raise gl.vm.UserError("claim's predicate/subject does not match this slot's definition - predicate substitution rejected")

        claim_state = claim_engine.view().get_state(claim_id)

        if claim_state in (ClaimState.TRUE.value, ClaimState.FALSE.value):
            claim_key = claim_id.hex()
            if not claim_engine.view().is_evidence_eligible(claim_id):
                raise gl.vm.UserError("claim's evidence is no longer in an eligible state (REVOKED or INVALID)")

            # A claim's bond may back only one slot at a time.
            if claim_key in self.claim_slots and self.claim_slots[claim_key] != slot_key:
                other = self.slots[self.claim_slots[claim_key]]
                if other.current_claim_id == claim_id and other.state in (SlotState.PENDING.value, SlotState.RESOLVED.value):
                    raise gl.vm.UserError("this claim is already bound to another slot")

            # The bond is the deposit ClaimEngine is STILL HOLDING for this
            # claim. Once released (refunded) it is zero, so a refunded
            # deposit can never be counted as a bond.
            bond = claim_engine.view().get_bond(claim_id)
            policy_registry = gl.get_contract_at(self.policy_registry_address)
            min_deposit = policy_registry.view().get_min_deposit(process.policy_id, process.policy_version)
            if int(bond) < int(min_deposit):
                raise gl.vm.UserError(
                    f"claim's held bond ({bond}) is below the policy's min_deposit ({min_deposit}) - "
                    "its deposit was released or never held"
                )

            if slot.state == SlotState.OPEN.value:
                # First TRUE/FALSE binding on this slot: opens the
                # dispute window, does not resolve yet.
                slot.current_claim_id = claim_id
                slot.state = SlotState.PENDING.value
                slot.bound_at = now
                slot.bound_deposit = bond
                self.claim_slots[claim_key] = slot_key
            elif claim_id == slot.current_claim_id:
                # Re-affirming the already-pending claim (e.g. to refresh
                # after a no-op call) -- not a challenge, window unchanged.
                pass
            elif int(now) - int(slot.bound_at) >= DISPUTE_WINDOW_SECONDS:
                raise gl.vm.UserError(
                    "dispute window has already elapsed for the pending claim - "
                    "call finalize_slot instead of attempting a late challenge"
                )
            else:
                challenger_deposit = bond
                if int(challenger_deposit) <= int(slot.bound_deposit):
                    raise gl.vm.UserError(
                        f"challenger deposit ({challenger_deposit}) does not exceed the "
                        f"currently pending claim's deposit ({slot.bound_deposit}) - cannot challenge"
                    )
                # Bond escalation: challenger displaces the pending claim
                # and the window resets, same as a fresh binding.
                # The displaced claim stops being locked (it is no longer
                # the pending candidate) and may release its deposit.
                slot.current_claim_id = claim_id
                slot.bound_at = now
                slot.bound_deposit = challenger_deposit
                self.claim_slots[claim_key] = slot_key
        elif claim_state in (ClaimState.INVALIDATED.value, ClaimState.EXPIRED.value):
            # Found in review (session 2026-09-14): before ClaimEngine's
            # fix, EXPIRED-via-freshness and human-initiated INVALIDATED
            # were the same literal string here and could not be told
            # apart. Both still follow the same allow_revocation_retry
            # gate for now -- deliberately unchanged behavior, this fix
            # is about making the two cases distinguishable in claim
            # state history, not about changing what a policy author's
            # allow_revocation_retry setting does.
            slot.current_claim_id = claim_id
            slot.state = SlotState.OPEN.value if process.allow_revocation_retry else SlotState.LOCKED.value
            slot.bound_at = u64(0)
            slot.bound_deposit = u256(0)
        else:
            slot.current_claim_id = claim_id
            slot.state = SlotState.OPEN.value
            slot.bound_at = u64(0)
            slot.bound_deposit = u256(0)

        return slot.state

    @gl.public.write
    def finalize_slot(self, slot_id: bytes) -> str:
        """Permissionless, same rationale as bind_slot: locks in a
        PENDING slot as RESOLVED once its dispute window has elapsed
        without being outbid. Window length is measured against consensus
        transaction time. If the pending claim's evidence has been
        REVOKED/INVALIDATED in the meantime the slot is NOT resolved on it:
        it reopens (or locks, per the policy's allow_revocation_retry) and
        that claim's deposit becomes releasable. See DISPUTE_WINDOW_SECONDS."""
        slot_id = _coerce_bytes(slot_id)
        slot_key = slot_id.hex()
        if slot_key not in self.slots:
            raise gl.vm.UserError("unknown slot_id")
        slot = self.slots[slot_key]
        if slot.state != SlotState.PENDING.value:
            raise gl.vm.UserError(f"slot is not PENDING (state={slot.state!r}) - nothing to finalize")
        if _tx_now() - int(slot.bound_at) < DISPUTE_WINDOW_SECONDS:
            raise gl.vm.UserError("dispute window has not elapsed yet")

        claim_engine = gl.get_contract_at(self.claim_engine_address)
        if not claim_engine.view().is_evidence_eligible(slot.current_claim_id):
            process = self.processes[slot.process_id.hex()]
            slot.state = SlotState.OPEN.value if process.allow_revocation_retry else SlotState.LOCKED.value
            slot.bound_at = u64(0)
            slot.bound_deposit = u256(0)
            return slot.state

        slot.state = SlotState.RESOLVED.value
        return slot.state

    @gl.public.view
    def is_claim_locked(self, claim_id: bytes) -> bool:
        """True while this claim is the pending candidate of a slot whose
        dispute window is unresolved -- i.e. while its deposit is counted
        as a bond. ClaimEngine.release_deposit refuses while this is True."""
        claim_id = _coerce_bytes(claim_id)
        claim_key = claim_id.hex()
        if claim_key not in self.claim_slots:
            return False
        slot = self.slots[self.claim_slots[claim_key]]
        return slot.state == SlotState.PENDING.value and slot.current_claim_id == claim_id

    def _evaluate_node(self, process_key: str, node_key: str) -> str:
        node = self.nodes[f"{process_key}:{node_key}"]

        if node.node_type == NodeType.CLAIM.value:
            slot_key = node.claim_slot_id.hex()
            slot = self.slots[slot_key]
            if slot.state == SlotState.LOCKED.value:
                return ThreeValued.UNKNOWN.value
            if slot.state == SlotState.PENDING.value:
                # Not yet counted: the dispute window (see bind_slot /
                # finalize_slot) hasn't closed, so this binding could
                # still be displaced by a larger-deposit challenger.
                # finalize_process cannot even reach this (see
                # _collect_open_slots_reachable below), but the
                # standalone `evaluate` view can be called at any time,
                # including mid-window -- it must not report a not-yet-
                # final outcome as if it were settled.
                return ThreeValued.UNKNOWN.value
            if len(slot.current_claim_id) == 0:
                return ThreeValued.UNKNOWN.value
            claim_engine = gl.get_contract_at(self.claim_engine_address)
            claim_state = claim_engine.view().get_state(slot.current_claim_id)
            if claim_state == ClaimState.TRUE.value:
                return ThreeValued.TRUE.value
            if claim_state == ClaimState.FALSE.value:
                return ThreeValued.FALSE.value
            return ThreeValued.UNKNOWN.value

        child_results = [self._evaluate_node(process_key, c.hex()) for c in _decode_children(node.children)]

        if node.node_type == NodeType.NOT.value:
            return _three_valued_not(child_results[0])
        if node.node_type == NodeType.AND.value:
            return _threshold(len(child_results), child_results)
        if node.node_type == NodeType.OR.value:
            return _threshold(1, child_results)
        if node.node_type == NodeType.THRESHOLD.value:
            return _threshold(int(node.threshold_k), child_results)

        raise gl.vm.UserError(f"unhandled node_type at evaluation: {node.node_type!r}")

    @gl.public.view
    def evaluate(self, process_id: bytes) -> str:
        process_id = _coerce_bytes(process_id)
        key = process_id.hex()
        if key not in self.processes:
            raise gl.vm.UserError("unknown process_id")
        process = self.processes[key]
        if len(process.root_node_id) == 0:
            raise gl.vm.UserError("process has not been committed yet")
        return self._evaluate_node(key, process.root_node_id.hex())

    def _collect_open_slots_reachable(self, process_key: str, node_key: str, seen: set) -> list:
        if node_key in seen:
            return []
        seen.add(node_key)
        node = self.nodes[f"{process_key}:{node_key}"]
        open_slots = []
        if node.node_type == NodeType.CLAIM.value:
            slot = self.slots[node.claim_slot_id.hex()]
            if slot.state in (SlotState.OPEN.value, SlotState.PENDING.value):
                # PENDING blocks finalization too, not just OPEN (added
                # alongside PENDING itself, session 2026-09-14) -- a
                # process must not finalize while a slot's dispute window
                # is still open, or the window would be meaningless.
                open_slots.append(slot.slot_id)
        for c in _decode_children(node.children):
            open_slots += self._collect_open_slots_reachable(process_key, c.hex(), seen)
        return open_slots

    @gl.public.write
    def finalize_process(self, process_id: bytes) -> str:
        process_id = _coerce_bytes(process_id)
        key = process_id.hex()
        if key not in self.processes:
            raise gl.vm.UserError("unknown process_id")
        process = self.processes[key]

        if process.state == ProcessState.FINALIZED.value:
            raise gl.vm.UserError("process is already FINALIZED - cannot finalize twice")
        if process.state == ProcessState.CANCELLED.value:
            raise gl.vm.UserError("process is CANCELLED - cannot finalize")
        if process.state not in (ProcessState.COMMITTED.value, ProcessState.ACTIVE.value, ProcessState.RESOLVING.value):
            raise gl.vm.UserError(f"process is in state {process.state!r} - cannot finalize")
        if len(process.root_node_id) == 0:
            raise gl.vm.UserError("process has no root_node_id - cannot finalize")

        now = _tx_now()  # consensus time -- not caller-controlled

        open_slots = self._collect_open_slots_reachable(key, process.root_node_id.hex(), set())
        if len(open_slots) > 0:
            raise gl.vm.UserError(
                f"cannot finalize: {len(open_slots)} claim slot(s) reachable from root are still OPEN"
            )

        process.state = ProcessState.RESOLVING.value
        result = self._evaluate_node(key, process.root_node_id.hex())

        process.final_result = result
        process.finalized_at = u64(int(now))
        process.state = ProcessState.FINALIZED.value

        return result

    @gl.public.view
    def get_process_commitment(self, process_id: bytes) -> str:
        process_id = _coerce_bytes(process_id)
        key = process_id.hex()
        if key not in self.processes:
            raise gl.vm.UserError("unknown process_id")
        process = self.processes[key]
        if process.state == ProcessState.DRAFT.value:
            raise gl.vm.UserError("process has not been committed yet - no stable commitment exists")
        return commit_process(_as_off_chain_process(process), process.schema_version).hex()

    @gl.public.view
    def get_state(self, process_id: bytes) -> str:
        process_id = _coerce_bytes(process_id)
        key = process_id.hex()
        if key not in self.processes:
            raise gl.vm.UserError("unknown process_id")
        return self.processes[key].state

    @gl.public.view
    def get_final_result(self, process_id: bytes) -> str:
        process_id = _coerce_bytes(process_id)
        key = process_id.hex()
        if key not in self.processes:
            raise gl.vm.UserError("unknown process_id")
        process = self.processes[key]
        if process.state != ProcessState.FINALIZED.value:
            raise gl.vm.UserError("process is not FINALIZED yet")
        return process.final_result

    @gl.public.view
    def get_slot_state(self, slot_id: bytes) -> str:
        slot_id = _coerce_bytes(slot_id)
        slot_key = slot_id.hex()
        if slot_key not in self.slots:
            raise gl.vm.UserError("unknown slot_id")
        return self.slots[slot_key].state
