# Known issues in the pinned GenVM build

Pin: `py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6`.

Everything below was found by deploying and calling all four contracts against a live GenLayer
Studio instance. Each item includes the fix already applied in the contract source. If this system
is ever ported to a different pinned build, re-test each of these before assuming the workaround is
still needed.

## 1. `DynArray` cannot be constructed manually

`DynArray[T]()` and `DynArray[T](some_iterable)` both fail at runtime
(`TypeError: this class can't be instantiated by user`, raised inside the SDK's own `vec.py`).
`gl.storage.inmem_allocate(DynArray[T])`, which the general GenLayer storage documentation
describes as the correct way to build a fresh generic storage container, also fails in this build
with a different, internal error (`_GenericAlias.__init__() missing 1 required positional
argument: 'args'`).

**Fix applied:** every field that would have been a freshly-constructed `DynArray` (`predicate_rules`
on a stored policy, `children` on a stored graph node) is stored instead as a plain comma-joined
string (hex-encoded for byte values) and decoded on read. See `_decode_children` in
`process_graph.py` and the equivalent inline join/split in `policy_registry.py`.

## 2. Nested `TreeMap` cannot be assigned into another `TreeMap`'s value slot

`self.outer[key] = TreeMap[K, V]()` fails with
`AssertionError: Is right the same storage type? TreeMap <- TreeMap`, even though the same class,
constructed as a **contract-level field**, works fine. The failure is specific to assigning a
freshly built generic container into a slot of another generic container.

**Fix applied:** `ProcessGraph.nodes` was flattened from `TreeMap[str, TreeMap[str, StoredGraphNode]]`
to a single-level `TreeMap[str, StoredGraphNode]`, keyed by the composite string
`f"{process_key}:{node_key}"`. Enumerating "all nodes for one process" is done by keeping a
comma-joined `node_ids` string on the `StoredProcess` record and looking each one up individually,
rather than by holding a live reference to a nested map.

## 3. `bytes` and `Address` constructor and method arguments arrive as `int`

Studio's calldata builder converts a pasted `0x...` value into a decimal integer before sending it,
regardless of whether the declared parameter type is `bytes` or `Address`. The type hint is not
enforced or coerced by GenVM at the call boundary; it only drives Studio's form generation.

**Fix applied:** every public method that takes a `bytes` or `Address` argument runs it through
`_coerce_bytes` or `_coerce_address` first, which accept `int`, `bytes`, `bytearray`, `memoryview`,
`str` (hex, with or without an `0x` prefix), or an already-correct `Address`/`bytes` value, and
normalize to a fixed-width value (`Address.SIZE` bytes for addresses, 32 bytes for the generic
`bytes` helper, since every hash in this system is a sha256 digest).

## 4. `bytes` return values are displayed lossily by Studio

Studio's Output panel for a `bytes` return value also converts through `int`, and then re-renders
using the minimal number of hex digits needed for that integer. Any leading zero byte in the true
value is silently dropped in the display, with no way to tell from the UI that this happened. A
value copied from Output and pasted into a later `bytes` field will therefore not match what was
actually stored, unless the true value happens to have no leading zero byte.

**Fix applied:** every public method's return type was changed from `bytes` (or a tuple containing
`bytes`) to `str`, returning `.hex()` explicitly. Plain strings are displayed by Studio without
this transformation.

**Consequence this caused, also fixed:** two places compared such a return value, read through a
cross-contract `.view()` call, against a local `bytes` value: `ProcessGraph.bind_slot`'s
`process_commitment` and `subject_commitment` checks, and `ClaimEngine.adjudicate_claim`'s
comparison of the fetched content's hash against the committed `artifact_hash`. A `str` and a
`bytes` value are never equal in Python regardless of content, so all three checks always failed
after item 4's fix was applied on its own. Each read-back value is now passed through
`_coerce_bytes` before comparison.

## 5. There is no on-chain clock

`gl.block.timestamp` does not exist (`AttributeError: module 'genlayer.gl' has no attribute
'block'`). The public `gl.message` object (`MessageType`) only exposes `contract_address`,
`sender_address`, `origin_address`, `value`, and `chain_id`; no timestamp field.

**Fix applied:** every method that needed the current time now takes an explicit `now: u64`
argument supplied by the caller. See `SECURITY.md` for the trust implication.

## 6. `gl.nondet.web.render` only supports `http` and `https`

Any other URI scheme, including `ipfs://`, fails with
`NondetException: {'causes': ['SCHEMA_FORBIDDEN'], ...}`.

**Fix applied:** none needed in the contract code; this is a data requirement. `retrieval_hint_uri`
on evidence records must be an `http(s)` URL that GenVM's sandbox can actually reach.

## 7. Studio's per-argument type dropdown does not exist for enums or dicts

There is no way to tell Studio's deploy or call form that a `str` field is actually constrained to
an enum, or that a `dict[str, int]` field has fixed keys. Passing an unrecognized value (a free-text
unit like `"units"` instead of `GRAMS`/`KG`/`ITEMS`, or a `scope` other than `"PROCESS"`) is
accepted by the form and only rejected inside the contract at call time, with a plain Python
exception. This is expected behavior, not a bug, but it means the field reference in `TESTING.md`
should be treated as authoritative over what Studio's form implies is acceptable.

## 8. Debugging a hash mismatch you cannot reproduce locally

If a `bytes` field is supposed to equal the hash of some off-chain content and the two do not
match, do not guess repeatedly. `ClaimEngine.adjudicate_claim` was extended so that, on a hash
mismatch, the equivalence principle output is `HASH_MISMATCH:<actual hex hash>` instead of a bare
`HASH_MISMATCH`. Use that value directly. This is a permanent, harmless diagnostic addition (it
exposes only the hash of already-public web content, nothing sensitive) and does not need to be
reverted.
