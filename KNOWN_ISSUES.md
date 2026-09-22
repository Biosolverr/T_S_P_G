# Known issues in the pinned GenVM build

Pin: `py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6`.

Everything below was found by deploying and calling all four contracts against a live GenLayer
Studio instance, not by reading documentation alone. Each item includes the fix already applied in
the contract source. If this system is ever ported to a different pinned build, re-test each of
these before assuming the workaround is still needed, and before assuming a workaround listed here
as unnecessary on a different build is actually unnecessary there.

## 1. `DynArray` cannot be constructed manually

`DynArray[T]()` and `DynArray[T](some_iterable)` both fail at runtime
(`TypeError: this class can't be instantiated by user`, raised inside the SDK's own `vec.py`).
The general GenLayer storage documentation describes `gl.storage.inmem_allocate(DynArray[T])` as
the correct way to build a fresh generic storage container; in this exact build that call also
fails, with a different, internal error
(`_GenericAlias.__init__() missing 1 required positional argument: 'args'`).

**Fix applied:** every field that would otherwise have been a freshly constructed `DynArray`
(`predicate_rules` on a stored policy, `children` on a stored graph node) is stored instead as a
plain comma-joined string (hex-encoded for byte values) and decoded on read. See `_decode_children`
in `process_graph.py` and the equivalent inline join and split in `policy_registry.py`.

## 2. A nested `TreeMap` cannot be assigned into another `TreeMap`'s value slot

`self.outer[key] = TreeMap[K, V]()` fails with
`AssertionError: Is right the same storage type? TreeMap <- TreeMap` when the outer field's
declared type is itself a `TreeMap` of `TreeMap`, even though the same construction, used directly
as a top-level contract field (not nested), works without issue. The failure is specific to
assigning a freshly built generic container into a slot of another generic container.

**Fix applied:** `ProcessGraph.nodes` was flattened from `TreeMap[str, TreeMap[str, StoredGraphNode]]`
to a single-level `TreeMap[str, StoredGraphNode]`, keyed by the composite string
`f"{process_key}:{node_key}"`. Enumerating "all nodes for one process" is done by keeping a
comma-joined `node_ids` string on the `StoredProcess` record and looking each node up individually,
rather than holding a live reference to a nested map.

Note: `PolicyRegistry.policies` remains a genuinely nested `TreeMap[str, TreeMap[u32,
StoredPolicyRecord]]`, and its own `self.policies[key] = TreeMap[u32, StoredPolicyRecord]()`
construction has not reproduced this failure in live testing across many `register_policy` calls.
The two cases were not confirmed to differ in any way that would predict this in advance; treat the
absence of a failure here as empirically observed, not as a general exception to item 2, and retest
if this line is ever touched.

## 3. `bytes` and `Address` arguments arrive as `int`

Studio's calldata builder converts a pasted `0x...` value into a decimal integer before sending it
over the wire, regardless of whether the declared parameter type is `bytes` or `Address`. The type
hint is not enforced or coerced by GenVM at the call boundary; it only drives Studio's form
generation.

**Fix applied:** every public method that takes a `bytes` or `Address` argument runs it through
`_coerce_bytes` or `_coerce_address` first. Both accept `int`, `bytes`, `bytearray`, `memoryview`,
`str` (hex, with or without a `0x` prefix), or an already-correct `Address`/`bytes` value, and
normalize to a fixed-width value: `Address.SIZE` bytes for addresses, 32 bytes for the generic
`bytes` helper, since every hash in this system is a sha256 digest.

## 4. `bytes` return values are displayed lossily by GenLayer Studio

Studio's Output panel for a `bytes` return value also converts it through `int` before display, and
re-renders using the minimal number of hex digits needed for that integer. Any leading zero byte in
the true value is silently dropped, with no indication in the UI that this happened. A value copied
from Output and pasted into a later `bytes` field will not match what was actually stored, unless
the true value happens to have no leading zero byte, which cannot be predicted in advance for a
hash.

**Fix applied:** every public method's return type was changed from `bytes` (or a tuple containing
`bytes`) to `str`, returning `.hex()` explicitly. Plain strings are displayed by Studio without this
transformation.

**A consequence this caused, also fixed:** three internal comparisons were reading one of these
now-`str` return values, through a cross-contract `.view()` call, and comparing it directly against
a local `bytes` value: `ProcessGraph.bind_slot`'s `process_commitment` and `subject_commitment`
checks, and `ClaimEngine.adjudicate_claim`'s comparison of the fetched content's hash against the
committed `artifact_hash`. A `str` and a `bytes` value are never equal in Python regardless of
content, so all three checks always failed once item 4's fix was applied on its own, independent of
whether the underlying data actually matched. Each such value is now passed back through
`_coerce_bytes` before comparison.

## 5. There is no on-chain clock

`gl.block.timestamp` does not exist (`AttributeError: module 'genlayer.gl' has no attribute
'block'`). The public `gl.message` object (of type `MessageType`) exposes only
`contract_address`, `sender_address`, `origin_address`, `value`, and `chain_id`; there is no
timestamp field anywhere on it, and no other public accessor for the current time was found.

**Fix applied:** every method that needed the current time takes an explicit `now: u64` argument
supplied by the caller, with monotonicity checks added where practical. See `SECURITY.md`,
"Caller-supplied time", for the trust implication this carries.

## 6. `gl.nondet.web.render` only supports `http` and `https`

Any other URI scheme, including `ipfs://`, fails with
`NondetException: {'causes': ['SCHEMA_FORBIDDEN'], ...}`.

**Fix applied:** none needed in the contract code; this is a data requirement, not a code path.
`retrieval_hint_uri` on evidence records must be an `http(s)` URL that GenVM's sandbox can actually
reach.

## 7. Studio's form has no way to express an enum or a structured dict

There is no per-argument type selector in Studio's deploy or call form that would let it validate a
`str` field against an enum, or a `dict[str, int]` field's expected keys, before submission. An
unrecognized value, a free-text unit like `"units"` instead of `GRAMS`/`KG`/`ITEMS`, or a `scope`
other than `"PROCESS"`, is accepted by the form and only rejected inside the contract at call time,
with a plain exception. This is expected behavior given the tooling, not a defect to fix; it means
the field reference in `TESTING.md` should be treated as authoritative over anything Studio's form
implies is acceptable.

## 8. `_ContractAt.emit_transfer` does not take a positional value argument

`gl.get_contract_at(addr).emit_transfer(amount)` fails with
`TypeError: emit_transfer() takes 1 positional argument but 2 were given`. The method must be
called with the amount as a keyword argument.

**Fix applied:** `_send_native` calls `emit_transfer(value=amount)`. This is item 3 of the three
confirmed defects fixed in `_send_native`; see `SECURITY.md`, "Native value transfer", for the full
sequence (address-prefix handling and `Address` wrapping were the other two) and for what is still
unverified about the call even after all three fixes.

## 9. `gl.evm` does not exist in this build

A speculative fix attempt used `@gl.evm.contract_interface`, a pattern documented as the correct
mechanism for sending native value to a plain wallet address in other GenLayer material. Referencing
`gl.evm` raises `AttributeError` at class-definition time, because the decorator is evaluated when
the module is loaded, not when the decorated code actually runs.

**This is more severe than a runtime failure in one method.** A crash while loading the module
means GenLayer Studio cannot introspect the contract's schema at all; the symptom is "Could not
load contract schema" for the entire contract, with no constructor inputs shown and no way to
deploy it, not an error confined to whichever method used the missing attribute. This was reverted
immediately on observing the symptom.

**Lesson for future changes:** never add a new top-level `gl.*` reference, especially inside a
decorator or a class body evaluated at import time, without first confirming it exists in the
exact pinned build. A mistake here does not degrade gracefully; it takes down the whole contract's
schema loading, and the resulting error message ("Could not load contract schema") gives no hint
that the cause is a missing attribute reference three hundred lines into the file.

## Working around a hash mismatch you cannot reproduce locally

This is a debugging technique, not a defect, but it is worth recording here since it was used
repeatedly during testing. If a `bytes` field is supposed to equal the hash of some off-chain
content and the two do not match, do not guess repeatedly. `ClaimEngine.adjudicate_claim`'s
equivalence-principle output is `HASH_MISMATCH:<actual hex hash>` rather than a bare
`HASH_MISMATCH` specifically so the real value can be read directly from a failed attempt and used
to correct the evidence record, instead of being recomputed by hand against an assumption about
exactly what bytes `gl.nondet.web.render` will return for a given URL (which, for anything other
than a plain text file served as-is, is not straightforward to predict from outside GenVM). This
diagnostic addition is permanent and does not need to be reverted; it exposes only the hash of
already-public web content, nothing sensitive.
