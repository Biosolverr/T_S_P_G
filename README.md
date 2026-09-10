# TSPG (Trust Semantic Process Graph)

TSPG is a four-contract GenLayer Intelligent Contract system for registering, adjudicating, and
graph-composing claims whose truth depends on off-chain evidence and natural-language predicates.
Adjudication is performed by LLM validator consensus, not by deterministic parsing, which is why
this needs GenLayer rather than a conventional EVM contract.

## What it does

A caller registers a **policy** (rules that any claim under it must satisfy: allowed predicate
types, minimum validator count, evidence freshness window, deposit size, graph size limits). A
caller separately registers **evidence** (a content-addressed commitment to some off-chain
artifact, plus a retrieval hint URI). A caller then registers a **claim**: an assertion, tied to a
policy and to a piece of evidence, expressed as a predicate (for example "quantity delivered is at
least 500 items"). Anyone can trigger **adjudication**: the contract fetches the evidence content
through GenVM's non-deterministic web fetch, asks the validator set to judge the predicate against
that content, and records the consensus verdict (TRUE, FALSE, or UNKNOWN) on-chain.

Claims can be composed into a **process graph**: AND/OR/NOT/THRESHOLD nodes whose leaves are claim
slots. A process can only be finalized once every claim slot reachable from the root has resolved
to TRUE or FALSE (UNKNOWN or unbound slots block finalization by design).

## Contracts

| Contract | File | Responsibility |
|---|---|---|
| PolicyRegistry | `policy_registry.py` | Immutable versioned policies: predicate rules, validator count, evidence freshness rules, deposit size, graph size limits. |
| EvidenceRegistry | `evidence_registry.py` | Content-addressed evidence records: artifact hash, size, mime type, retrieval hint URI, submission time. |
| ClaimEngine | `claim_engine.py` | Claim lifecycle: registration, deposit handling, LLM adjudication against fetched evidence, withdrawal of deposits and protocol fees. |
| ProcessGraph | `process_graph.py` | Boolean composition of claims into a directed graph, slot binding, and final result evaluation. |

None of these contracts move value except `ClaimEngine` (claim deposits and the protocol sink).
Neither `PolicyRegistry` nor `EvidenceRegistry` nor `ProcessGraph` are payable.

## Trust and cross-contract wiring

`ClaimEngine` reads policy and evidence data from `PolicyRegistry` and `EvidenceRegistry` through
read-only cross-contract calls (`gl.get_contract_at(...).view()`). `ProcessGraph` reads claim data
from `ClaimEngine` the same way. None of the four contracts ever writes into another contract; all
cross-contract calls are `.view()` reads. This keeps the trust graph a strict DAG: PolicyRegistry
and EvidenceRegistry have no dependencies, ClaimEngine depends on both, ProcessGraph depends on
PolicyRegistry and ClaimEngine.

Each contract's dependency addresses are set once at construction time and are immutable for the
life of the deployment. Deploying against the wrong registry, or replacing a registry later,
requires a fresh deployment of every contract that pointed at it. See `DEPLOYMENT.md` for the
required deployment order.

## Documents in this repository

- `DEPLOYMENT.md`: constructor arguments, required deployment order, and environment-specific
  quirks you will hit when deploying to GenLayer Studio.
- `SECURITY.md`: trust boundaries, the caller-supplied timestamp model, known limitations, and the
  security checklist this system was reviewed against.
- `TESTING.md`: a full manual field-by-field walkthrough for exercising every public method across
  all four contracts, in dependency order, with realistic (non-placeholder) values.
- `TEST_RESULTS.md`: the actual end-to-end test run performed against a live GenLayer Studio
  deployment, including every value used and the final on-chain result.
- `KNOWN_ISSUES.md`: environment-specific bugs and constraints discovered in the pinned GenVM
  build (`py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6`) during development, and
  the workaround applied for each. Read this before changing any of the four contract files, so a
  fix is not accidentally reverted.

## Predicate types

`ClaimEngine` currently implements one predicate family in full: `QuantityAtLeast` and
`QuantityEquals` (quantity comparisons in a fixed unit set: `GRAMS`, `KG`, `ITEMS`).
`DateBefore`, `DateEquals`, `AttributeEquals`, and `ArtifactContains` are defined in the enum but
should be treated as not yet exercised end-to-end; verify their prompt-building and adjudication
path before relying on them in production.

## Status

All four contracts have been deployed to GenLayer Studio and exercised end to end at least once,
including a real LLM adjudication that returned `VERDICT:TRUE` against real off-chain content and
a `finalize_process` call that returned `TRUE`. See `TEST_RESULTS.md` for the full run.
# T_S_P_G
