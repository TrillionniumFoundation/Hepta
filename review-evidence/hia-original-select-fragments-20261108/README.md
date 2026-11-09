# Frozen original select: exact integrated-source evidence

## Retained result

This evidence was newly generated from clean source commit
`1be1f075dab01a56d43ceca286668946dbc9037b`, tree
`a21e280aeda15e911ccf9cc619e0d116d1cec47d`. This source includes the revised
Safe Core ELF binding checks. Older checker evidence is not reused here.

The result is **PASS_SCOPED_COPIED_FRAGMENTS**. The original Agent's strict
verification/evaluation/adoption gate remains **HOLD**.

| Item | Observed result |
| --- | --- |
| Frozen C0 + original patch reconstruct exact C1 | Exact complete-byte match |
| Native C1 compiler invocations | Five typed select fixtures completed |
| Full generated program native calls | 64 finite cases matched their expected values |
| Actual 35-byte copied intervals | Five typed source/output bindings checked |
| Read-only whole-output disassembly | Six instruction boundaries per copied interval checked |
| Independent supplied-byte projection validation | Five typed subjects, 25 SMT obligations passed |
| Native calls on proof-qualified projections | 200 finite cases matched scalar selection |
| Fresh isolated replay | 555 retained files checked; all 25 obligations recomputed |
| Focused provenance tests | Four passed on the exact integrated source |

The five compilation invocations produce four distinct complete byte images;
`u64` and `usize` generate identical bytes. The copied intervals have two
distinct byte strings. Typed bindings and projections carry distinct
specifications/preconditions; these counts are not independent statistical
samples or five different selection algorithms. The replayed obligations are
not added to the original 25 as new proofs.

## Archive and integrity

`raw-evidence-1be1f075.zip` is 850,873 bytes, SHA-256:

`f119a88c9be7ac0cca56800422af029e406352c035ebc06752d01b54efa9b01e`

It contains the complete new qualification and replay directories, raw native
requests/responses and private buffer snapshots, all five output byte images,
copied intervals, object/final projection images, all SMT queries/results,
full disassembly observations, frozen original task files, exact patch
reconstruction, the seed receipt/image, source inventories/import origins,
focused test output and selected checker/tool source snapshots. It contains no
Agent state database, adopted generation or invented provider transcript.

The selected source snapshots are an inspection aid, not an alternative
complete repository closure. Use the exact Git commit for reproduction.

The externally pinned qualification artifact manifest SHA-256 is:

`0dafac49ce2e3fc859b78131d8e36d5138fdb533eb8568a5e052b926f91da7e7`

After verifying the ZIP bytes and extracting to a fresh directory, run from the
exact source checkout with the pinned Z3 environment:

```sh
python -B tools/replay_hia_original_select_fragments.py \
  --input EXTRACTED/qualification \
  --expected-manifest-sha256 0dafac49ce2e3fc859b78131d8e36d5138fdb533eb8568a5e052b926f91da7e7 \
  --output NEW_REPLAY_DIRECTORY
```

Replay is read-only with respect to the retained evidence. It recomputes the
proof obligations without executing any compiler or native image and creates
no acceptance receipt.

## Explicit remaining boundary

The theorem concerns the copied load/select/store fragment under initialized,
normalized SSA-slot preconditions established by new projection scaffolding.
It does not prove that the original compiler establishes those invariants in
every context. The full generated programs have finite observations only.
The complete old/new source-domain relation, rejection/capacity/resource
behavior and general compiler Core-to-machine refinement remain unproved.

This is new local evidence for one fixed integrated source. It is not a later
commit's qualification, a new unfamiliar-Agent study, a remote MCP deployment,
or a reconstruction of missing historical provider interactions and costs.

See [the implementation scope](../../docs/HIA_ORIGINAL_SELECT_COPIED_FRAGMENTS_20261108.md)
and `REPORT.json` for the machine-readable binding and remaining obligations.
