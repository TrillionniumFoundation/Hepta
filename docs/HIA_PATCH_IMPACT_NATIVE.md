# Native patch impact

`examples/hia_bootstrap/patch_impact.hepta` owns the finite impact computation
used by `analyze_patch_impact`: exact function and interface comparisons,
canonical function ordering, both old and new call graphs, duplicate-edge
elimination, and direct/transitive caller reachability across their union.
The original 1–1,024 function domain is retained. Recursive edges and cycles
terminate with at most one queue entry per function. Removed declarations and
unlisted callees retain the original refusals.

Select the image with `HEPTA_HIA_PATCH_IMPACT_MANIFEST`, or register that selector
in the administrator-pinned worker helper bundle. A present empty selector or
an invalid/missing selected image refuses without entering the reference
computation. The ordinary route remains available when the key is absent.

## Public boundary and ordering

The existing caller freshly verifies the original, applies the existing patch,
reverifies the candidate, and authenticates the complete patch receipt. Native
phase zero compares detached canonical function/signature bytes. The caller
then checks the original interface-change and migration-policy receipt fields.
Native phase one constructs both graphs and computes the complete impact. Its
change/interface result must equal phase zero. This preserves the original
receipt-before-graph refusal ordering.

Python transports every original function and operation in declaration order;
it does not classify call opcodes, sort names, compare function bodies or
interfaces, construct edges, or perform graph reachability on the selected
route. It materializes the HIA-selected indices and adjacency bits into the
unchanged public report. Core verification, patch semantics, signature
projection, canonical serialization, receipt authentication and final report
hashing retain their existing owners. Impact remains advisory and grants no
equivalence or external-caller authority.

## ABI and bounds

The source uses the existing six-argument borrowed-byte ABI. Its request has
an explicit magic, phase and both function counts, followed by length-delimited
names, canonical function/signature bytes and original operation facts. HIA
validates all lengths and counts before indexing. The original verifier's
input budgets remain in force; no smaller source-data limit is introduced.

State and output sizes are derived from the original counts and two compact
adjacency bitsets. At 1,024 functions in each program, output is 278,544 bytes
and workspace is 376,896 bytes. The workspace includes original metadata,
sorted index arrays and a bounded queue. No output bytes are written until
the entire requested phase accepts. Failed requests cannot publish partial
graphs. The generated program has 14 functions, 156 blocks and 614 operations,
within the unchanged native compiler limits.

## Build and verification

```sh
python -B tools/build_hia_patch_impact.py \
  --compiler /absolute/current/compiler.bin \
  --cold-report /absolute/current/cold.json \
  --output /absolute/new/patch-impact
python -B tools/qualify_hia_patch_impact_callers.py \
  --cold-report /absolute/current/cold.json \
  --evidence /absolute/new/patch-impact-callers
```

The builder requires a completed matching-source cold result for qualification.
Its separate explicit development mode records that narrower scope. Compiler,
source, cold report and full packed output are read back before the manifest
is published.

`tests/test_hia_patch_impact_native.py` compares complete native buffers with
an independent Core VM, checks randomized and 1,024-function graphs, malformed
lengths/counts, output/workspace canaries and original refusal order. The
unchanged public patch module runs with the Python comparison and graph bodies
forbidden. The full caller gate retains all five original modules, including
v5/v6 patches, returned-loan interfaces and CLI editing. Its original proof
dependency must be installed; an unavailable Z3 result is not a pass.

The installed-wheel control in `tests/test_hia_full_cost_native.py` builds one
real wheel and independently executes both selected owners from an isolated
working directory, forbids both reference paths, and checks that modifying
either installed `.hepta` source refuses before fallback. These component
checks do not replace whole-product native installation or worker migration.
