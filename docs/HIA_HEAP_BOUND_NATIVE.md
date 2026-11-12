# Native public heap analysis owner

## Status and scope

This is an explicitly selected development owner. It does not activate a new
default, delete the retained Python implementations, qualify a deployed worker,
or establish whole-language or whole-product equivalence. All whole-delivery,
default-change, production-activation, and old-owner-removal claims remain false.

The selected HIA controller owns admission order, policy/type/range decisions,
analysis selection, exception categories and details, and every public report
field for these seven existing APIs:

| Public entry | HIA controller mode | Native analysis |
| --- | ---: | --- |
| analyze_constant_live_heap | 0 | All-function legacy local peak |
| qualify_live_heap_budget | 1 | Legacy local peak and explicit limit |
| qualify_entry_live_heap_budget | 2 | Borrowed-local v8 entry peak |
| qualify_finite_entry_live_heap_budget | 3 | Exact scalar v7 invocation |
| qualify_finite_entry_live_heap_budget_v8 | 4 | v8 owners and returned parameter loans |
| qualify_finite_entry_live_heap_budget_v8_with_borrowed_extents | 5 | v8 caller-derived borrowed extents |
| analyze_entry_payload_bound | 6 | Cumulative requested v1 entry payload |

The HIA live kernel owns the CFG/call traversal, live-owner and loan maps,
abstract scalar intervals, branch joins, finite invocation stack and memo,
and the original work-limit checks. The HIA payload kernel owns the closed
opcode/profile checks, call/CFG order, SCC membership, constant allocation
provenance, cumulative requests and byte totals, and payload report graph.

The complete original bodies are retained under _reference_ names. The normal
unselected path still calls those bodies. A selected failure does not choose a
reference body or a hosted heap/static-analysis fallback.

## Four immutable image dependencies

A public selection captures these four manifest paths once:

| Environment selector | Source asset | Fixed image adapter |
| --- | --- | --- |
| HEPTA_HIA_HEAP_BOUND_MANIFEST | examples/hia_bootstrap/heap_bound.hiaasm | NativeHeapController |
| HEPTA_HIA_HEAP_LIVE_ENGINE_MANIFEST | examples/hia_bootstrap/heap_live_engine.hiaasm | NativeLiveHeap |
| HEPTA_HIA_STATIC_BUDGET_MANIFEST | examples/hia_bootstrap/static_budget.hiaasm | NativeStaticBudget |
| HEPTA_HIA_HEAP_PAYLOAD_MANIFEST | examples/hia_bootstrap/heap_payload.hiaasm | NativePayloadHeap |

Each uses the existing Linux x86-64 six-argument byte ABI and an exact
source/image/compiler manifest. Each manifest is an operator code selection,
not an input proof or a release-promotion receipt. The source and image bytes
are admitted by the existing loader; immutable mappings stay held for the
whole public operation.

When static analysis composes heap analysis, the selected static entry captures
the same four paths before any foreign program callback. Its heap continuation
reuses the already admitted static image. A nested heap-to-static request never
reselects from the environment and cannot request another hosted heap callback.
No mutable dependency factory is attached to a cached image.

The two small live/payload binding modules expose only SOURCE, SCHEMA, the
existing fixed adapter class, and a one-image loader. They contain no analysis
policy. The worker bundle and checker identity use the same loaders/classes as
public composition. A worker bundle containing the heap controller must include
all three dependencies before importing selected adapters or creating any
executable mapping. Partial groups refuse.

Each public call takes a new path snapshot. Changes made by a foreign callback
cannot replace the held dependency group mid-operation. Missing or invalid
selected images are configuration failures with E_HIA_BUDGET_NATIVE, not
successful policy refusals and not permission to run a retained implementation.

## Foreign boundary

Python remains responsible for these declared operations:

- The existing canonical program verifier and the actual returned checked
  object, including its real as_dict call and exposed identity properties.
- Exact foreign object operations requested by HIA: tuple capture, indexing,
  membership, length, dictionary lookup, and the original CPython type-in-tuple
  operation where metaclass equality is part of the old input domain.
- Fixed byte transport, mmap allocation/growth/release, native entry, and
  representation validation.
- The already native static-budget image, invoked under the same retained
  dependency group.
- Final JSON serialization and SHA-256 at their original positions.

These operations do not choose a heap profile, infer a bound, choose an error
category, traverse the semantic CFG, or reconstruct a result by calling the old
heap analyses. Authoring tools are not imported by installed execution.

Exact object identity and ordering matter. The controller keeps the original
limit, function and scalar argument objects where the original API does.
Finite calls perform one tuple capture. A public finite wrapper keeps its
original argument-container local until its private call returns; the retained
private helper alone can release that container immediately after tuple
capture. The tests distinguish these two original finalizer boundaries.

qualify_live_heap_budget preserves the original double verification sequence:
verify the incoming object, verify the first checked object, obtain only the
second checked document, then use the first checked object's report hash.
There is no extra first-checked as_dict call.

Metadata for integers larger than the fixed scalar width carries sign and bit
length but does not first create a low-word two's-complement temporary. HIA
still decides all public type/range admission. Huge negative policies retain
the original immediate policy rejection.

## Source aliases and generated scalar aliases

Equal values do not imply the same object. The payload bridge retains the
actual checked document alongside the HIA-selected immutable snapshot. It
verifies byte equality before invoking the kernel and records exact source
node offsets with opaque object references. The HIA kernel validates this
occurrence table and emits references to the actual source objects.

This preserves declaration names, actual call-target occurrences, block names,
opcode and argument strings, and constant value identities. It does not intern
all equal strings or merge independently created equal values. Topological
and DFS provenance follow the original edge/declaration ordering.

An allocation constant's generated enumerate index is captured once per
constant record in the kernel's synthetic value pool. Multiple allocation
sites referring to that constant share the same decoded index object,
including values outside Python's small-integer cache. Separate constant
records retain independent identity. No shared native-value-graph codec
behavior was changed to implement this binding.

## Once-only continuations and failure handling

A retained context owns its input, work arena, output, object pool, current
native sequence, and exact issued frame. Before a foreign operation begins,
its permission is consumed. Replaying an old frame, substituting an equal
dataclass, mutating a bound graph, entering with an incomplete outcome, or
using a closed context refuses.

An uncertain native or foreign return closes execution authority. It does not
infer that the effect did not happen or retry the operation. The original
foreign exception object and its traceback remain observable; error cleanup
keeps still-live foreign references when the original exception would retain
its Python frame. Arena cleanup revokes execution first. A real exported
memoryview can delay mapping release, but completing that cleanup cannot
restore execution authority.

These checks assume the existing cooperative Python bridge and admitted native
code. They are not a security boundary against arbitrary same-process memory
mutation. The owner is an in-process analysis state machine, not a durable
journal or a live-release migration mechanism.

## Limits and compilation

The existing bootstrap compiler limits remain unchanged: at most 128
functions, 1,536 total blocks, 8,192 operations, 256 blocks per function,
2,048 SSA values per function, and 16 parameter slots. The live engine uses
exactly 128 functions. The controller and payload engine are separate images;
no larger compiler limit was introduced to fit the composition.

The existing finite-analysis limits remain 1,024 contexts, call depth 64, and
32,768 transfer steps. Native tests exercise both sides of those actual default
limits and compare the complete original result/error. They do not patch a
private Python constant and assume that the HIA image changed.

Heap magnitudes and cumulative event counts use the existing arbitrary-precision
native bigint representation. Typed interval endpoints preserve the verified
scalar domain and original failure/refinement rules. Unknown extents are not
silently interpreted as zero. An exact zero scalar and a degenerate span remain
distinct where the original constructors made them distinct.

## Build and installed custody

tools/build_hia_json_preflight.py exposes heap-bound, heap-live-engine, and
heap-payload candidates. Production builds require a completed matching
current-source cold report through the existing admission gate; the builder
does not bootstrap a compiler or manufacture a successor.

The three HIA assets are included in the explicit Agent resource list and
MANIFEST.in. The installed sdist/wheel tests check exact source bytes inside
hepta/_data. Their isolated child rejects all tools/tests imports, poisons
retained heap/static policy callbacks, exercises all seven heap APIs plus
static composition, and verifies all four mapping identities through the
worker bundle and checker. Changed installed source bytes and each missing
dependency are separate refusal controls.

Test configuration is explicit:

- HEPTA_HIA_HEAP_BOUND_COLD_REPORT selects completed current-source cold builds.
- HEPTA_HIA_HEAP_BOUND_DEVELOPMENT_COMPILER selects a retained compiler for a
  clearly labeled development build. Its historical source qualification is
  not inherited.
- Supplying both refuses before reading either input. Supplying neither skips
  the machine-only fixture explicitly; a skipped fixture is not a native pass.
- HEPTA_HIA_HEAP_BOUND_EVIDENCE chooses the evidence parent. Every fixture uses
  its own exclusive child directory and preserves original logs/results.

The tests record source bytes, compiler/image/manifest bytes, complete original
and native observations, and readback conservation. The independent old VM
compares complete controller buffers with actual machine transitions. Installed
controls test real sdists, wheels and a fresh unrelated working directory.

## Development evidence and retained failures

The current source lineage is a new candidate based on
67382498b9d60bfecf3696d8c2cb632d8f20281b. Earlier pure-kernel inputs were
reconstructed from the byte-verified 26de archive; the missing historical Git
prerequisite was not invented and its historical qualification was not
inherited. The earlier transfer-workflow error and all reconstruction receipts
remain in the independent audit evidence.

Completed predecessor development observations are kept separately:

- Initial native compilation refused one overlarge per-function block count.
  Literal-table grouping repaired the source without increasing compiler
  limits; the original refusal remains.
- Real payload identity witnesses found source-object and generated-index
  alias differences. Corrected r6 machine controls passed all 12 complete
  report/error/alias scenarios; original failing observations remain.
- The original selected r6 public group executed 134 tests with 11 failure
  events. Nine events came from tests that patched hosted private limits;
  two patched a hosted invocation callback. The reference group passed.
- Explicit native branches were added to five original test methods in three
  files. The unselected branches and all original assertions remain. The
  selected branches exercise real HIA continuation points and unchanged
  default limits. Corrected r7 reference 134 and selected native 134 passed,
  with zero skips and no retained heap/static policy calls.
- An initial composition fixture used an unsupported original API/schema
  pairing: eight controls passed and two failed before native execution.
  The corrected original mapping passed all ten on unchanged r7 product
  bytes. Both runs remain distinct.

The installation revision and its repository fixtures require their own
current-source observations and later unified cold/full qualification. The
predecessor observations above are not relabeled as qualification of newly
changed wiring, packaging, checker identity, or the whole product.
