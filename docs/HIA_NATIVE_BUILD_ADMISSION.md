# Native artifact and build-receipt admission

`HEPTA_HIA_NATIVE_BUILD_ADMISSION_MANIFEST` explicitly selects one source-bound
HIA byte image for four complete methods from commit
`aac7550ee2e5d5c3d0e42567ee35e2acfa28f759`:

| Mode | Original method | HIA responsibility |
| --- | --- | --- |
| 1 | `_signatures` | Scalar filtering, ordered parameter/return loops, then borrowed-buffer overrides |
| 2 | `_native` | Installation/context binding, admitted Core identity, exact signatures and export binding |
| 3 | `_build_inputs` | Every original receipt/metadata/object/final-byte binding check |
| 4 | `_build_receipt` | The complete mode 3 observation followed by the original receipt projection |

Build-to-native-to-signature subcalls stay within the same continuation. A selected
owner never calls any of the four retained Python bodies. Empty, malformed,
unbound or changed selections fail; they do not choose the portable path.
Unselected calls retain the original lazy route.

## Exact boundaries

The HIA image owns every original composite condition, short circuit, loop and
accept/refuse path in these four methods. The adapter retains opaque Python
objects and exposes individual access, iteration, comparison, truth and container
operations. The existing `_program` Core checker, `_context` provider,
`normalize_exports` ABI provider, Store/SQLite and SHA-256 remain explicit foreign
providers. This component does not claim to rewrite or prove those providers,
the surrounding proof-policy methods, emission, evaluation or adoption.

The complete original input behavior is retained: `!=` keeps its own Python
protocol; export materialization precedes the Core hash check; late hashes and
object reads remain behind their original conditions; exact `dict` checks are
unchanged. The two signature passes preserve one-shot iterator consumption and
the different evaluation orders of a dictionary comprehension and a subscript
assignment. Generator-body `StopIteration` retains PEP 479 conversion, whereas
iterator exhaustion and the outer `any` truth operation keep their distinct
original meanings. No new shape, integer-magnitude or frame-count quota is added.

## Continuation custody

The six-argument byte ABI uses an 80-byte request, 128-byte private state and
96-byte receipt. HIA issues a fixed foreign port, validates a claim, then accepts
an acknowledgement or a confirmed foreign exception. Sequence, phase, mode,
identity and state are checked on each observation. Invalid, stale or replayed
acknowledgements cannot advance an effect. Frames belong to their creator
process and thread.

Growable custody is reserved before effects. A confirmed success or foreign
exception releases its frame. An unconfirmed native return fences the frame and
retains it until process exit; no retry, implicit completion or cleanup is
invented. Ordinary native transport errors caught by the public request rejection
wrapper are converted to `NativeBuildAdmissionUnknown`, including RuntimeError
intersections such as RecursionError. Other RuntimeError objects and process
control signals retain identity. A confirmed foreign exception remains the
original object and is not reclassified as native transport loss.

The image is a registered single-image worker helper. The standard pinned-loader
scope is checked before standalone selection. The installed worker uses the
packaged `.hepta` resource, not a source-checkout path or authoring import.

## Independent controls

Five byte-frozen original functions, including the separate
`_behavior_equivalence` caller, are retained as fixtures. The independent oracle
contains 303 scenarios authored from those original functions before candidate
execution. Comparison uses canonical JSON bytes, including exact tuple/list and
byte representations, returned object aliases, exception causes and complete
ordered provider traces. Six scenarios additionally compare the reference Core
VM and the actual native image, including all returned and mutated buffers.
These are finite observations, not an all-input equivalence theorem.

The source inventory freezes nine complete ordinary modules with 112 test IDs,
plus eight separate scope modules with 128 outer IDs. Inherited tests are
included. The ordinary qualifier runs all 112 methods with all four retained
bodies forbidden and reports actual per-test native entries and per-mode frames.
It does not claim that every method enters the owner. Parent-only poison does
not establish child-process coverage; installed-worker controls separately
poison the actual child's four retained methods and prohibit authoring imports.
The original separate helper bundles and nested tests retain their own scopes.
A completed `hia_verify` replay keeps its original read-only subject revalidation: one complete mode 4 observation. It must not publish artifacts or change the completed request/cost records. A replay of unknown durable intent performs no admission frame.

The new controls also cover manifest/source drift, thread and finished replay,
forged ACKs, unknown transport custody versus confirmed foreign exceptions,
installed worker intent/replay after a lost ACK or process exit, and a pinned
seven-owner composition with the existing context, Store, execution budget,
candidate budget, cost ledger and evaluation owners. Original test bodies,
deadlines, workload limits and mathematical assertions are not replaced.

## Reproduction

A matching-source cold component is built with:

```sh
python -B tools/build_hia_native_build_admission.py --compiler COMPILER --cold-report COLD_REPORT --output NEW_DIRECTORY
```

Explicit development uses `--development` instead of `--cold-report`. Development
artifacts never count as matching-source cold qualification.

`NativeBuildAdmissionSourceTests` needs no native compiler. The native class
requires exactly one nonempty `HEPTA_HIA_NATIVE_BUILD_ADMISSION_COLD_REPORT` or
`HEPTA_HIA_NATIVE_BUILD_ADMISSION_DEVELOPMENT_COMPILER`. Optional
`HEPTA_HIA_NATIVE_BUILD_ADMISSION_EVIDENCE` names a fresh evidence directory.

```sh
python -B -m unittest tests.test_hia_native_build_admission_native.NativeBuildAdmissionSourceTests -v
python -B -m unittest tests.test_hia_native_build_admission_native.NativeBuildAdmissionNativeTests -v
python -B tools/qualify_hia_native_build_admission_callers.py --cold-report COLD_REPORT --evidence NEW_CALLER_EVIDENCE
```

The caller qualifier also accepts explicit `--development-manifest MANIFEST`.
Reports retain their actual scope, complete ordered IDs, anomalies, source/image
pins and caller counts. No report in this component authorizes deletion of the
remaining hosted implementation or asserts complete native delivery.
