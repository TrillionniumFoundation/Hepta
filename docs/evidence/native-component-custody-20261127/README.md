# Native cold components and separate authoring custody

Native-v2 cold reports qualify the actual native source inventory. Development
builders and independent retained Python models are outside that inventory.
Requiring those host files to appear inside the native manifest prevented the
existing component builders from consuming a legitimate native cold report.

`tools/hia_component_input_custody.py` preserves both domains explicitly. The
caller first runs the full unchanged cold-admission gate. Each captured native
input must match that admitted source map. Host authoring inputs must instead
match regular Git blobs in one clean, exact commit/tree, with physical bytes
and executable modes independently reread. Implementation source suffixes
cannot move into the host domain. A post-build rederivation refuses commit,
tree, blob, mode, byte or scope drift. Legacy cold reports retain the original
requirement that every component input be present in the complete source map.
These host-side receipts do not qualify a release or a whole native stack.

`tools/hia_cold_compiler.py` reads native-v2's separate generation-location
index without manufacturing a legacy `nested_report` or Python-isolation
checks. It verifies the exact original report path/hash/length and all three
distinct generation paths, physical ELF bytes and hashes. It then requires
the original complete cold admission, and rereads the files before returning
B3. The retained legacy route verifies its original nested-report hash and
three physical generations before the same strict admission. An index alone
never confers qualification.

The bounded-memory builder, its original native-test cold selector, the
complete six-module ordinary-caller gate, and the verified-kernel CI consumer
use this explicit boundary. The original cases, independent comparisons,
resource limits, 180+3-second cold limits, 10-minute CI job, and legacy cold
checks are unchanged. Other legacy component builders still need the same
explicit migration; this foundation does not claim they are complete.

## Actual checks and retained failure

The original no-skip unit-gate runner completed 25 controls: 11 real temporary
Git custody controls, eight physical generation-location controls, and all six
existing native cold-admission controls. These include assume-unchanged dirty
files, ignored mode drift, staged changes, symlinks, stale commits, untracked
inputs, omitted native sources, wrong compiler/report pins, boolean/integer
confusion, altered scope fields, missing generations, duplicate JSON keys and
physical image tampering. Synthetic control records are not actual cold
qualification evidence. Native source-contract validation passed with its
unchanged 1,281 source files plus the release contract itself.

An actual explicit-development B1 compiler built the bounded-memory image
(`0d24e0405f6b21643440820ad3af3d7a898df574affe76fc6f39d68d6839537e`).
The original six-module caller gate attempted all 36 tests: 33 passed and
three unchanged Clang comparisons were skipped because this local executor
has no Clang. The no-skip gate correctly returned FAIL. The original complete
compiler bytes, native compile input/output/receipt, manifest, build report,
caller report and test log are retained in
`local-development-original-caller-failure.tar.gz`, with exact per-file and
archive pins in `foundation-readback.json`. A subsequent run on a host with
Clang must retain this failure and perform all original comparisons.

No completed current-source cold compiler, release, installed native worker,
whole-stack replacement or retirement follows from these controls.


## Complete original caller gate on ROG

The exact committed foundation `349232bd7c7c1f583cdcc8e56facb82bf72c46c6`
then ran the same six modules on ROG with actual Clang 21.1.8. All 36 tests
passed, including all three unchanged LLVM/native comparisons, with no skips,
expected failures, errors, or filtering. The independent planned/started/stopped
IDs match; source and bundle pins remained stable. The selected HIA memory
implementation handled 1,733 fill and 1,692 move calls while the retained
Python memory bodies were explicitly forbidden. The gate measured 4.267277265
seconds and the complete command exited naturally with status zero. The owned
checkout was clean before and after the run.

`rog-original-six-callers-passed.tar.gz` retains every one of the 11 physical
build/gate output files plus their complete manifest. Its 160,903 bytes have
SHA-256 `e7765127e25d3dce07d4014eef503de726e1f1f8a50c5ab966449ce0442913d3`.
Every member's original byte length and SHA-256 were independently checked
again after transfer. `rog-original-callers-terminal.json` retains the actual
terminal output and natural-exit observation. This is an explicit-development
component PASS using the unchanged 641,344-byte B1 identified in the retained
local construction evidence. Matching-source cold and whole-native-delivery
qualification remain false; the original local missing-Clang failure above is
preserved without relabeling it.
