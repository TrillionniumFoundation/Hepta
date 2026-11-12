# Filecheck native target policy and failure retention

The filecheck experiment remains a finite Linux x86-64 LP64 application
qualification. Its eight arms, fixed 96 differential inputs, original scalar
ABI, allocation controls, training/held-out separation and performance gate
remain distinct from production Core admission. This change does not adopt an
optimization, switch production authority, or establish backend refinement.

## Reproduced failure and its evidentiary limit

The six-outcome push run on `3d5401cf9bacddfd6d8f14c806b29ce13bb04eed`
terminated with `SIGILL` in the in-process native differential. Its retained
ledger contains the zero-length case for all eight arms, then stops during the
first positive-length case. The original artifact archive, process log and
native libraries are retained with their original source identity. Another
successful run does not turn that failed run into a pass.

The original native-LTO HIA library executes an AVX-512 instruction on its
positive-length path. The original artifact reproduces the same stop under an
explicit Haswell CPU model whose actual CPUID/XCR0 excludes AVX-512: the zero
case returns, the next case signals, and the other seven arms return the oracle
values. The same original libraries return correctly on the available
AVX-512-capable native host. These are controlled execution observations; the
failed CI runner's CPU state was not retained and is not reconstructed as fact.

A separate Clang 20/LLD control makes the target-policy problem reproducible.
With `-march=znver4` and explicit AVX-512 exclusions, raw LLVM IR followed by
full LTO can generate instructions excluded by those flags. The corresponding
C frontend IR carries its complete CPU and feature attributes. Applying those
same attributes to the raw IR preserves the exclusions through LTO. The
controlled CPU execution checks both the failing raw route and the successful
bound route. The explicit CPU model is a regression control, not a replacement
for the experiment's native profile.

## Explicit target attributes for the research build

`tools.hia_filecheck_target_profile.bind_native_target_profile` obtains the
target policy from a small C function compiled by the selected actual Clang
with the selected profile. It validates the frontend's CPU and complete
positive/negative target-feature attributes and applies them to every defined
function of the emitted HIA IR. Missing, malformed or conflicting attributes
are refused. The original emitted IR is retained separately from the bound
research IR, along with the probe, command and identity records.

The research arm retains its full LTO and native optimization policy. This
does not rewrite the default backend receipt or substitute the research
library for that receipt. Both routes still begin with freshly verified Core,
and their final native behavior must pass the existing differential and
resource checks. Compiler/loader/hardware correctness remains a trust
assumption; a target-feature record is not a program admission token.

## Native validation failures remain observable

Differential and maintenance validation execute their native calls in finite
worker processes. The parent owns the qualification report and records the
actual exit status, partial progress and host/tool context. Workers retain the
original call order and emit progress before and after native invocation, so
an interrupted call cannot become an unobserved success. A signal or incomplete
result still fails qualification. Successful reports require the complete
expected inputs, routes and oracle values.

Actual `SIGILL` and `SIGABRT` regression libraries exercise this boundary. The
parent must survive and retain a failed report and the partial invocation
records. The same checks retain ordinary successful validation and reject
invalid requests or libraries. This is finite failure containment for the
qualification process, not a hostile native-code sandbox or proof that
interrupted program resources were normally released.

The performance sampling path remains the original application subprocess
protocol. Validation-worker overhead is not relabeled as application throughput,
tail latency, human migration cost or a performance improvement.

## Required qualification inputs

The integrated actual-tool gate now also records the x86-64 QEMU invocation,
version and executable digest, and includes it in the before/after external
inventory. The safety runner records the linker and x86-64 emulator identities.
The source/application CI installs the required emulator and executes both new
regression modules without accepting skips. The reviewed safety matrix retains
all earlier selectors and adds the masked-target, `SIGILL` and `SIGABRT`
boundaries. Complete regression and current-source host qualification remain
required separately.

The optimization policy remains `no_change`. General CPU dispatch, general
LLVM ABI, representative performance/RSS qualification and physical-device
protocols remain open under the broad P0–P7 obligations.
