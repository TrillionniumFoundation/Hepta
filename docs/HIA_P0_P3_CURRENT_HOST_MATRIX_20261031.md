# HIA P0/P2/P3 — exact-head current-source host matrix qualification

## Source and purpose

Exact reviewed stack parent: PR #480 `f944e996c45584a8102035e8f42d86226aeb50da`, including current P0/P1/P5
finite source and P7 queue generation/token admission research. This follow-up
changes **only three GitHub Actions workflow trigger branch lists**. It does not
change the tested compiler, runtime, ABI, C/C++ translator, objective, test
selection, assertions, tools, or source-bound result formats.

Every job checks out its triggering exact commit SHA. This new branch must
exercise *the current integrated tree*, not transplant old #465 green evidence
from an older build into the new P7 research source.

## Actual independent coverage requested

- Existing `hepta-native-hosts.yml`: 7 actual job profiles across Linux
  x86-64 GCC/Clang, Linux AArch64 GCC/Clang, Windows x86-64 MSVC/Clang, macOS
  AArch64 Clang. Artifacts preserve original C ABI and host-specific failures.
- Existing `hepta-cpp-upstream-hosts.yml`: 7 real C++ compiler/host profiles
  with unchanged multi-version, source, native, and migration assertions.
- Existing `hia-nextstage-source-native.yml`: bounded legacy HSIR collision,
  actual LLVM20 native and project C/C++ source qualification, direct
  LLVM/native x86-64 + AArch64 object checks, migration and strict test gate.

These run by branch push; if any installation, build, test or result retrieval
fails or is skipped, its status remains missing/failed/unknown. Never claim
success from the trigger declaration alone.

## Explicit remaining P0–P7 boundaries

No source-to-machine whole-language refinement, Windows ARM64/device hardware,
general C++ ABI/exceptions/templates, zero-cost migration, source-disjoint
NDU-positive complete cost, unseen Agent net productivity, or durable
P7 journal/crash/restart/external-effect exactly-once is qualified by this
matrix alone. All #471 checklist boxes remain OPEN; `DENY_ALL`.
