# Complete stb_divide component migration

The existing captured C project frontend translates the complete `stb_divide.h`
v0.94 library implementation in two explicitly declared builds. All six public
functions retain their original two-C-`int` signatures. The safe generated code
executes through the existing Rust backend and, on the separately qualified
Linux x86-64 route, the standalone HIA verifier, interpreter and LLVM backend.
Original C implementations appear only in the comparison caller executable.
They are never linked into either generated target.

## Native dependency capture

The capture frontend decodes the fixed Clang `-M`/`-MM` Make rule directly.
Ordinary Windows drive and UNC backslashes survive; spaces, hashes and doubled
dollars follow Clang's filename encoding, while quotes remain filename data.
Shell tokenization is not used for dependency output. The implementation follows
[`PrintFilename` in Clang 20.1.8](https://github.com/llvm/llvm-project/blob/llvmorg-20.1.8/clang/lib/Frontend/DependencyFile.cpp).
Other Make targets, variable expansion, comments, raw ambiguous whitespace and
trailing-backslash filenames are outside this dependency profile.

Every component variant retains independent raw dependency probes before normal
migration, including command, compiler digest, working directory, stdout/stderr
bytes and their digests. These probes are diagnostic records only. Migration
still captures and replays all system and project dependency hashes, and a
missing dependency names the exact rejected path. Neither failed capture nor a
zero declaration inventory can satisfy the six-function component gate.

The first `8b0fd11` seven-host execution passed five Linux/macOS jobs and rejected
both Windows jobs before declaration inventory with `E_C_BUILD_CHANGED`.
Its dependency stdout was not retained. Local tests of corrected dependency
syntax and actual Clang escaped filenames do not convert that failed Windows
run into a pass; each changed source still requires fresh actual-host evidence.

## Source, scope and human input

The frozen official repository revision is
[`003501f6d7a8668ce8b6d875e34dd97ad0d5d5b5`](https://github.com/nothings/stb/tree/003501f6d7a8668ce8b6d875e34dd97ad0d5d5b5).
The complete header is **14,507 bytes and 433 lines**, with SHA-256
`46358dedcc0f49324a602f796b13f24e00fa0e512046354ee69511997401af6c`.
Its Git blob is `6a51e3f2e3b328df25bf9c9a866268782889d08c`.
The MIT/Unlicense text, upstream README and contribution policy are retained
unchanged in `tests/fixtures/c_migration/stb_divide/`. No upstream body is edited
or truncated, and this work makes no submission to the upstream project.

The authored `implementation.c` is the documented two-line include adapter,
58 bytes. There are zero pointer/resource annotations. Human-supplied scope
assumptions are explicit: a measured 32-bit C `int`, nonzero denominator, and
exclusion of `(INT_MIN, -1)` from every original-C call. Independent arithmetic
expectations and the qualification harness are authored support, not upstream
source. Six generated scalar Hepta ABI forwarding wrappers expose the original
names to the HIA native caller; they do not contain hand-rewritten algorithms.
Manual review hours, model-token cost and total migration-cost reduction have
not been measured.

| Build | Capture | Active declaration denominator |
| --- | --- | --- |
| `generic` | C11, `-O2`, `STB_DIVIDE_IMPLEMENTATION` from the unchanged include adapter | 6 definitions + 6 resolved prototypes |
| `truncating` | Same complete source plus `-DC_INTEGER_DIVISION_TRUNCATES` | 6 definitions + 6 resolved prototypes |

The entire source file also retains the disabled built-in self-test harness,
the floor-division simulation, `C_INTEGER_DIVISION_FLOORS` path and C++ linkage
wrapper. These are disclosed inactive branches, not omitted source files or
translated active declarations. This claim covers the six-function library in
the two builds; it does not cover the self-test application, every macro build,
or the other stb libraries. Each output retains raw Clang AST, preprocessed
source, node counts for every active function definition, the full declaration
inventory and captured source/header dependencies. The 433 source lines are
not relabeled as active executable lines.

## Frontend semantics added

Ordinary scalar locals may be declared before receiving their first assignment.
A conservative structured-flow analysis requires assignment on every reachable
path before each read. The analysis intersects branch states, excludes returning
branches from the following join, and assumes a loop may execute zero times.
Self/compound reads before assignment and unmodeled control flow reject. Only
after this check may safe Hepta receive an unobservable scalar zero initializer.
Pointer aliases and record-view initialization retain their separate stricter
rules; zero initialization does not invent initialized foreign data.

Pure scalar conditional values may appear inside arithmetic, initializers and
assignments. Each lowers to a generated helper with explicit `if`/`else` control
flow. Only initialized scalar captures are evaluated at the call site. The
selected branch performs its arithmetic, so an unselected divide-by-zero or
negation of `INT_MIN` is not evaluated. Clang's operand conversions are retained.
Mutating conditions/arms, pointer/record captures and other unsupported
expressions reject. The existing direct conditional-return path remains usable
for its separately admitted slice profile.

The shared scalar lowering also benefits the existing captured C++ profile.
However, this original header does not mark its functions `noexcept`. An actual
attempt through `lower_cpp_project` therefore still rejects with
`E_CPP_PROJECT_PROFILE`. This is a C component migration, not a C++ migration or
an exception/RAII/class ABI claim. No upstream declaration is edited to obtain
a C++ label.

## Functional, resource and failure evidence

The finite corpus contains **21,453 distinct inputs**: 16,512 small-grid pairs,
845 additional deduplicated 32-bit edge pairs, and 4,096 seeded full-width pairs.
The same inputs execute in both builds, yielding **42,906 input/configuration
pairs**. Python unbounded integers independently define truncating, floor and
Euclidean quotients and their corresponding remainders.

Each native caller compiles the actual unchanged header and dynamically loads
the generated target. For each input it invokes all six original functions and
all six target functions, checks both against the independent expectation and
writes all values to a retained TSV. With two original compiler families
(GCC/Clang), two generated targets (Rust/HIA LLVM), and two builds, the collector
observes **2,059,488 native function calls**. This includes repeated original and
target calls across the paired runs; it is not that many distinct inputs.

The independent interpreter has its own explicitly smaller denominator:
58 inputs and 348 function observations per build, **696 observations** total.
These cover selected `INT_MIN`/`INT_MAX` quadrants and other fixed/seeded cases.
Each executes with zero heap budget and checks that every resource counter is
zero. The native Rust target separately has a real allocator probe for attempts,
successful allocations, frees and live allocations, checked around each group
of six calls. HIA LLVM runs do not claim native allocator measurements; their
unavailable native counter fields are `null`.

The component contains scalar arithmetic, with no upstream owned resource or
allocator-failure API. These observations establish the declared zero-allocation
behavior on the corpus; they do not demonstrate migration of an upstream owner,
cleanup stack or allocator failure protocol.

Each generated function also receives zero-divisor and unrepresentable-quotient
inputs in isolated native processes. Both targets and both builds give
**48 target-only native trap processes**, plus interpreter traps. Those inputs
are never sent to original C. A separately compiled, source- and resource-legal
all-zero implementation must fail the actual functional oracle. Three whole
bundle controls each retain all 13 active declarations, reject an added global,
an uninitialized read path or a pointer-returning function, and publish no
partial translated bundle.

The optional Linux GCC UBSan audit instruments the original caller and runs the
entire corpus against Rust targets in both builds. Its **514,872** additional
native observations are reported separately from the main comparison count.
This is an observed undefined-behavior check for those original-C executions,
not a proof over every 32-bit input.

## Actual platform qualification

`hepta-native-hosts.yml` now invokes the portable component collector in each of
its existing seven actual host/compiler jobs, after the original ABI gate. The
portable route freshly captures the whole component with actual Clang, builds
the safe Rust target and runs a C executable using the selected GCC, Clang or
MSVC toolchain. Windows uses its established Visual Studio environment and the
real `LoadLibrary`/`GetProcAddress` ABI boundary; Unix hosts use `dlopen`/`dlsym`.
The job retains the original and generated binaries as well as reports and logs.

A declared workflow step is not a remote execution result. Until a particular
job completes successfully on the integrated source revision, that host's new
component gate remains unqualified. The older seven-host ABI results do not
qualify this component. The additional HIA LLVM route is currently collected
only on actual Linux x86-64, independently of portable Rust route coverage.

Exact upstream fixture bytes are preserved on Windows checkout. Published
migration source files use explicit LF encoding so their stored bytes match
their byte/hash manifests on every host. The collector verifies those manifests.

## Reproduction

For the portable actual-host route:

```sh
python tools/qualify_c_stb_divide.py \
  --clang /path/to/clang --rustc /path/to/rust-1.90.0/bin/rustc \
  --cc /path/to/host-c-compiler --cc-family gcc \
  --expected-system Linux --expected-machine x86_64 \
  --output-directory /path/to/new/stb-evidence
```

For the local complete two-compiler/two-target observation and UBSan audit,
add `--additional-cc /path/to/clang --additional-cc-family clang --hia-native
--audit-original-ub`. On other hosts choose the measured compiler family and host
identity, and omit the Linux-specific additions.

The output directory must be new. `qualification.json` retains failures as well
as successful runs, source-before/after identities, actual compiler identities,
manual-contract boundaries, exact denominators, process traces and a full file
manifest. It does not claim a source equivalence theorem, universal Rust
performance parity, a whole-language safety proof or completion of the six
larger HIA research stages.
