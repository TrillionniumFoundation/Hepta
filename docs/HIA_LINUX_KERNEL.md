# Linux 6.18.60: whole-source intake and a real kernel component route

This campaign targets an operating-system kernel. It must not be confused with
the small numerical kernels used by earlier HIA/NDU experiments. The requested
end goal is a Linux implementation rewritten in HIA and a fair system-level
comparison. The present compiler does **not** implement that end goal.

The prospective [comparison protocol](../benchmarks/hia_linux_kernel/PROTOCOL.json)
separates the goal from the narrower artifacts that the current implementation
can produce. A successful stock build or mixed-kernel boot cannot satisfy the
whole-HIA-kernel gate. A failed migration is retained as a measured failure, not
deleted from the denominator.

## Upstream identity and scope

The source is Linux **6.18.60**, stable commit
`f45ed76d6791cf72ff1265ee93511175bbbc2f18`, official archive SHA-256
`3c2f44ef6acc021a7ad444d9a2e6ec1ef488ff09368793d0004a6080f69d621e`.
The archive URL, signed-tag identity, checksum source and verification boundary
are in the protocol. Matching an official published checksum is distinct from
locally verifying an archive signature.

Extraction must preserve the original symbolic-link text, including redundant
`./` components. An extraction API can normalize a link while leaving every
regular file unchanged. The stock collector independently compares the whole
directory against the checked archive; a normalized link is a recorded input
mismatch, not a reason to weaken that check. Retain the mismatching run and
extract a separate exact tree before retrying.

There are three different denominators:

| Denominator | What it establishes | What it does not establish |
| --- | --- | --- |
| Complete archive manifest | Every original regular file and symlink target across architectures, drivers, tools and tests, with byte identity | Every configuration compiled, every function parsed, or all source semantics rewritten |
| Original compilation database | Every target C compilation command in one resolved configuration, with exact original arguments and rejection status | Assembly, Rust, link scripts, host tools and all other Kbuild inputs covered by a C-only database |
| Actual HIA component/object route | A named HIA body, its explicit ABI bridge, real linked image and observed execution checks | An entire translation unit, subsystem, configuration or Linux source tree rewritten |

The suffix-classified `.c/.h/.S/.s/.rs` count is a useful inventory statistic.
Link scripts, device trees, Kconfig and build-generation logic can be classified
as `other`; none disappears from the complete archive manifest.

## Existing migration intake remains strict

[`qualify_hia_linux_translation.py`](../tools/qualify_hia_linux_translation.py)
first attempts the original whole-project capture. The current C capture has
explicit database-size and command-count limits. These are reported directly;
the campaign does not raise them and then declare whole-project admission.

It also exercises the original command-admission function on **every** database
entry. An individual-entry shard preserves the original arguments and the
original database directory resolution. The complete database is retained.
No database command is executed as a shell program. No GNU C or architecture
flag is silently removed to obtain a successful result.

A command rejected by this gate has `declaration_analysis=not_reached`. Its
functions are not counted as analyzed, unsupported or rewritten. A command
admitted by intake advances to the real captured-project Hepta translator;
Hepta source or a generated Rust bridge still does not establish an independent
HIA kernel object. The command ledger distinguishes those stages.

Example invocation, after obtaining the source and completing the stock build:

```sh
python -B tools/qualify_hia_linux_translation.py inventory \
  --source /absolute/path/linux-6.18.60 \
  --source-receipt /absolute/path/source-receipt.json \
  --output /absolute/path/new-source-inventory

python -B tools/qualify_hia_linux_translation.py intake \
  --source /absolute/path/linux-6.18.60 \
  --database /absolute/path/build/compile_commands.json \
  --config /absolute/path/build/.config \
  --clang /absolute/path/llvm-20/bin/clang \
  --output /absolute/path/new-translation-intake
```

Output directories must be new. The receipt format is produced by the archive
acquisition step; it includes `version` and `sha256` plus the verification method.
The collector checks its own source identity across execution. The intake also
binds all Hepta Python compiler sources using the existing `compiler_hash()`.

## Real build and execution layers

The stock baseline builds the selected `x86_64_defconfig` with a recorded boot
overlay, using a fixed Clang/LLVM toolchain and an independent `O=` directory.
It retains the resolved configuration, original compilation database, build
logs, object/symbol inventories and actual kernel image identities.

A static guest PID1 runs bounded process, memory, file and IPC/network checks
inside QEMU TCG. The host checks the complete guest record and exit. These
checks are finite OS smoke tests. They are neither the complete Linux
`kselftest` suite nor all KUnit tests, and CPU enumeration is not a proof of
SMP race freedom. TCG timings are not bare-metal performance measurements.

Workspace QEMU packages require their explicit `QEMU_MODULE_DIR`. The runner
binds every shared module in that directory and records a paused TCG startup
followed by `quit` before spending time on a kernel build. That preflight does
not execute a kernel. A boot PASS additionally requires the actual guest run;
the module bytes and execution environment must remain bound throughout.
Retain an earlier module-loading failure and its successful build separately
from any newly frozen, complete build-and-boot campaign.

The component path targets the software 32-bit population-count implementation
used by the x86 kernel. On this architecture the active original is
`arch/x86/lib/hweight.S`; the superficially similar `lib/hweight.c` is not the
active implementation. The inline-assembly caller has a special register
preservation contract, so a normal C-ABI object cannot replace it directly.

The new HIA object is a restricted total integer leaf. Its explicit assembly
bridge remains assembly and is included in coverage accounting. The original
64-bit implementation remains original. The 8-bit and 16-bit inline adapters
are not counted as independently rewritten kernel functions. The pure HIA
body does not gain an unmodeled shared counter to claim execution coverage.

The stock mirror, a common-selftest control and the mixed HIA candidate use
explicit source trees and build directories. The original downloaded tree is
not modified. Control and candidate run the same checks with the same CPU and
configuration. Positive execution requires independent outputs and the linked
object/route identity; an unused symbol does not qualify a replacement.

## Full-kernel blockers are system capabilities

The following requirements cannot be closed by one integer leaf replacement:

| Requirement | Why it remains separate |
| --- | --- |
| GNU C and full build capture | The current front end has bounded language/flag/project profiles; retaining source bytes is not translating them |
| Global, section and per-CPU storage | These require an explicit independent HIA storage and placement model |
| Function pointers and cross-object linkage | The current closed named-call profile does not implement arbitrary Linux callbacks and external linkage |
| Linux layouts and raw-pointer aliasing | Packed records, unions, intrusive lists and `container_of` require actual layout/provenance obligations |
| Volatile, atomics, barriers and MMIO | A Rust/C wrapper or a design document does not implement these operations in the independent HIA authority |
| Allocation, failures and execution context | Hosted `malloc`/`abort` are not kernel allocators, GFP constraints or kernel trap handling |
| IRQ, preemption, SMP and RCU | These require kernel-specific concurrency and lifecycle semantics plus real execution qualification |
| Boot, UAPI, drivers and configuration matrix | One x86 configuration and a finite guest smoke do not establish Linux compatibility across supported systems |
| Global NDU comparison | Requires real eligible images, actionable candidates and online decisions before outcomes, not retrospective scores |

The actual source locations and measured rejections belong in the retained
run report. This table describes obligations, not a blanket impossibility
theorem about future HIA implementations.

## Separating HIA effects from NDU effects

The protocol registers original Linux, static HIA, the strongest development-
selected fixed policy, state-visible greedy, ordinary MPC, a same-objective
controller, fixed-preference NDU and dynamic NDU. Original Linux already has
adaptive algorithms; it is not labeled a static or deliberately weak control.

All adaptive HIA arms receive the same observation interface, legal candidate
permissions, forecast inputs and computation caps. One external objective
scores all outcomes. Internal planning objectives are declared rather than
silently equated. A bounded exact oracle may test a small projection; it is
not a free future-information source or the optimum of the whole OS.

Stationary, adaptive and misleading-feedback regimes remain distinct. Runtime
decisions must consume real resources and affect later execution. Calibration,
failed attempts, code generation, validation, compilation, switching, warmup,
retained memory and workload execution are retained in the cost ledger. An
outer total is not added again to its nested components.

The present full-kernel comparison status is `NOT_RUN` unless the whole-kernel
admission gate is genuinely satisfied. A mixed-kernel component result can
have its own positive correctness result while the whole-HIA and NDU-gain
claims remain false. That distinction is part of the executable contract.

## Regression and CI scope

[`qualify_hia_linux_tests.py`](../tools/qualify_hia_linux_tests.py) runs the exact
five-module regression inventory, including actual Clang native-object tests.
It uses the existing started/finished test-identity gate and refuses skipped
tests, missing tests, unexpected outcomes and source changes. A clean frozen
checkout and real tool paths are required:

```sh
HIA_KERNEL_CLANG=/absolute/path/llvm-20/bin/clang \
HIA_KERNEL_OBJDUMP=/absolute/path/llvm-20/bin/llvm-objdump \
python -B tools/qualify_hia_linux_tests.py \
  --output /absolute/path/new-linux-regressions.json
```

The matching CI workflow retains this receipt. These source/contract/native
leaf tests do not replace the separately recorded stock and mixed Linux builds
and guest runs.
