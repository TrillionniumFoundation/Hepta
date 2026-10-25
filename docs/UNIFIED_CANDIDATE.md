# Unified native candidate — 2026-10-25

The implementation branch unifies the 51287478 candidate, source-bound
resource replay, verified i32/u32 SSA/LLVM origin checks, native Clang C/C++
migration repairs, scoped C++ RAII interoperability, local stored-loan checks,
selected exclusive C++ owner implementation migration and direct owned-byte
LLVM generation. The language goal
remains broader than this candidate. Passing a gate qualifies its stated
profile; it does not close an unsupported feature or a research theorem.

## Semantic authority

[SPEC.md](SPEC.md) is the implemented-language specification. The project
loader and shared checker own source meaning; `semantic_ir.py` is the sole
canonical checked semantic encoder. CFG/SSA/resource projections consume that
meaning and retain their own precise scopes. Rehashed IR is not a replacement
for source correspondence. Current production blockers remain in
[BLOCKERS.md](BLOCKERS.md); historical execution reports describe their own
source snapshots, not this branch automatically.

## Backends

| Property | Rust reference | Independent C | Scalar32 LLVM | Owned-byte LLVM |
| --- | --- | --- | --- | --- |
| Shared source/frontend | Yes | Yes | Yes | Yes |
| Fresh rustc validation | Required | Not used | Reference gate | Reference gate |
| Machine-code route | Rust → rustc | C11 → C compiler | Verified SSA → LLVM → Clang | Checked AST + resource gate → LLVM → Clang |
| Scalar arithmetic | Implemented profile | Explicit checks | Checked i32/u32 | Checked integers through 64 bits |
| Owned ADT/Result/Buffer | Supported profile | Finite profile | Rejected | Finite Buffer<u8>/struct/enum/Result profile |
| Returned/stored borrows | Explicit origins; bounded stored records | Explicit returns; stored records rejected | Rejected | Immediate receiver-tied returns; stored records rejected |
| Tasks/shared budgets/I/O | Hosted qualified profiles | Rejected | Rejected | Rejected |
| Hardware | no_std/BSP profile | Hosted profile | Target objects; execution qualified separately | Linux x86-64 objects/shared libraries only |
| Silent backend fallback | None | None | None | None |

The LLVM path is independent machine-code generation with a Rust reference
validation dependency. It is not yet an independent whole-language type and
ownership implementation. C ABI compatibility is qualified per target, data
model, compiler and exported layout; a general C++ ABI is not promised.

## Migration routes

| Route | What executes after conversion | What remains an external assumption |
| --- | --- | --- |
| C compilation-database module migration | Accepted complete active declaration set in Hepta | Explicit record-view/foreign contracts; unsupported declarations reject |
| C/C++ strict scalar implementation migration | Hepta functions generated from actual Clang AST | Source's defined arithmetic domain; no arbitrary C++ class/STL conversion |
| Selected C++ scalar value class | Hepta struct and real constructor/method bodies; no original C++ link input | Native-checked standard layout and trivial lifecycle; nontrivial resource owners reject |
| Selected C++ exclusive byte owner | Hepta Buffer/Result, move, borrow and cleanup; original implementation absent | Complete closed native AST protocol; arbitrary destructors and moved-from inspection reject |
| C++ direct/span/handle/constructor bridge | Original C++ implementation through checked interfaces | Foreign implementation, retention, thread and allocator contracts |
| C++ scoped RAII operation | Original C++ automatic object; copied result after destruction | Same foreign obligations; no escaped local object or hidden handle lifecycle |

`for` condition-variable placeholders and C++ lvalue ternaries are handled
according to the native AST. A nonempty condition declaration, unsupported
conversion, value-observed increment or unsupported active declaration still
rejects. Native differential checks compare accepted inputs with separately
compiled originals; finite tests are not an equivalence theorem.

`hepta migrate-cpp-class` accepts the complete bounded value-class profile in
[CPP_CLASS_MIGRATION.md](CPP_CLASS_MIGRATION.md). It accounts for each field,
constructor, method and trivial destructor. Source bodies are translated;
this is distinct from the scoped bridge that retains C++ RAII execution.

`hepta migrate-cpp-owned` additionally implements the closed resource-owner
protocol in [CPP_OWNED_MIGRATION.md](CPP_OWNED_MIGRATION.md). The
`tools.qualify_cpp_owned_llvm` gate consumes fresh actual translator output,
builds it with the independent LLVM source pipeline, links only a C observation
driver and executes the same 475 lifecycle/allocation vectors used by the
original C++ and other Hepta backends. The ordinary LLVM examples are not
substituted for the output of that migration.

Local stored byte-slice views have their own independent v4 resource verifier
profile and source replay. General stored-region features are not silently
enabled in the C or LLVM backends by that graph support. The separate
two-version JSON library upgrade measures actual generation/build/compatibility
and preserves both catchable allocation failures and foreign process termination.

The owned LLVM performance protocol compares two unchanged Rust baselines.
`tools.qualify_llvm_owned_rust_allocator` separately recompiles those sources
with an observing global allocator and executes actual first/second-allocation
refusal, cleanup and recovery, plus compiled deallocation-leak controls. This
untimed gate records instrumented programs; it does not claim to observe the
allocator trace of the uninstrumented performance binaries.

## Reproduce current acceptance

Install the exact checked components with `tools/bootstrap_toolchain.py` and
`tools/bootstrap_verification.py`, or supply matching local executables.
Set `RUSTC` and `LEAN`; put the selected Clang/C++ drivers on `PATH`.
The owned LLVM profile requires a native Clang 20+ Linux x86-64 driver.
The full-gate CI workflow explicitly installs LLVM 20 from LLVM's signed
Noble repository, verifies its published signing-key fingerprint and selects
`/usr/lib/llvm-20/bin` for subsequent steps. It does not assume the runner's
default Clang is new enough. Each qualification records the actual compiler
version and binary digest; this package setup is not a claim that a queued
workflow executed. Upstream configuration references are
[the runner image inventory](https://github.com/actions/runner-images/blob/main/images/ubuntu/Ubuntu2404-Readme.md)
and [LLVM's package repository](https://apt.llvm.org/).

```sh
python -m unittest discover -s tests -v
python tools/release_check.py \
  --output-directory evidence/my-new-candidate \
  --continue-on-failure \
  --qemu-aarch64 /absolute/path/to/qemu-aarch64-static
```

The output directory must be new. All source files are hashed before and after
qualification. Each command, exit status, elapsed time and log digest is
retained. `--continue-on-failure` gathers remaining independent results; it
does not permit a failed or skipped gate to pass. A source change during the
run fails the aggregate. The final report records every planned gate and the
code commit used for the run.

The earlier exact 776f005d candidate passed all 40 gates and is preserved under
`evidence/unified_candidate_20261025/`. The resource extension is qualified
separately under `evidence/resource_candidate_20261025/`; the aggregate's exact
commit and status decide acceptance. Failure/unknown entries remain part of
the evidence. Genuine model trials, physical boards,
GPU execution, production service loads, full-language soundness and universal
performance superiority need their own evidence. Scripted evaluator fixtures,
QEMU and small abstract Lean cores cannot establish those claims.
