# Unified native candidate — 2026-10-25

The implementation branch unifies the 51287478 candidate, source-bound
resource replay, verified i32/u32 SSA/LLVM origin checks, native Clang C/C++
migration repairs, and scoped C++ RAII interoperability. The language goal
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

| Property | Rust reference | Independent C | Independent scalar32 LLVM |
| --- | --- | --- | --- |
| Shared source/frontend | Yes | Yes | Yes |
| Fresh rustc validation | Required | Not used | Required reference gate |
| Machine-code route | Generated Rust → rustc | Generated C11 → C compiler | Verified SSA → LLVM IR → Clang |
| Scalar arithmetic | Implemented profile | Implemented profile with explicit checks | Checked i32/u32, Boolean control flow |
| Owned ADT/Result/Buffer | Supported profile | Supported finite profile; resource verifier required | Rejected |
| Returned/stored borrows | Explicit origins; bounded stored records | Explicit returned origins; stored records rejected | Rejected |
| Tasks/shared budgets/I/O | Hosted qualified profiles | Rejected | Rejected |
| Hardware | Qualified no_std/BSP profile | Hosted profile | Target objects; target execution qualified separately |
| Silent backend fallback | None | None | None |

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

## Reproduce current acceptance

Install the exact checked components with `tools/bootstrap_toolchain.py` and
`tools/bootstrap_verification.py`, or supply matching local executables.
Set `RUSTC` and `LEAN`; put the selected Clang/C++ drivers on `PATH`.

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

The current execution report and the seven-stage outcome are stored under
`evidence/unified_candidate_20261025/`. Its failure/unknown entries, if any,
remain part of the candidate evidence. Genuine model trials, physical boards,
GPU execution, production service loads, full-language soundness and universal
performance superiority need their own evidence. Scripted evaluator fixtures,
QEMU and small abstract Lean cores cannot establish those claims.
