# HIA program v6: checked partial byte fill

**Status:** narrow executable semantic/LLVM increment, not closure of all
P0–P7 production language goals. This change extends the *existing single*
\`hepta.hia_program.verify_program\` and its existing interpreter/native emitter.
No second source checker, parser, resource graph, or LLVM backend is created.

## Operation

\`\`\`text
buffer.fill_range(mutbuf, offset:usize, length:usize, value:u8)
  -> ()
  effects { write, trap }
\`\`\`

The mutable view's root must remain live; unique loan exclusion already comes
from the existing verifier. \`offset <= buffer_length\` and
\`length <= buffer_length - offset\` must both hold **before** any pointer
formation or mutation. These subtraction-safe guards avoid unsigned overflow,
including adversarial \`usize::MAX\` input. Zero length at the exact end of a
zero-size or nonzero-size buffer is legal. The LLVM emitter skips the GEP and
memset entirely when length is zero, including a null zero-size owner.

All earlier versions v1–v5 reject this opcode. Version v6 retains their
existing operation profiles and introduces only \`buffer.fill_range\`.
It requires the exact \`write\` and \`trap\` effect upper bounds; fabricated
proof fields and wrong byte/offset types fail closed. The operation is not
included in the allocation-zeroing elision whitelist.

The Python interpreter mutates precisely the admitted byte subrange and
retains normal-path owner/loan cleanup and observable allocator counts. LLVM
consumes independently reverified immutable Core bytes and emits exactly two
dominating unsigned bounds guards followed by a conditional
\`llvm.memset.p0.i64\`; no Rust/C source backend fallback. This is a
finite observational profile, not compiler refinement proof.

## Tests

\`\`\`sh
python -m unittest tests.test_hia_range_fill_v6 -v
python -m unittest tests.test_hia_program tests.test_hia_bulk_memory \
  tests.test_hia_offset_copy_v5 tests.test_hia_program_llvm -v
\`\`\`

New tests cover legal writes, zero-size/zero-count, bounds traps, forged
capabilities/types/effects/attrs, legacy schema isolation, exact emitter
origin/profile, Linux native VM-vs-LLVM return comparisons and an actual child
SIGABRT on out-of-bounds. Local Clang 17 handwritten LLVM control is
**separate evidence**, not an end-to-end run on these exact Hepta modules.

Still OPEN: general value+memory SSA and source→Core refinement; unconstrained
C/C++ L2/L3 translation; GPU/NPU/physical target execution; formal whole-core
soundness; real Agent/model A/B; fair sustained CPU/RSS/p99 performance.
\`whole_project_blockers_closed=false\`.

## AArch64 finite runtime option

The existing `hepta.hia_program_aarch64.run_finite_program_aarch64`
now admits `mode="range_fill"` for an **exact scalar ABI**
`fill_range(usize,usize,usize,u8,usize)->u8`. It constructs a fixed
eight-call driver comparing actual returned bytes and requiring exactly
eight allocations, eight frees, no live owners and no allocator refusals
on the *unchanged, hash-pinned* 4096-byte reviewed runtime. Unsupported
signatures or runtime hash drift reject. `QEMU_SHA256` still pins the
target emulator.

To actually execute on a full checkout with pinned Clang20, lld and QEMU8.2.2:

```python
from hepta.hia_program_aarch64 import run_finite_program_aarch64
from tests.test_hia_range_fill_v6 import fill_program
report = run_finite_program_aarch64(
    fill_program(), clang="clang-20", linker="ld.lld",
    qemu_aarch64="qemu-aarch64", mode="range_fill")
assert report["execution"]["returncode"] == 0
```

The separate Clang17 cross-object control is *not* a QEMU execution; this
driver extension does not demonstrate physical ARM64 target execution.
