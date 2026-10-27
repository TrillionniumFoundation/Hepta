# P1/P7: strict, inode-pinned Resource IR JSON file intake

## Exact code scope

Base: PR #296 `6e934e3b371fb3ba34838347fd9aaa4dc0f7cc83`.
This is a narrow file-intake correctness and availability patch to the
existing `hepta.resource_ir.read_resource_ir`. The resource graph verifier,
schema registry, source lowerer, ownership transitions, and native backends
remain unchanged.

## Bug

The data-only verifier read its input via `Path.open("rb")` and imposed a
16 MiB limit **after** opening. A source path swapped to a FIFO could
block indefinitely at open before the byte cap. A symlink might redirect
the read, while a changed filename could cause the checked graph to differ
from the originally selected input.

## Fix

- Require a nonempty ordinary file, prechecked no larger than 16 MiB.
- Use `O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC`. Fail closed when the
  required secure descriptor flags are unavailable, including unqualified
  Windows host variants.
- Verify device, inode, mode, size, mtime and ctime at `lstat/fstat` before
  and after the single bounded descriptor read, plus the final pathname.
- Preserve duplicate-key rejection and all preexisting JSON/resource
  validation. No hash/receipt can substitute for verifying actual content.

## Tests

```sh
python -m unittest tests.test_resource_ir_cli tests.test_resource_ir -v
python -m hepta.resource_ir /path/to/real/graph.json
```

Committed adversarial tests cover valid bounded data-only JSON, empty
input, sparse oversized input before opening, existing symlinks/FIFOs,
lstat-to-open FIFO/symlink swaps, and post-open path replacement.
Tests assert the nonblocking flag before opening any substituted FIFO so
a regression fails without hanging the test process.

An independent Linux CPython 3.13.5 ordinary/symlink/FIFO descriptor control
confirmed the secure-open premise. It is not exact-head complete Hepta or
Cargo execution, which remains unrun in the present tool container.

P1 Resource IR is still an independent abstract verifier; it is not the
same executable HIA Core, does not prove parser/LLVM refinement, and cannot
claim whole-language soundness, C/C++ L2–L3 migration, physical GPU/DMA/IRQ,
held-out Agent A/B success or production p99.
`whole_project_blockers_closed=false`.
