# HIA direct x86-64 machine backend

The direct backend consumes independently verified standalone HIA Core and
writes x86-64 instruction bytes and an ELF64 relocatable object itself.
It does not generate LLVM IR, C, Rust, or assembler input. A shared library
adds a separate system-linker step over the generated object.

The implementation is in
[`hia_program_native.py`](../hepta/hia_program_native.py),
[`hia_machine_x64.py`](../hepta/hia_machine_x64.py), and
[`hia_machine_elf.py`](../hepta/hia_machine_elf.py). The verifier remains
[`hia_program.py`](../hepta/hia_program.py); ownership and parameter-loan
admission are shared with the interpreter and the existing LLVM backend.

## Build and use

Object generation requires Python and the repository, with no assembler,
compiler, or linker process:

```sh
python -m hepta hia build examples/hia_recursive_chain/core_v7.json \
  --backend native --kind object -o /tmp/hia-core-v7.o
```

For a shared library on a Linux x86-64 LP64 host, GNU `ld` can link the object
directly:

```sh
python -m hepta hia build examples/hia_recursive_chain/core_v7.json \
  --backend native --kind shared --linker ld -o /tmp/hia-core-v7.so
```

`--linker cc` is also supported. In that mode the C driver receives an existing
ELF object and linker flags, with no source or intermediate representation to
compile. The linker and its command capture are recorded in the build receipt.
Output paths must be new files inside existing directories.

The original LLVM route remains the CLI default. Select `--backend native`
explicitly for this backend. Its only admitted target is
`x86_64-unknown-linux-gnu`; other targets are rejected. The `hia emit` command
continues to emit LLVM text and is not part of direct object generation.

The Python API separates generation from publication:

```python
from hepta.hia_program import verify_program
from hepta.hia_program_native import (
    emit_program_machine, compile_program_machine,
)

program = verify_program(document)
image = emit_program_machine(program)
receipt = compile_program_machine(
    image, program=program, output="/tmp/program.o", kind="object"
)
```

`build_program_machine(document, output, kind="object")` performs both steps.
Both boundaries independently reverify the exact program; publication re-emits
and compares the complete machine-image record. A constructed dataclass or a
recomputed digest does not grant admission to modified code.

## Supported Core and ABI

The reviewed instruction inventory covers all primitive Core v1–v8 operations:
fixed-width integer and boolean operations, closed block-argument SSA,
internal calls, owned byte buffers, lexical and reborrowed views, versioned
bulk-byte operations, recursive buffer chains, and v8 parameter-bound returned
loans. Composite inputs use the existing verified normalization into those
primitive schemas. New schemas, types, opcodes, or terminators require an
explicit backend change; a future verifier extension cannot silently broaden
the machine-code profile.

| Boundary or value | Representation and rule |
| --- | --- |
| Public function arguments | SysV AMD64 integer and boolean C arguments; first six in the ordinary argument registers, remaining arguments on the caller stack |
| Public return | At most one integer/boolean result; no result and `unit` results use C `void` |
| Public resource descriptors | Not exposed; a foreign caller cannot construct a buffer, loan, or chain through this ABI |
| Internal scalar | One 64-bit slot, sign-extended or zero-extended according to the declared type |
| Internal byte owner/view | Two slots: pointer and byte length |
| Internal chain | One pointer to `Nil` or a 24-byte node containing payload pointer, payload length, and tail pointer |
| Internal calls | Private array-input/array-output convention; resource and multiple-result signatures stay internal |
| Explicit export list | Complete contract; an unrepresentable signature rejects the entire build |
| Implicit legacy exports | Only representable public scalar entrypoints are emitted |

The emitter keeps values in stack slots, stages all block-edge arguments before
writing destination slots, preserves the ABI's callee-saved registers, and
aligns the stack before every call. Frames are limited to 64 KiB and touch each
4-KiB interval during allocation. This is a straightforward baseline for later
register allocation and optimization; no speedup over LLVM is claimed.

## Semantic details retained from Core

| Operation | Required behavior |
| --- | --- |
| Checked integer arithmetic | Overflow traps at the declared width, including narrow types |
| Signed division and remainder | Truncate division toward zero; both trap on signed minimum divided by minus one, at every width |
| Checked shifts | Reject a negative or out-of-width count; left shift then wraps at the declared width |
| Zero-length allocation | Successful empty owner, without calling an allocator |
| Failed `buffer.try_new` | Empty owner plus false; callers still consume the owner according to Core |
| Allocation over `INT64_MAX` | Reject before calling libc; trapping or fallible outcome follows the opcode |
| Empty owner drop | No `free(NULL)` event |
| Byte range operation | Validate offsets and remaining capacity before pointer formation or writes; skip libc calls for zero bytes |
| Byte swap | Check both indices before either byte is modified |
| Failed chain push | Return the original tail and payload, with false |
| Successful chain pop | Free only the node header and transfer its payload and tail |
| Chain destruction | Iterative; free every nonempty payload and each header exactly once |
| Program trap | Call `abort`, followed by a nonreturning machine instruction if it unexpectedly returns; no cleanup after an abort is promised |

The backend uses libc allocation and byte operations, with the declared
assumptions that allocation returns fresh nonaliasing storage or null and that
libc implements its standard memory semantics. The machine encoder, ELF writer,
verifier, linker, loader, libc, and hardware are part of the trusted execution
environment.

Native execution does not implement the interpreter's step, heap, or call-depth
quotas. An optional static bounded-resource report remains a separate Core
analysis and does not establish machine-level resource refinement. Native
recursive calls consume native stack space.

## Artifact checks and receipts

Objects carry private implementation symbols, public C entrypoints, explicit
relative call relocations, and a non-executable-stack note. The closed import
inventory permits only `abort`, `calloc`, `malloc`, `free`, `memset`, `memcpy`,
and `memmove`.

Shared-library publication runs the existing independent ELF inspector. It
checks the actual loader-facing symbol tables, segment permissions,
non-executable stack, and admitted dependencies. Unreviewed loader redirects,
TLS/interpreter entries, text relocations, and writable-executable segments are
rejected. Files are published without replacement and re-read for exact-byte
identity.

Receipts bind the input and normalized Core hashes, direct implementation
identity, machine text, object and final artifact, target, exports, symbol
inventory, frame sizes, and the actual linker where one was used. A successful
receipt describes generation/linkage; it deliberately does not claim that the
artifact has already been executed or that the backend has a formal refinement
proof.

### Loader-hook defect found during review

The first GNU `ld` integration accepted a valid public Core function named
`_init`. Linking a harmless void-returning fixture and inspecting the dynamic
table with `readelf` showed `DT_INIT` pointing to that generated wrapper. This
would turn an explicitly callable HIA function into a loader lifecycle action.
The observation was made from the linked ELF metadata; the library was not
loaded to execute the hook.

The backend now rejects public exports named `_init`, `_fini`,
`__gmon_start__`, `_ITM_registerTMCloneTable`,
`_ITM_deregisterTMCloneTable`, `__cxa_finalize`, or `__dso_handle` before
object publication. A Core function with such a name may remain internal:
internal calls use private renamed ELF symbols, and the reserved original name
is never exported. Regression tests cover both the seven public rejections
and the safe internal-name case.

## Reproducible verification

The qualification runner records the complete test inventory, actual executed
tests, failures/errors/skips, and the before/after source hashes:

```sh
python -B tools/qualify_hia_direct_native.py \
  --output /tmp/hia-direct-native-qualification.json
```

Missing or skipped required tests fail this qualification. The focused review
suite can also run independently:

```sh
python -m unittest tests.test_hia_program_native_review -v
```

The independent review adds these checks to the scalar, memory, v8-loan,
source-lowering, and encoder coverage in the main suites:

- The existing **324-case** recursive-chain matrix, including every selected
  payload/header allocation refusal, compared against both the old independent
  arithmetic specification and the interpreter. Actual allocation counts,
  frees, node/payload accounting, peak/live bytes, null frees, and invalid frees
  are checked by the original C observer.
- A caller witness that supplies dirty upper register and stack bits for narrow
  arguments, verifies callee-saved registers and stack restoration, and reaches
  a function whose frame exceeds one page.
- Zero-byte memory operations observed at wrapped libc boundaries: no allocator,
  free, or memory-function call is permitted.
- Invalid ranges and swaps observed at the abort boundary, proving that bounds
  rejection happens before partial writes, including extreme unsigned offsets
  and lengths.
- A simulated future verifier accepting new schemas/types or arithmetic and
  boolean opcodes; the reviewed backend must reject them explicitly.

The C and assembly files used by these tests are independent callers and
observers. They are not implementations of the HIA program. A separate fresh
process test prohibits LLVM imports and all subprocess creation while emitting
and publishing a direct object.

## Qualification boundary

This delivery is a Python-implemented direct machine-code backend for the
admitted standalone Core profile on x86-64 Linux. It supplies an independent
route around LLVM's code generator. It does not establish HIA compiler
self-hosting, other instruction-set backends, full operating-system/runtime
replacement, formal whole-language soundness, production adoption, or a
performance advantage. Those require their own implementation and evidence.
