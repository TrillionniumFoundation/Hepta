# HIA direct machine backend: actual qualification, 2026-11-06

## Result

The new backend emits verified HIA Core v1-v8 directly into x86-64 instruction
bytes and ELF64 objects. GNU ld can link the object into a loadable shared
library without any compiler or assembler. No LLVM code generator participates.

The complete fixed qualification passed **173/173 test methods**, with
zero failures, errors, skips, expected failures or unexpected successes.
The complete inventory executed, and all **1211** observed source/fixture files
were unchanged during the run. Elapsed wall time was 29.756 seconds
on the recorded Linux x86-64 environment.

## Exact source binding

- Published source commit: `4ca7b99349a43c02ec7a2621825d84c946fc8f7c`.
- Original tested local commit: `b1410e7c5b8bec9f6273b29a9639de349fa0968f`.
- **Identical complete Git tree:** `6d7c74e77a0cf5e73bbe636c1c0430c8442d89a4`.
- Before/after source-manifest digest: `902b3a2d08815114fa6eeb95568bbda38ad88e85070f0160ba1a2a0ceb5ea4a8`.

The ordinary HTTPS Git push lacked write credentials; the already-authorized
GitHub application published the exact same file tree. GitHub assigned a new
commit envelope. The remote commit was fetched and its tree compared against
the original qualification. This is a tree-identity binding, not a claim that
the original test process ran under the later remote commit identifier.
The test and demonstration receipts below retain their original identities.

## Observed execution

| Check | Recorded result |
| --- | --- |
| Complete fixed suite | 173 methods; 0 failures/errors/skips |
| Arithmetic/cast/ABI adversarial vectors | 11,947 correct native-return cases |
| Adversarial error vectors | 2,212 observed expected SIGABRT outcomes |
| Machine-image preservation | 32,495 nonrelocation bytes unchanged; 48 bytes in 12 declared call relocations |
| Recursive-chain allocator/refusal/cleanup matrix | Original 324 cases passed |
| Pre-write range/swap rejection | 11 invalid-range cases retain original memory at the abort observer |
| Public loader callback names | All 7 rejected before publication |
| Actual v8 returned mutable-loan demonstration | 12/12 VM/native comparisons agree |
| Object generation without toolchain | LLVM imports and subprocess creation forbidden; API, common Core API and CLI passed |
| GNU ld-only shared linkage | Only ld version and ld link commands recorded; no compiler/assembler input |

The adversarial vector counts come from per-test completed-case counters in
`qualification.json`; they are not the total count of all operations in the
other tests. Actual execution covers narrow and 64-bit integer semantics,
complete internal-call results, cyclic block-argument copies, stack-passed
arguments, stack probes, all versioned byte operations, recursive chains,
returned loans, and existing source-to-Core fixtures.

## Reproduction and evidence

```sh
python -B tools/qualify_hia_direct_native.py --output /tmp/hia-direct-result.json
python -m hepta hia build examples/hia_program/parameter_loan_return_v8.hia \
  --backend native --kind object -o /tmp/hia-direct-v8.o
python -m hepta hia build examples/hia_program/parameter_loan_return_v8.hia \
  --backend native --kind shared --linker ld -o /tmp/hia-direct-v8.so
```

- [Complete result and source hashes](qualification.json)
- [Raw test transcript](tests.log)
- [Original source-tree publication binding](source-binding.json)
- [v8 build commands, artifacts hashes and native/VM results](demonstration.json)
- [Direct object disassembly](object-disassembly.txt)
- [Linked shared-library disassembly](shared-disassembly.txt)
- [Implementation and ABI documentation](../../docs/HIA_DIRECT_NATIVE.md)

The standalone demonstration exercised `entry_mut_recursive` at lengths
1, 7, and 64 with byte values 0, 1, 250, and 255. Its object SHA-256 is
`2d883ddb0a7be31dec1a84d7ee971bb6c57e2312110424eddc816f0a7dd50192`;
its GNU ld-linked shared-library SHA-256 is
`9142813f5ff8593376be1e8c8d40eb42003c26a1c8aa0be1d925ffd5ccce8640`.
Temporary binaries were removed after recording exact-byte receipts and
complete disassembly; source and commands reproduce them.

## Findings preserved

The pre-fix backend allowed a public `_init`. A harmless void-returning probe
showed GNU ld creating a `DT_INIT` entry pointing at that wrapper. The library
was not loaded. Public loader/CRT callback names are now rejected, and their
private Core names remain usable only through renamed internal functions.

Initial test-authoring corrections are not native-semantic failures: an
expanded scalar fixture was split into explicit export shards to respect the
existing 128-export ABI limit; a forged-Core test was changed to mutate its
actual canonical bytes; and a disassembly minimum-size assertion was corrected
from 40,000 to 30,000 after the real image contained 32,495 unchanged bytes.
No arithmetic/backend fix was inferred from those fixture corrections.

## Scope

This is an executed, bounded **Linux x86-64** standalone Core backend. The
compiler implementation remains Python. No self-hosting, formal backend
refinement, production integration, other-machine execution, LLVM performance
advantage, or whole-runtime/whole-kernel replacement is inferred. Native VM
fuel/heap/call quotas are not implemented; existing Core traps abort.

The dedicated remote workflow is a separate qualification. Local passing
receipts do not stand in for a queued or failed hosted run. Its observed state
will be reported separately in the pull request and final delivery.
