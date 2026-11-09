# Independent machine-scope review of the PR #824 v16 integration

This is an **observed summary only**, written after the independent read-only
review. It is not a complete new raw qualification archive or a standalone
proof certificate. Original tool stdout/stderr was observed in the review
session but not saved as files. Temporary native images, build receipts and SMT
queries were removed by their test lifetime. No missing raw record has been
reconstructed or relabelled as an original artifact.

The reviewed publication is `edf48dcf9190b177740eb2802c26f24cfec3c936`.
Its tree, `03fed48a967fd33a2cd864c2ac5db8616abb1724`, exactly matches local
commit `18d1ebdf1ebb86da0e8b35a6dbe2e8b82051798a`. The local identity was checked
before and after review. No source file or branch was modified. `summary.json`
records exact hashes for the reviewed models, test modules and helper.

The v2 cast, supplied-artifact and loader-contract test modules completed
**25/25 tests in 3.398 seconds**, zero failures/errors/skips, exit code 0.
These test identities overlap prior qualification and must not be added to a
unique total from another suite.

A separately authored joint subject computes a wrapping u16 product and then
performs a checked cast to u8. The complete input document is recorded in the
JSON summary. Its actual profile-v2 validation returned SAT for caller-contract
nonvacuity and UNSAT for the four declared violation obligations. Six actual
nontrapping native calls agreed with independent masked-integer expectations,
including dirty ABI high bits, 65535-squared and 256-squared wrapping. No
aborting native input was launched. Since the exact temporary object/image and
query bytes are not retained, this is an observation of the validator result,
not a portable retained proof receipt.

The first joint-subject script failed during fixture construction: the helper
`i` was given a fourth positional attribute dictionary and raised
`TypeError: i() takes from 1 to 3 positional arguments but 4 were given`.
This preceded building or solving. The corrected attempt used `mode='checked'`
and completed successfully. The failed attempt remains failed; its traceback
was observed but not saved as a separate original file.

No new deterministic blocking defect was found. The reviewed IMUL semantics
use the low 64-bit product, signed 128-bit truncation for CF and a fresh arbitrary
ZF, and the decoder admits only reviewed unsigned/equality flag consumers.
Checked casts compare normalized unsigned source values with the target's
maximum, under the explicit v2 profile; v1 keeps its original rejection scope.
ELF checks bind section and program-header authority, page order/ranges,
dynamic lookup, PLT/GOT/call relocations and effective RELRO page containment.

The machine track remains **HOLD** for the broader requested theorem. Python
Core/x86/ELF models, Z3, conforming SysV callers and live disjoint borrowed
memory, actual loader mapping and libc abort behavior remain trusted or
assumed. Neither these observations nor additional finite witnesses establish
complete hardware ISA, whole-compiler, general ABI/resource/FFI/loading
correctness or execution/adoption authorization. Subsequent work needs a
mechanized refinement of the admitted decoder/executor and actual loaded-byte
and memory-ownership evidence; the original Agent/provider and NDU-economic
obligations are unaffected.
