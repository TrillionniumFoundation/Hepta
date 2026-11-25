# Native generation probes and retirement

This checkpoint supplies native preparation effects for the scalar multiversion runtime. It does not yet replace the complete public runtime or its background optimizer. The coordinator, native proof service, preparation transport, leases, thread ownership, and Future lifetimes still require their final integration gates. The accompanying JSON deliberately keeps whole-runtime completion false.

## Executed components

The native preparation path now has three actual in-process operations:

1. The existing image owner reads and checks the generated ELF, retains its path identity, seals its bytes, loads it, resolves all exports, and checks the actual loaded mappings.
2. The probe owner independently projects the complete canonical Core into the existing scalar reference wire, runs the HIA scalar VM for every original finite probe vector, calls the actual held native function, and compares the typed result.
3. The retirement owner transfers the image owner's actual acquisition history to the existing HIA retirement-state owner. Every release effect requires that owner's fresh preclaim receipt. It operates on the same held library, descriptors, path, and identities.

The effect owners and their packers are HIA. Their small assembly adapters perform fixed syscalls, fixed role calls, dlclose, or the selected SysV scalar call. The packers produce general-layout ELF relocatable objects; the native multiversion shared linker resolves the closed loader imports. Development qualification assembles the readable adapters independently and compares the complete capsule, holes, symbols, and relocations. That assembler is not used by the product packaging path.

## Full finite probes

hia_mv_probe is a private six-word entry taking the complete canonical Core, a 128-byte result buffer, and the admitted image owner's 160 MiB workspace. The enclosing preparation owner must bind that Core and the actual native build receipt. The entry is not a proof authority and must not admit a caller's ok flag.

It retains the original vector selection, deduplication, and ordering. It covers all eleven scalar ABI types and zero through sixteen arguments. Signed narrow arguments are sign-extended for the reference VM. Actual native returns use their original C ABI width; boolean returns use the low byte.

The original reference budget is 4,224 steps and depth 256. A scalar VM status of 14 requests additional frame workspace; the owner resumes that same execution with the requested capacity within its existing 48 MiB workspace area. It does not restart the VM, reset its steps, or increase the depth bound. Ordinary single-frame executions retain their original initial capacity.

The result begins with HIAMVPR1. Its words contain status, export/vector indices, expected/actual value words, the last step count, actual native-call count, accumulated steps, and the last role result. A successful finite probe is required in addition to the independent all-input proof. It does not establish all-input correctness by itself.

The actual qualified observations are kept separate:

- The vector-generator component compared 283 positive signatures and thirteen refusal cases against the original helper, totalling 16,547 vectors.
- The original six actual ELF fixtures executed 3,936 complete HIA-VM/native pairs. Those fixtures cover every scalar type, arities zero through sixteen, mixed signatures, proved-total operations, and long names.
- All 283 positive signature fixtures were then compiled with the actual HIA hia-build-shared entry in eighteen groups. Every one of their 16,547 vectors ran through the actual HIA VM and the actual loaded native function. Each group was retired through the same native holder.
- Eleven private fault cases exercise checked arithmetic, all five explicit trap reasons, the original step budget, and the original call-depth budget. The failing vector is never called natively.
- A well-formed ELF with deliberately wrong actual machine code is rejected by the live VM comparison. Invalid Core, a missing function/address, and a different process are also rejected.

The deliberately trapping, recursive, and cyclic programs are private fault tests. The public multiversion profile or proof service rejects them earlier. They are not an expansion of the accepted public profile.

## Same-holder retirement

hia_mv_retire accepts HIAMVRT1, operation 1 (attempt) or 2 (query), and the private generation identifier. It uses the same image workspace and returns a 768-byte HIAMVTR1 receipt.

The initial handoff records only effects the actual image owner has already performed. It never reopens a path to fabricate an earlier pin, repeats a close, or reconstructs ownership from caller-provided booleans. The existing retirement_state role remains the authority for preclaims, acknowledgements, native-release status, disk observations, and completion.

Native function addresses are cleared after the release right is claimed and before dlclose. A failed or interrupted close is uncertain and is never retried on that descriptor number. This remains true if an external actor later reuses the number. Disk deletion requires a fresh path observation and the held identity pin; replacement files, symlinks, and recreated paths are preserved. A subsequent absent-path observation can release the pin without inventing successful native release.

Actual syscall tests preserve the original distinction: fstat retries EINTR; lstat, unlink, and close do not gain that retry. A corrupted retirement state is persistently fenced. A forked process cannot acquire release rights over its parent's holder.

The qualifier compares nine normal/refusal/path-lifecycle pairs against the original reference owner and ten actual EIO/EINTR syscall pairs. Eight additional private frame, generation, fork, and corruption guards are retained. Earlier failed fixtures and the discovered fstat retry difference remain in the external qualification evidence.

## Ownership and integration limits

The six-word entries are private native preparation operations. An enclosing owner must serialize each holder, register it before relinquishing a prepared reference, maintain the actual library and descriptor lifetimes, and retain failed cleanup tasks. It must also bind fresh structural admission, the selected profile, all proof inputs and receipts, the real native build result, and the image closure.

The private generation field is a machine word. The original public generation and accounting values are Python integers; the final language-neutral public owner must preserve their unbounded observable semantics without exposing a wrapping private slot identifier as the public value.

The native coordinator component already preserves selection and retirement ordering in its own qualification. Its previous external-effects harness is not claimed as the completed native public owner. Background work, cancellation/Future callbacks, public locks, and the final native preparation transport remain explicit integration work.
