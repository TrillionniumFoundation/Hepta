# Native Runtime Info lock and ownership contract

This checkpoint covers the public enclosing-owner operation 8 for GenerationLease.info. It preserves the previous public request and result layout. It does not qualify a new public Lease acquisition method, immediate cache pruning after every Runtime mutation, or the complete Runtime/BG release.

## Actual ownership and locking

The owner holds its native mutex at context offset 64 while it serializes Info scratch, detached carrier metadata, and stream descriptors. It obtains a real temporary Lease reference through private Value operation 91. A delivered reference is recorded before inspecting independent cleanup status. A known delivered result with no mapping pending remains usable when its status 11 reports only the shared resource queue.

Info cache lookup, conversion, cache reconciliation, and Lease attachment use the private HIABVQ14 profile, operations 65, 60, 66, and 64. These operations execute the original graph changes and collection work but defer the automatic resource and invocation cleanup for that one call. The previous Q05 operations retain their original automatic cleanup behavior.

The native owner checks the Q14 trailer at reply offsets 128 through 160: HIABVD01, snapshot known, mapping pending, shared queue pending, and deferred marker. It proceeds only with a known snapshot, no mapping pending, a Boolean queue field, and the deferred marker. A queued resource is permitted. A successfully delivered Info capability is saved before checking this trailer, so a later error cannot hide it.

Private operation 78 consumes the temporary Lease reference. The owner uses the explicit known/consumed and deferred mapping/queue fields. A known consumed reference with only a shared queue pending is not reported as a lost local reference. An unconfirmed reference remains in the existing explicit cleanup-capability result.

After all serialized Info scratch and descriptors have been handled, the owner increments its real active guard at offset 72 and releases mutex 64 through the fixed native bridge. It then invokes Value operation 56. Runtime finalizers may therefore retire their actual Runtime ledger under the root mutex. The enclosing call reacquires that mutex, decrements its guard, and returns. No host code writes a lock, identity, reference, mask, or cleanup receipt.

## Public request boundary

HIABVQ12, HIABVQ13, and HIABVQ14 are rejected at the mechanical owner entry before the phase word or any other output/context byte is written. The HIA owner independently rejects these profiles as well. Existing public operations and earlier private-domain refusals remain in place.

The mechanical bridge was rebuilt from the existing bound-owner assembly and compared byte for byte with the frozen 1,200-byte bridge before deriving the new 1,280-byte bridge. This does not introduce a caller-selected entry or context.

The new native packer uses HIARIFP1 with the same 47 roles and size limits. Runtime/BG fusion must retain the BG owner policy and finalizer bindings, combine the Info policy changes, and use the matching mechanical prefix and relocation metadata. Merely replacing a BG-enabled owner policy with the standalone mask-190 policy would be incorrect.

## Qualification

The same new owner shared object and the formal e2e3fc40 Value image passed:

- All seven original Info cases, including eight-thread first access, actual allocator refusal, closed-Lease access, and strong generation/ABI identity after two sets of 128 live allocations.
- Three actual queued-Runtime cases: uncached Info, cached Info, and a wrong-kind request. Runtime inputs came from the real public constructor. A second Runtime's last Value reference was deferred, then its actual directory, native ledger guard, and queue retired during the public Info call.
- The original post-publication allocation failure gate: ten actual kernel notifications; Info60 published a capability before cache import encountered real ENOMEM. The capability was returned and explicitly consumed, and a subsequent read recovered the same object.
- Thirteen public private-domain refusals with the entire output and context unchanged.
- Twenty-seven original root-packer boundary and captured-hole controls.

The Lease inputs for the queued-Runtime cases were produced by an actual carrier acquisition and a fixed native Value capture. Those fixture steps are not evidence for a public Lease acquisition API.

The former V9 path-limit checkpoint retains its 71 cases against its original Value115 product. Its results are not relabeled as tests of this new Q14 product. Construction receipts separate native HIA/assembly sources from development authors and qualification code.

## Remaining release work

Immediate generation-cache pruning at all successful publication, cleanup, and close boundaries remains unqualified. Complete public Runtime methods, the final unified BG/LLVM Runtime image, and the new native production recipe/source-resource authority graph remain separate required work.
