# Native NDU rank context and retained results

## Qualified scope

This component owns the resources captured by a rank object, its strong owner references, active rank calls and returned immutable byte payloads. Its fixed six-word entry executes HIA policy, source-bound HIA SHA and payload roles, and a closed mechanical syscall/allocator adapter. It does not invoke a host-language dispatcher, libc or a caller-supplied function pointer.

The qualified product is 351,894 bytes, SHA-256 **d20b82959ebcb61d06cda1b00d29ffd40379cd4b3d8c3b0fa7ed2fad5de8da20**. The JSON companion records exact source, captured resources, build products and actual qualification receipts.

Integration with rank engine **8338a80a992218ca6faefea66235fd18fcfb5c5d59f2bcc1d10a184f28e294ff** passed all 17 existing complete rank cases, including fresh proofs, admitted selections, exact original output comparisons, 9 MiB and 72 MiB arguments, and 32 candidate proposals. Each case calls the engine once, without Python effect or role dispatch. Retained results remain byte-identical after the engine arena is unmapped.

This checkpoint does not claim complete public rank closure, background integration, final source aggregation or activation. Engine 8338 copies control word 104 into the evaluator owner's cancellation word at role entry; it has no qualified live cancellation-pointer connection during that role. Asynchronous cancellation wiring and actual process-tree gates are a subsequent checkpoint. Context abort/finish ownership is qualified; callers must finish process cleanup before aborting an active ticket.

## Construction from HIA

Compile ndu_rank_context.hepta for policy, the existing three SHA HIA sources and alias packer for the qualified 116,455-byte composite SHA, and the unchanged multiversion_background_payload.hepta with ndu_rank_context_payload_packer.hepta for the closed 85,040-byte payload. Compile ndu_rank_context_packer.hepta for the final native packer.

The packer consumes **HIANKP01**, a 40-byte header with the three actual flat lengths at offsets 8, 16 and 24, a zero word at 32, then policy, SHA and closed-payload bytes. Each flat has length 16 through 4 MiB. The packer emits its fixed 772-byte bridge, those flats and the fixed 175-byte closed allocator, patching only five relative call holes. Its output is the complete entry-zero flat. Bad frames return 0xffffffff; short output returns 0xfffffffe without output writes.

The readable mechanical sources are retained. HIA packers emit their literal bytes; no runtime assembler, linker or libc is needed. The allocator dependency is separately qualified in HIA_NATIVE_RANK_CLOSED_ALLOCATION. The companion binds the actual compiler and all source/flat pins.

## Six-word entry and persistent state

The entry is:

    context(input_pointer, input_bytes, output_pointer, output_bytes,
            persistent_context_pointer, persistent_context_bytes) -> u32

Persistent context is at least **131,072 bytes**, 8-byte aligned and private to one constructed object. Three views must be non-null, non-wrapping and pairwise disjoint. Output is at least 512 bytes. Mechanical view errors return 0xfffffffd before stores. Protocol errors return the same code; the first 128 output bytes and persistent context remain unchanged, while reserved per-call output continuation bytes may have been initialized.

Initialization is exclusive and requires a zero first context word. Later object operations are serialized by the native atomic/futex mutex. The actual PID is checked before lock acquisition; forked children cannot wait on an inherited lock or use inherited capabilities. Integer extent checks do not establish that arbitrary caller mappings are live.

Output bytes 128–511 are private continuation state. The mechanical bridge supplies the actual view bases; no public input frame supplies them.

## HIANKC01 operations

Ordinary input is exactly 128 bytes. Magic is at 0 and operation at 8.

| Operation | Meaning | Input fields |
| --- | --- | --- |
| 0 | Initialize | FDs at 48, 56, 64, 72; integer-digit policy at 80 |
| 1 | Retain owner | Owner capability at 16, 24, 32 |
| 2 | Drop owner | Owner capability at 16, 24, 32 |
| 3 | Enter rank call | Owner capability at 16, 24, 32; output exactly 65,536 bytes |
| 4 | Finish | Input is the exact original 65,536-byte control, with magic/operation changed |
| 5 | Abort active ticket | Same exact-control requirement; only after engine execution ended |
| 6 | Destroy | Capability and remaining fields zero |

Reserved words are zero. Init accepts FD integers through INT_MAX and digit limits 0 or 640 through INT_MAX, retaining the established captured integer policy.

Init duplicates the normalizer, proof, source-root directory and threshold FDs. Normalizer, proof and threshold must be regular files with exact sizes, exactly all four required seals and matching actual streamed SHA-256. The source root must be a directory capability; the evaluator owner re-reads and checks the actual source files on every rank call. A receipt cannot substitute another root. The threshold is mapped read-only and private. Constructor failure closes duplicated FDs and unmaps its mapping. Failed contexts become closed; retry uses a new context.

Generic reply is **HIANKS01**/128. Status at 8: 0 success, 1 unknown/stale capability, 3 range, 4 allocation, 5 lifetime/process, 6 syscall, 7 resource identity, 9 internal invariant. Init and retain return a new independent capability at 16/24/32.

No fixed counter caps references. Owner, active and result references use three separate source-bound registries. Copying a tuple does not retain it, and no live tuple accesses another registry.

## Entry metadata and clock

Enter reads the actual monotonic clock before identity checks or mutex waiting. A valid owner produces a distinct immutable active ticket bound to the actual control address, its 65,536-byte extent, entry time and PID.

Successful enter clears control and supplies:

| Offset | Value |
| --- | --- |
| 48, 56, 64 | Held normalizer, proof and source-root FDs |
| 72, 80 | Read-only threshold pointer and full byte count |
| 88 | Captured integer-digit policy |
| 96 | Zero; no payload registry is exposed |
| 104 | Zero initial interrupt word |
| 3504, 3512, 3520 | Active ticket capability |
| 3528 | Actual entry timestamp |
| 4096 | Same timestamp for rank START |

Engine phase/feedback at 0/8 must be initialized without resetting START. Actual engine integration checks START is unchanged. Active references prevent destruction even after all ordinary owner references have been dropped.

## Finish and independent results

After engine return, control supplies arena pointer/extent at 40/16 and final status/kind/body-offset/body-length at 4000/4008/4016/4024.

Finish validates the active ticket and exact original control binding. It checks the full body extent without adding an aggregate cap. Bounded process_vm_readv operations copy actual bytes and safely reject an unmapped or partially unmapped source. A new independently retained payload owns the copied body. Temporary storage is freed and the active reference consumed exactly once. Elapsed time includes actual copying and active settlement.

**HIANKR01**/128:

| Offset | Value |
| --- | --- |
| 8 | 0 JSON, 1 ordinary exception, 2 BaseException, 3 MemoryError, 4 internal |
| 16 | 1 rank JSON or 2 exception JSON |
| 24, 32 | Immutable pointer and full byte count |
| 40, 48, 56 | Owned result capability |
| 64 | Full elapsed nanoseconds |

The pointer is borrowed under the live result capability and must not be written or freed by the caller. It survives engine-arena unmapping.

Allocation failure returns status 3/kind 2, zero pointer/length/capability, and consumes the active ticket once. Invalid result metadata or actual copy failure consumes only the verified ticket. A foreign, stale or address-mismatched ticket cannot consume a legitimate ticket.

The caller unconditionally unmaps the original engine arena after finish, including finish failure. It must not rerun rank to retrieve results or retry finish after consuming the ticket.

## Result operations and destruction

**HIANRO01** is exactly 128 bytes. Operation 1 copies; operation 2 drops. Capability is at 16/24/32 and copy offset/count at 40/48. Drop requires both zero. All remaining words are zero.

Reply **HIANRR01** has status at 8, full payload length at 16, copied length at 24 and copied bytes at output offset 512. Invalid range or short output writes no copied body. Copy/drop uses the same mutex and never executes rank again.

Destroy requires all three registries empty, then closes four FDs and unmaps the threshold. Active calls and result references block destruction independently of owner references. BG must retain an owner from construction through worker join.

## Actual qualification

Companion records report hashes and exact QA drivers. These sets overlap and must not be summed into an invented independent-case count.

- Real lifecycle smoke: original FDs closed, active/result destroy refusal, arena mutation/unmap and full result equality.
- 17 original complete rank engine cases through this context.
- 45 lifecycle groups: 16 native-lock threads, 640 complete result cycles, 201 strong owner refs, eight active tickets, actual fork refusal, all status kinds, zero through 64 MiB + 1 results, final FD/map closure.
- 40 constructor failures/capability cases: actual wrong type/size/seals/digest, closed descriptors and O_PATH directory capture.
- 150 private frame/view/alias/overflow/reserved/packer/NOSPACE cases.
- 11 kernel ENOMEM injections at actual native allocation syscalls. New allocations and frees match exactly. Failed finish frees both prior active-ticket allocations; an existing owner remains usable.
- Actual read-only threshold enforcement, partial source copying followed by unmapped-page failure, and inclusion of an actual futex wait in entry elapsed time.

No original compiler limit, NDU process/output limit, rank deadline or cold budget was increased.
