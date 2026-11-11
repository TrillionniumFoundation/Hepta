# Namespace filesystem reconstruction: private ABI revision 3

Status: NEW AUTHORING, no generated Core, VM execution, B3 compilation, native execution, root admission, migration or ordinary AgentStore completion is claimed by this source checkpoint.

The former complete FS r2 archive (838,288 B, SHA256 27c68a4bf1bbe5674927a3cac13178e07c3afff33b53666279903192c660d1e1) is currently inaccessible. This is not evidence that it was lost. Its prior execution counts are not inherited. This reconstruction reuses the exact saved identity/locking constraints and restored ObjectBuilder/VALUES authoring helpers, with a separately named wire format. It does not claim old FS frame equivalence.

## Owned behavior and trust boundary

HIA owns logical descriptor tokens, dynamic descriptor-slot allocation, input-shape validation, syscall selection, continuation identity, exact result extent, descriptor retirement, syscall sequencing, growth decisions and permanent refusal.

The fixed executor to be implemented performs only Linux x86-64 primitives selected by an actual HIA event. It must supply their actual raw return value, and exact output bytes; preserve the same immutable request lease across GROW; keep input mappings read-only; copy all prior workspace bytes on growth; never replay a syscall because a buffer needs growth; and never interpret namespace permissions, SQL, rows, names or transaction policy.

The framing checks are not authentication for externally supplied ACKs or workspace. Session/call/source IDs are only continuation labels inside a private issuance chain. An untrusted caller cannot mint an issued source lease by copying these integers. This kernel alone does not verify the bytes of an externally substituted request behind a reused lease. Ordinary public entry must use the fixed coordinator/executor's real immutable mappings and owned contexts.

The minimum workspace is 512 bytes. Short-workspace failure writes a permanent bad marker if at least 8 bytes exist; below 8 bytes no persistent marker can be stored. Output shorter than 256 bytes is refused before a syscall. No global namespace row, byte, transaction or descriptor count quota is introduced. The descriptor array grows in 16-slot increments as memory permits; u64 representation and actual allocation failure remain intrinsic constraints.

## Input

Every frame has 32 little-endian u64 words (256 bytes), followed by exactly word12 bytes. All words14..31 must be zero. Magic is the little-endian value of ASCII HIAnamespace revision marker HIAnFR03 spelled exactly as bytes HI A N F R 0 3, without spaces (the generator uses b"HIANFR03").

| Word | Meaning |
|---|---|
| 0 | Magic HIANFR03 |
| 1 | Command |
| 2,3 | Session identity; both zero is invalid |
| 4 | Call; new CALL/CLOSE_ALL is previous call+1 |
| 5 | Issued syscall sequence; zero on a fresh CALL/CLOSE_ALL |
| 6 | Operation |
| 7 | Raw Linux syscall return bits, only on SYSACK |
| 8..11 | CALL arguments a,b,c,d; zero on SYSACK/control replies |
| 12 | Exact payload extent |
| 13 | Immutable source lease label; nonzero for CALL and echoed by its ACK |
| 14..31 | Zero |

Commands: 1 INIT, 2 CALL or the same pre-syscall GROW continuation, 3 SYSACK, 4 CLOSE_ALL, 5 UNKNOWN_OUTCOME, 6 GROW_FAILED.

INIT has exactly 256 bytes; only magic, command and session may be nonzero. It is accepted only in a pristine zero header. A context is never reset by another INIT. Every accepted call consumes a strictly increasing call ID. Every emitted actual syscall consumes a strictly increasing syscall sequence. All ACK identity fields must match the one currently issued syscall. Duplicate/reordered/late replies permanently refuse the context. UNKNOWN_OUTCOME and GROW_FAILED permanently refuse; they cannot silently report success.

## Output

A full event is 32 little-endian u64 words and word16 bytes.

| Word | Meaning |
|---|---|
| 0 | HIANFR03 |
| 1 | 0 COMPLETE, 1 SYSCALL, 2 GROW, or 0xfffffffd BAD |
| 2,3 | Session |
| 4,5,6 | Call, issued syscall sequence, operation |
| 7 | Positive errno (0 on success) |
| 8..11 | SYSCALL raw primitive arguments; COMPLETE result fields described below |
| 12,13 | Additional typed stat fields when applicable |
| 14 | Original source lease label |
| 15 | Workspace phase |
| 16 | Exact payload extent |
| 17,18 | Required workspace/output size for GROW |
| 19 | First permanent-refusal reason |
| 20 | Live descriptor count |
| 21 | Next logical descriptor token |
| 22 | ABI version 3 |
| 23 | CLOSE_ALL continuation marker |
| 24 | stat nlink only; otherwise zero |
| 25..31 | Zero |

There is no accepted application result in a GROW/SYSCALL event. A COMPLETE with positive errno is a known syscall failure, not a protocol failure. Permanent BAD never becomes usable again. Source and output buffers must be distinct from workspace.

## Operations

Descriptor arguments are logical HIA-issued tokens, never caller-supplied raw FDs. For directory arguments only, token zero selects the fixed executor's actual AT_FDCWD context. A real raw descriptor zero is a normal issued descriptor and receives a nonzero logical token. Mode/flag operands preserve their low 32-bit ABI type without adding namespace policy.

| Op | Primitive | CALL arguments and body | Success result |
|---|---|---|---|
| 1 | openat | a=directory token/0,b=flags,c=mode,d=0; one nonempty NUL-free path | word8=new logical token |
| 2 | pread64 | a=fd token,b=count,c=nonnegative offset,d=0; no body | word8=count, exact bytes |
| 3 | pwrite64 | a=fd token,b=nonnegative offset,c=d=0; raw bytes | word8=actual count |
| 4 | fstat, typed | a=fd token; other operands zero | typed stat fields |
| 5 | ftruncate | a=fd token,b=nonnegative length | zero |
| 6 | fsync | a=fd token | zero |
| 7 | renameat | a=old directory token/0,b=new directory token/0,c=first path length,d=0; two adjacent nonempty NUL-free paths | zero |
| 8 | close | a=fd token | zero |
| 9 | unlinkat | a=directory token/0,b=flags; path | zero |
| 10 | mkdirat | a=directory token/0,b=mode; path | zero |
| 11 | flock | a=fd token,b=operation | zero |
| 12 | clock_gettime(CLOCK_MONOTONIC) | all operands zero | word8=seconds,word9=nanoseconds |
| 13 | nanosleep | a=seconds,b=nanoseconds<1e9 | zero or actual errno; no hidden EINTR retry |
| 14 | getrandom | a=count,b=flags | word8=count, exact bytes |
| 15 | fstat, complete | a=fd token | typed stat plus complete144-byte Linux x86-64 struct |
| 16 | geteuid | all operands zero | word8=actual uid, including valid zero |
| 17 | fcntl(F_SETLK) | a=fd token,b=F_RDLCK0/F_WRLCK1/F_UNLCK2,c=start,d=len; SEEK_SET | zero or actual errno |
| 18 | newfstatat | a=directory token/0,b=flags; path | typed stat plus complete144-byte struct |
| 19 | readlinkat | a=directory token/0,b=capacity; path | word8=count, exact bytes without invented NUL |
| 20 | getcwd | a=capacity | word8=kernel count and exact bytes including terminal NUL |
| 21 | fchmod | a=fd token,b=mode | zero |
| 22 | fchmodat | a=directory token/0,b=mode; path | zero |

Other operands and bodies are zero/empty except those stated. Offsets/counts are representable nonnegative signed off_t/ssize_t operands. The kernel decides filesystem semantics and errno. Paths are raw bytes; this layer neither decodes Unicode nor rejects parent symlinks.

Typed stat is word8=dev,9=ino,10=mode u32,11=uid u32,12=gid u32,13=size bits,24=nlink. It is an observation, not root admission. UID zero is not an unissued marker.

All negative Linux raw return values in [-4095,-1] become the corresponding positive errno only after exact zero error payload is checked. Unexpected positive returns, mismatched data extent, duplicate raw FD ownership, impossible clock nanoseconds and inconsistent correlation permanently refuse.

CLOSE retires the logical token before emitting the actual syscall, even if the syscall returns EINTR. It is never retried implicitly and the retired token is never resurrected. CLOSE_ALL issues each live close once in slot order, retaining the first known errno while attempting the remaining closes. Its final operation is zero, marker word23 remains1, and the context is closed permanently. Uncertain syscall outcome poisons the context; process/owner cleanup is an independent executor obligation still to be implemented and tested.

## Workspace and growth

Bytes0..255 hold the private FSM header. Bytes256..511 hold the exact original CALL header while pending. Starting at512, each32-byte descriptor slot is [logical token,actual fd,live flag,zero]. The body staging area follows all allocated slots. Live tokens and raw FDs must be unique; dead slots are all zero. Slots may be reused, logical tokens are never reused.

Header offsets: 0magic,8phase,16/24session,32call,40sysseq,48operation,56first reason,64nexttoken,72livecount,80slotcapacity,88sourcelease,96bodybytes,104/112GROW requirements,120reserved open slot,128CLOSE_ALL cursor,136first close errno,144close-all flag,152retired actual FD,160retired token,168..247zero,248version3.

Phases1idle,2issued syscall,3pre-syscall growth,4permanent bad,5closed. Growth occurs before side effects and before issuing a new syscall sequence. The executor resubmits the same retained immutable request view; the kernel compares its complete header and shape, then stages the body once capacity is sufficient. It does not claim that labels authenticate a foreign substituted body.

## Next mandatory gates

1. Generate new Core, preserve original authoring failures and source pins, check source profile.
2. Full VM and actual retained-B3 image differential, including all22 primitives, FD0/UID0, malformed/short frames, actual result extents, GROW, replay, counter boundaries and permanent refusal. Compare every output and workspace byte, source unchanged, and canaries.
3. Actual fixed executable with real syscalls, exact ownership/cleanup and source mapping permissions, no Python semantic callback in the executable.
4. HIA root permission/order and inode-chain coordinator preserving supplied-root final symlink policy and allowed parent symlinks.
5. Actual WAL shared-memory inode byte120 fencing in both directions against the selected SQLite3.46.1 runtime; account for per-process inode locks, alias descriptor closure and stale snapshots.
6. Full immutable view/commit/physical log/multiwriter coordinator and complete migration/drain, ordinary callers and existing crash/replay tests.

A new flock or unrelated lock filename is not a legacy-writer fence. sqlite timeout10000 is the retained busy sleep schedule rather than an elapsed-time deadline. BEGIN/body/ROLLBACK/COMMIT error replacement follows the exact preserved source constraints. Neither new file handles nor component PASS permits SQLite or old-runtime removal.
