# Native Linux compiler capture

This component runs the Linux compiler-capture process policy in five compiled
HIA roles. The enclosing public Value adapter and the complete LLVM build path
remain separate integration work; the qualification JSON marks them false.

## Construction and actual execution

The retained 813129-byte HIA compiler double-compiles the admission, child,
stream, ownership and storage roles, the native packer and the runtime linker.
The HIA packer creates the relocatable object; the HIA runtime linker creates
the shared library. Its only dynamic platform import is dlsym, used before
fork to capture libc's current environ. The fixed mechanical assembly prefix
matches its independently assembled bytes. Python is a development author,
driver and comparison oracle, and is not a product callback.

The current library is 328464 bytes with SHA256
e15ee132d071f984411b5eadb57dac0cc9c0d7c4f26dda44a0ebc9da0b02a996.
A separate reproducible construction produced the same object and library.

The unchanged assertions in 13 original real-process tests pass, including
actual Clang preprocessing and four descendant-cleanup paths. Ten additional
groups bring the campaign to 112 native calls. Seventeen custody/control
groups exercise real kernel errors, fallback descriptor closure, eight-thread
process creation, inherited descriptors above 64, initially closed descriptors
0/1/2, and rejected copied or forked ownership contexts. The original compiler
and packer size budgets remain unchanged.

## Private request ABI

The exported hia_clang_capture uses the existing six-word buffer ABI. Source,
output and workspace must be disjoint and nonoverflowing; workspace is aligned
to eight bytes, private to the owning process and exclusively borrowed for
each operation. It must have at least 4096 + 8*(argc+envc+2) bytes; output needs
256 bytes. A new context is zero initialized. The workspace remains owned
until explicit retirement acknowledges completion.

HIACAP01 has a 128-byte header. All words are little-endian unsigned 64-bit:

| Offset | Meaning |
| --- | --- |
| 0 | HIACAP01 |
| 8 | 0: run; 1: retire |
| 16, 24 | Argument and explicit environment counts |
| 32 | Explicit environment present, 0 or 1 |
| 40 | Relative wall-time budget in nanoseconds |
| 48, 56, 64 | Stdout, stderr and stdin byte limits |
| 72, 80 | Stdin and cwd byte lengths |
| 88 | Reserved zero |
| 96 | Cwd present, 0 or 1 |
| 104..120 | Reserved zero |

Run appends argv and environment entries as length, bytes, NUL; optional cwd
bytes and NUL follow, then the exact stdin bytes. Argv is nonempty with no
empty arguments or NUL. An explicit environment retains the original 256-key
and 131072-byte UTF-8 bounds, without an extra identifier regex. There is no
64-argument restriction and no five-second timeout restriction. Stdin is
strict UTF-8. The public typed adapter must retain its original Python-like
type admission and exception order before constructing this private wire.

Retirement is exactly 128 bytes: op 1 and every word after offset 8 zero.
The fixed entry independently checks process identity, the actual workspace
address and its extent before writing to an existing ownership context.

## Reply and retirement

HIACAR01 is a 256-byte header. Stream pointers name this component's actual
owned anonymous mappings; they are for the enclosing trusted native consumer,
and are not public pointer-bearing Value results.

| Offset | Meaning |
| --- | --- |
| 0 | HIACAR01 |
| 8, 16 | Primary error and errno |
| 24, 32 | Return status known and actual signed child return code |
| 40, 48 | Cleanup error and errno |
| 56, 64 | File snapshot stdout and stderr totals |
| 72, 80; 88, 96 | Raw stdout and stderr pointer/length pairs |
| 104, 112; 120, 128 | Normalized UTF-8 stdout/stderr pointer/length pairs |
| 136 | Cleanup remains pending |
| 144, 152 | Child PID and consumed group-termination permission |
| 160, 168, 176, 184 | Corresponding mapping capacities |
| 192 | Actual child setup/exec failure stage |
| 200, 208 | Failure-evidence error and errno |
| 216, 224 | Retirement error and errno |
| 232 | Encoding-failure stream index |
| 240 | Uncertain legacy-close ownership mask |
| 248 | Reserved zero |

Errors are 1 argv, 2 budgets, 3 environment, 4 stdin encoding, 5 stdin size,
6 process ownership, 7 launch, 8 output limit, 9 timeout, 10 output encoding,
11 cleanup, 12 OS error, 13 allocation, 14 context, 15 output extent,
16 retained ownership and 17 integer/read-size overflow. Public exception
objects and exact messages are not represented by these private codes.

The process policy observes its own unreaped child with waitid(WNOWAIT).
It consumes permission to signal the process group before the one attempt,
then requires an actual leader reap and retains the original exit status.
It never infers that every escaped descendant stopped. Final reads are
independently bounded, including after a file-size race. Failure evidence is
a bounded raw prefix with separate observed totals. Text decoding is strict
UTF-8 and converts CRLF and CR to LF without changing retained raw bytes.

Owned parent descriptors use close_range on one retained descriptor. A real
failure preserves the descriptor and permits explicit retirement to retry.
If the kernel reports ENOSYS, ordinary close retains the original valid-call
domain; an ambiguous failure is quarantined and is never blindly retried
against a reusable descriptor number. Failed munmap retains its exact mapping.
A second thread in the same process can complete known-safe retry, as the
actual EACCES controls demonstrate. Cleanup never reuses a consumed process
group identity. Unknown process ownership remains pending.

Successful retirement releases all retained mappings and descriptors, then
clears the context. Failed or unknown retirement retains its ownership state.
The enclosing caller must keep that workspace and fixed image alive while
pending; a failed operation is not permission to free them.

## Reproduction

Development commands, with a new output directory for each invocation:

- python3 -m tools.qualify_hia_clang_capture_build --compiler COMPILER --output BUILD
- python3 -m tools.qualify_hia_clang_capture --library BUILD/clang-capture.so --output SEMANTICS
- python3 -m tools.qualify_hia_clang_capture_faults --library BUILD/clang-capture.so --output CUSTODY

The source and binary pins, original fixture identity, concrete evidence paths
and outstanding integration boundaries are in
HIA_NATIVE_CLANG_CAPTURE_QUALIFICATION.json.
