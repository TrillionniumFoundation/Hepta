# Native multiversion preparation process capture

This component implements the private process boundary used by HIA preparation owners. The HIA policy owns executable admission, input custody, pipes, deadlines, cancellation, output sealing, and direct-child cleanup. Its 266-byte mechanical adapter translates the declared syscall arguments, executes a raw syscall, reads the caller-owned cancellation word, or re-enters the policy. There is no Python, shell, C policy, or Rust runtime in the product path.

The qualification here is a component result. It does not establish a completed multiversion public API, a completed scalar proof facade, or whole-native runtime closure. A complete captured process result is not evidence that the child succeeded or that a proof was proved.

## Native source closure and construction

The policy is `examples/hia_bootstrap/multiversion_prepare_process.hepta`. The packer is `examples/hia_bootstrap/multiversion_prepare_process_packer.hepta`; its readable mechanical source is `tools/hia_multiversion_prepare_process_bridge.S`. The existing `elf_shared_linker.hepta` turns the packer's closed seven-section ET_REL into the shared image.

The packer takes `HIAMVXP1`, a little-endian u64 role count of one, a u64 policy-flat extent, then that actual flat. The flat must contain 1 through 4 MiB of bytes; no trailing bytes are accepted. The result exports only `hia_mv_prepare_process`. It requires no undefined imports. Native source compilation, this HIA packer, and the HIA shared linker perform construction. The assembly and C compiler are used only by development qualification to compare the mechanical byte provenance and to build an external controlled child fixture.

## Callable boundary

The SysV function is `u32 hia_mv_prepare_process(s_ptr, s_len, o_ptr, o_len, w_ptr, w_len)`, with six machine words. The caller supplies disjoint, private memory: request bytes, at least 128 output bytes, and at least 20 MiB of workspace. Calls with separate workspaces are independent. The mechanical entry initializes the continuation phase and records the actual workspace address.

The cancellation capability is an aligned pointer to a live, caller-owned u64. Zero means that no cancellation capability was supplied. The value 1 requests cancellation; values 0 and 2 retain the existing native Future token meanings of open and committed. Its storage must remain alive through the call. This private capability is not a public request pointer.

### Request

The request is exactly a 128-byte header followed by input bytes and, for role 3 only, the output path bytes. All integers are little-endian u64.

| Offset | Field |
|---:|---|
| 0 | Eight bytes `HIAMVPS1` |
| 8 | Fixed role, 1 through 4 |
| 16 | Caller-owned, already captured executable FD, between 3 and INT_MAX |
| 24 | Nonzero absolute CLOCK_MONOTONIC deadline in nanoseconds |
| 32 | Input byte count |
| 40 | Standard-output cap, 0 through 64 MiB |
| 48 | Standard-error cap, 0 through 64 MiB |
| 56 | Output-path byte count, nonzero only for role 3 |
| 64 | Cancellation capability pointer or zero |
| 72 through 127 | Seven zero words |

| Role | Exact argv | Input cap |
|---:|---|---:|
| 1 | `hia-admit-agent-json` | 8 MiB |
| 2 | `hia-native-scalar-proof` | 16 MiB + 192 bytes |
| 3 | `hia-build-shared`, followed by the supplied absolute output path | 8 MiB |
| 4 | `hia-verify-core-json` | 8 MiB |

Roles 1 and 4 use the same caller-captured normalizer image. Role 4 preserves the original verification diagnostic path after a failed normalization. The path in role 3 is 1 through 4095 bytes, begins with `/`, and has no NUL. The environment is exactly `PATH=`. There is no caller-selected argv, executable pathname, shell, or fallback interpreter.

The caller first binds the executable's actual bytes and SHA to its admitted closure. This transport duplicates that immutable capability, verifies a regular anonymous file with nlink zero, a size from 1 byte through 8 MiB, and all four memfd seals (15). A caller-supplied boolean is not such a binding. The original executable FD remains caller-owned.

### Response

On a well-formed call, the return value equals the outcome word in this 128-byte response:

| Offset | Field |
|---:|---|
| 0 | Eight bytes `HIAMVPO1` |
| 8 | Outcome: 0 complete, 1 deadline, 2 cancelled, 3 capability/I/O failure, 4 stream cap, 5 exec failure |
| 16 | Actual direct child PID, or zero if none is retained |
| 24 | Linux raw wait status |
| 32 | Exec-error pipe's raw result, represented as u64 |
| 40 | First transport-error raw result |
| 48 | Owned sealed stdout FD, or UINT64_MAX |
| 56 | Owned sealed stderr FD, or UINT64_MAX |
| 64 | Captured stdout extent |
| 72 | Captured stderr extent |
| 80 | Start monotonic timestamp; zero if the initial clock failed |
| 88 | Last monotonic timestamp |
| 96 | Direct child reaped, 0 or 1 |
| 104 | True EOF bits: stdout 1, stderr 2, exec-error pipe 4 |
| 112 | Confirmed returned-stream seals, 15 on a complete result |
| 120 | Zero |

Outcome zero transfers exactly two anonymous mode-0600 sealed FDs to the caller, which must close them. The caller must separately require the appropriate exit status and validate the complete typed child response. A nonzero child exit or child signal can have outcome zero because the streams and status were captured completely. Other outcomes return no owned output FDs. Partial streams are never a successful typed result.

Malformed private frames or insufficient output/workspace return `0xfffffffd` without changing output bytes. The workspace is private scratch and must not alias the request or output.

## Process and lifetime semantics

Input is copied into owned workspace, written completely to a private memfd, rewound, and sealed before execution. All owned FDs are normalized above the standard streams. The child establishes its own process group, installs a parent-death SIGKILL and checks its parent identity, installs standard streams, marks unrelated inherited FDs close-on-exec, and uses `execveat(AT_EMPTY_PATH)` on the captured image. An error pipe preserves the actual exec failure.

The parent uses nonblocking pipes and bounded chunks to capture both streams. It handles actual short writes and EINTR without inventing bytes. `waitid(WNOWAIT)` observes the direct child without relinquishing its PID custody while a descendant can still keep a stream open; completion requires all true EOFs followed by reaping. Deadline and cancellation failures kill the owned process group and direct leader and reap the direct child. This is a direct-child and same-process-group boundary; it does not claim subreaper ownership of arbitrary escaped or setsid descendants. The caller must not have another owner concurrently reap this child.

One absolute deadline is checked throughout capture, retry, polling, and final sealing. Separate normalization, diagnostic, proof, and build invocations belonging to one preparation receive that preparation's unchanged absolute deadline. The proof request's configured budget is independently enforced by its HIA owner. Cleanup consumes each owned FD once and preserves the first error. It does not retry a possibly consumed close.

## Qualification

The exact qualified product, native source/flat pins, report hashes, and case names are in `HIA_MULTIVERSION_PREPARE_PROCESS_NATIVE_QUALIFICATION.json`.

The four-role image passed 57 actual-process cases, 52 private boundary controls, 36 fault/short-write controls, and 16 native packaging controls. The actual cases include all four fixed argv values, the exact environment, both streams through 64 MiB, real seven-byte pipe writes, nonzero exit and signals, stream-cap overflow, cancellation, absolute deadlines, closed streams with a live child, process-group descendants, real normalizer/diagnostic/proof/builder images, and eight concurrent workspaces.

Fault qualification uses external ptrace on the unchanged adapter's exact syscall instruction and the actual HIA continuation phase. EIO, EINTR, zero writes, pipe failure, and sealing failure are covered. For short writes, the real kernel syscall executes with a reduced count of 1, 7, 97, or 4096; its actual bytes and returned count are preserved. FD and direct-child ownership are checked after every call. The v1 wait4-failure defect and the earlier invalid strace-ordinal QA attempt remain in historical external evidence; the qualified source includes the cleanup correction.

The external fixture is generated by `tools.qualify_hia_multiversion_prepare_process --directory D --source S --prepare-fixture`. The normal test accepts explicit `--normalizer`, `--proof`, and `--builder` paths for custody-pinned products. The fault and guard modules consume the same built component and controlled child. These Python and C qualification inputs are development evidence, not final runtime dependencies.
