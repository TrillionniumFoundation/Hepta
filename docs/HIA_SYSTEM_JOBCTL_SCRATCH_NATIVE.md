# Native engine scratch custody inside privileged Jobctl

These three HIA companions preserve the original supervisor's `ScratchOwner`,
private directory and unreaped process-group observation. They do not introduce
another job registry or dispatch authority. The supervisor retains the original
child until process-group observation succeeds and performs the original reap.
The scratch group component never reaps that child.

The authored sources are `system_jobctl_scratch.hepta`,
`system_jobctl_scratch_directory.hepta` and `system_jobctl_scratch_group.hepta`.
They use the already qualified `system_jobctl_value.hepta` for serde Value input.
Python files regenerate HIA or run independent qualifications; they are not
invoked by the native supervisor's runtime path.

## Entry and continuations

Every owner uses the existing six-buffer ABI: startup bytes, a 128-byte syscall
plan and exactly 128 MiB of owned workspace. Action 1 requests a mechanical Linux
syscall; action 8 resumes the common top-level dispatcher. The dispatcher maps
3000–3099 to scratch action 21, 3100–3499 to directory action 22, and 3500–3999 to
group action 23. Action 14 invokes the existing Value companion using its exact
six-buffer plan. There are no policy decisions in the syscall adapter.

The supervisor enters action 21 at phase 3000. Private directory and group
continuations are internal, not caller-selected cleanup capabilities.

| Workspace field | Meaning |
| --- | --- |
| 62000 | Operation: 0 prepare, 1 observe original exit, 2 stop original group, 3 finish, 4 retain supervision error |
| 62008 | Supervisor continuation phase |
| 62024 | Interactive flag |
| 62032 | Original argument count |
| 62040 / 62048 | Sole argument offset and length, relevant when count is one |
| 62056 | Original stdin presence |
| 62064 / 62072 | Original decoded stdin offset and length |
| 62080 / 62088 | Original `STATE_DIRECTORY` offset and length |
| 62096 / 62104 | Original job ID offset and length |
| 62112 / 62120 | Original launch nonce offset and length |
| 62128 | Original child PID |
| 62136 | Confirmed original-group stopped flag |
| 62144 | Method error flag |
| 62152 | `original_exited` result |
| 62160 / 62168 | Binding or cleanup JSON offset and length |
| 62176 / 62184 | Error UTF-8 offset and length; operation 4 takes its original error here |
| 62192 | Selected static-engine scratch flag |

Preparation first checks noninteractive mode, exactly one `rea-static-worker`
argument, a valid complete serde Value, the original request schema and provider
`jadx` or `ghidra`. Other requests do not create scratch. Duplicate decoded Value
keys use their last value, but overwritten values must still parse. The inherited
Value profile covers the complete bounded stdin inventory and original serde
container depth; it does not replace typed Request validation.

On selected success, operation 0 returns the canonical binding JSON without a
line feed, while the atomically published file has the original final line feed.
The supervisor copies this JSON into `HEPTA_RUNTIME_ENGINE_SCRATCH`, then reparses
its preserved raw Request before assembling ordinary process arguments. Scratch
creation and binding publication precede the original cwd checks.

Operations 1 and 2 return their observation fields; the binding JSON remains
owned until finish. Operation 3 consumes the original directory custody and
returns a cleanup Value, including a retained or incomplete Value on cleanup
failure. Operation 4 first snapshots the input error, creates the original
negative receipt, and atomically writes `engine-scratch.retained.json`; it does
not publish a successful terminal outcome.

## Workspace and descriptor custody

Fields 62000–63999 belong to scratch. Persistent state/path bytes occupy
114–116 MiB, and binding JSON occupies 116–118 MiB. Original caller-provided job
ID and nonce spans must remain stable until finish. Raw Request bytes at 1–2 MiB
and supervisor Spec metadata at 102–108 MiB are preserved.

Temporary work at 4–68 MiB and 68–100 MiB is reused only during a scratch method.
The supervisor calls these methods after any spawn vectors are consumed and
when no capture buffer has an outstanding read or write. Receipt output is at
80–88 MiB, and method errors are at 88–90 MiB; the caller consumes or copies them
before its next use of temporary workspace. Operation 4 snapshots its input
error before reusing these areas.

The original owned directory and parent FDs are retained in fields 62200 and
62208, always close-on-exec. A second directory object used by finish has separate
FDs. Temporary walks, iterator FDs, child-directory FDs, claims and atomic files
have explicit ownership and cleanup continuations. A method failure closes only
its acquired descriptors. Finish and retained-error completion close both
original custody FDs. Atomic exclusive-open failure never unlinks another
writer's temporary file.

## Preserved directory and group rules

Directory preparation exclusively creates `engine-scratch` with mode 0700.
Every path component is opened without following symlinks; original legal slash
and dot normalization is retained. Verification compares the held parent,
re-resolved parent, named leaf, original inode metadata, re-resolved path and
held directory, including effective UID and exact private mode. Finish reopens
the original device/inode before checking the worker claim.

Claim admission retains the original regular-file, single-link, effective UID,
0600 and 16384-byte limits. It checks complete serde Value equality for the owner
binding, the original PID and accepted engine name. Missing, invalid or unreadable
claims set `worker_adopted` false; they do not grant or withhold cleanup authority
in place of the original directory and process-group checks.

Cleanup retains the original three-second deadline, maximum 100000 entries and
maximum depth 32. An iterative descriptor stack implements the recursive source
semantics. Symlinks are removed as leaves. Every child directory must share the
held parent's mount identity; a substituted mount grants no cleanup authority.
Each child inode is checked again after its recursive clear. The root directory
is verified again before removal, and parent fsync is the final durability
barrier. A failure can leave a partially cleared directory, and its receipt
retains the original stage, flags and error.

Original exit observation uses `waitid(P_PID, ..., WEXITED | WNOHANG | WNOWAIT)`.
It checks the reported PID and original exit-code classes without releasing
custody. Group stop validates `/proc/self/mountinfo`, rejects restricted hidepid
visibility, preserves the original two-second deadline, scans the complete
bounded `/proc` inventory when the leader has exited, and ignores zombie/dead
members exactly as the source does. An observation error does not authorize a
later signal. Group kill preserves ESRCH handling and the original 10 ms wait.

Rust File opens and synchronization retry interrupted syscalls. Raw directory
open, waitid, kill and rename retain their original error behavior. Directory
iterator errors remain errors, with the original count/deadline checks preceding
propagation. Atomic write-zero is distinct from an OS error. These distinctions
are independently exercised, not implemented by changing the oracle.

## Source and qualification evidence

The unchanged published source identities are:

| Source | SHA256 |
| --- | --- |
| `src/bin/jobctl.rs` | `575e7b74f26f7ddada5f19ffafd6b9597307b565ac69de3c8091346fa516dc81` |
| `src/mcp/rea_engine_job_owner.rs` | `2025571154747e012e40fe8493bf73d50f4bc1d13b58a7c877b942c9237f9d78` |
| `src/mcp/rea_engine_directory.rs` | `e338f3b27e52cd0c891114d9a41e96f2baf5d7508e93b50c5beec35311134fa9` |

The v3 component checkpoint uses the designated native compiler SHA
`494833999e25ac74ea6ad1de41235c01bfa036951f212604026cb8be686c78af`.
Its Rust oracles compile the original code with the original 1.95 toolchain,
locked dependency versions and serde Value float-roundtrip profile where used.
The qualifications exercise real filesystem effects and real child processes.

| Gate | Cases and evidence |
| --- | --- |
| Group | 42 original/native pairs, including actual running/exited leaders, residual descendants, repeatable WNOWAIT observation, lost custody and exact parsing errors |
| Owner | 35 pairs comparing binding, cleanup/retained JSON and complete persistent trees |
| Private namespace extension | 38 cases, including the ordinary inventory plus actual mounted descendants, read-only cleanup and differing claim UID |
| Failure continuations | 28 one-shot EIO, EINTR and WriteZero pairs against the unchanged Rust code through a separate QA interposer and the HIA mechanical syscall boundary |

The namespace extension requires an explicit private mount namespace and never
changes live host mounts. The failure interposer is an external oracle fixture,
not part of any native runtime image. Image/source hashes, earlier failing
versions and detailed receipts remain in the integration qualification inventory.
The extended inventory overlaps the ordinary cases; the counts are not a sum of
distinct behavior claims.

The reusable qualifier tools accept explicit runtime-source, component, output
and oracle-compiler paths. They verify frozen original source and component
identities. These component gates do not alone qualify the entire privileged
supervisor, actual systemd/DynamicUser launch or the final packaged runtime. The
final Jobctl owner must compose these exact HIA components and exercise its whole
spawn, capture, retained-error and terminal-publication paths.
