# Native system Jobctl

## Product and privilege boundary

`hepta-runtime-jobctl` is a static Linux x86-64 ELF whose control, parsing,
process supervision, capture, terminal publication, and scratch directory
policies are HIA programs. The x86 adapter transports argv/environment, performs
the syscalls selected by those programs, and dispatches their next actions. It
does not interpret requests or implement job policy.

The administrator-owned entry is
`/usr/local/libexec/hepta-runtime-jobctl`. Its normal root entry consumes the
original JSON request protocol and implements the five original operations:
start, pty, status, read, and cancel. The unprivileged
`supervise JOB_ID` and `supervise-pty JOB_ID` entries consume the systemd
credential and state directory supplied by the root owner. Root policy is read
from the original fixed policy path. Requests cannot supply executable images,
privileged helper paths, or a replacement supervisor. Workloads run under the
original DynamicUser systemd policy.

The fixed nonprivileged job transport at
`/usr/local/libexec/hepta-runtime-job-entry` is a separate product. It supplies
the original Operator profile's native submit/observation/cancel transport and
does not grant the system Jobctl root capability.

## Native composition

`tools/generate_hia_system_jobctl_packer.py` defines the exact ordered role
list. The native packer accepts `HIAJCT01`, twenty little-endian u64 lengths,
and the corresponding flat programs. The header is 168 bytes. Every flat is
between 1 byte and 1 MiB; the complete static ELF must fit the original 4 MiB
product boundary. Length arithmetic, complete input consumption, output size,
and all component extents are checked before publication.

| Position | HIA module | Responsibility |
| --- | --- | --- |
| 1 | system_jobctl_entry | Root and supervisor entry dispatch |
| 2 | system_jobctl_control | Root request and filesystem control |
| 3 | system_jobctl_json | JSON arena decoder |
| 4 | system_jobctl_request | Original typed Request decoding and rendering |
| 5 | system_jobctl_start | Root START and PTY lifecycle |
| 6 | system_jobctl_record | Original typed persistent Record |
| 7 | system_jobctl_process | Fixed systemd command process and capture |
| 8 | sha256_stream | Streaming SHA-256 |
| 9 | system_jobctl_observation | STATUS, READ, CANCEL and binding |
| 10 | system_jobctl_terminal | Typed Exit, Witness and capture evidence |
| 11 | system_jobctl_value | Complete retained serde Value domain |
| 12 | system_jobctl_supervisor | Unprivileged supervision and credentials |
| 13 | system_jobctl_spec | Typed systemd credential Spec |
| 14 | system_jobctl_spawn | Original workload exec and child ownership |
| 15 | system_jobctl_capture | Streams, deadlines, cancellation and original child |
| 16 | system_jobctl_publish | Durable Exit and Witness publication |
| 17 | system_jobctl_scratch | Engine scratch lifecycle and receipts |
| 18 | system_jobctl_scratch_directory | Directory custody and bounded deletion |
| 19 | system_jobctl_scratch_group | Original process group observation |
| 20 | system_jobctl_supervisor_vectors | Rust-compatible command and path vectors |

The shared state is 128 MiB and each syscall plan is 128 bytes. The authoring
modules contain the named field and phase allocation. Scratch persistent
binding state occupies 114–118 MiB, separately from the captured input and
credential. Scratch error text is temporary; the capture owner saves it before
performing child cleanup or requesting a retained receipt.

## Preserved boundaries and failure ordering

Typed Request, Record, Spec, Exit, Witness and capture values retain the
original serde struct object and sequence forms, defaults, duplicate rules,
integer types and rejection of `-0` for signed integer fields. The JSON file
reader preserves its 1 MiB metadata gate and its additional growth byte.
Retained Values include unknown floating values and last-wins object keys.
The specialized Value owner provides 524,289 nodes, sufficient for the
unchanged file bound; it does not substitute the smaller MCP request arena.

Captured execution retains 16 MiB per output stream, bounded reads on each
turn, the original 20 ms poll interval and 200 ms post-exit drain deadline.
Cancellation and deadline handling only signal an owned, unconfirmed original
child. Nonblocking child observation reports EINTR as the original
`Process::try_wait` does; blocking `wait` retries EINTR. The original child
is reaped at the original ownership boundary. Scratch WNOWAIT observation
never reaps it.

Terminal publication preserves file write, file fsync, rename and parent
directory fsync ordering. The Witness hashes the actual complete Exit bytes,
including their newline. Publication failures preserve the original observable
partial files. The original terminal timestamp is recorded before scratch
cleanup and is not replaced by a later publication timestamp.

Scratch retains the original 2 second process group observation, 3 second
directory deadline, 100,000-entry and 32-level bounds. The directory owner
retains descriptor custody and never follows a replacement symlink.
Interrupted file opens, writes and fsync use the original retry behavior;
directory enumeration, rename and raw waitid preserve their original failures.

## Reproducible qualification

The following commands build the actual HIA product, rather than invoking a
host implementation of its policy:

```sh
python3 -m tools.qualify_hia_system_jobctl_packer \
  --source SOURCE --seed NATIVE_SOURCE_BUILD \
  --seed-sha256 EXPECTED_SEED_SHA256 --output NEW_OUTPUT
```

The output contains every source/flat pin, the source seed pin, the packed ELF,
and 76 native packer cases. These cases include each of twenty zero, excessive
and overflowing component lengths, truncation, trailing data, insufficient
work/output, and exact 4 MiB versus 4 MiB plus one final images.

The full supervisor qualifier requires an independent original Jobctl oracle,
the newly packed product, and the two C fixtures in a new directory. The
fixtures supply workload facts or inject one syscall result in their own
traced child; they are not part of the product. Its caller must establish a
private mount and PID namespace. For example:

```sh
cc -O2 -Wall -Wextra -Werror tools/hia_system_jobctl_supervisor_fixture.c -o QA/fixture
cc -O2 -Wall -Wextra -Werror tools/hia_system_jobctl_supervisor_faults.c -o QA/fault-tracer
sudo -n unshare --mount --pid --fork --mount-proc --propagation private \
  python3 tools/qualify_hia_system_jobctl_supervisor.py QA
sudo -n unshare --mount --pid --fork --mount-proc --propagation private \
  python3 tools/qualify_hia_system_jobctl_supervisor.py QA --faults
```

The first invocation covers 54 actual supervisor scenarios. The second covers
52 actual syscall failure/short-write scenarios, including nonblocking wait,
blocking wait and kill with EIO and EINTR. They compare return status, output,
all resulting file metadata and content, original capture semantics, and
independently verify Witness-to-Exit hashes. Unique timestamps and directory
device/inode identities are validated before their comparison normalization.

`tools/qualify_hia_system_jobctl_start.py` preserves the 29 independent root
START/PTY cases with `tools/hia_system_jobctl_start_fixture.c`. It runs in a
private mount namespace with isolated policy and registry and observes the
original fixed systemd command arguments and persisted records. This fixture
gate does not claim a real systemd manager execution.

The first complete same-seed checkpoint used source seed SHA-256
`494833999e25ac74ea6ad1de41235c01bfa036951f212604026cb8be686c78af`.
The packed product is 3,387,004 bytes with SHA-256
`fe9ba1c6b6d309e7ddd4ae5da984de328cb86a64cf3c639e2a6c81ac226f0f2e`.
The 76 + 54 + 52 + 29 gates passed. The final three reports have SHA-256:

- Supervisor: `c580e0f3f988b913c3941f3ddbb1e3cfd319c69193d72ac305581e2e01ba5792`
- Faults: `e07c2bb9a6bbe97e7aa34a486976390efc0d91db372b9326f103123bc42eac7e`
- Root START/PTY: `f14e0cc3ba75dad7b3d23d1924cab9ab20d28e3bfc3aaa7f7750cf3a8d7e521e`

Earlier independent gates also cover 416 Requests, 274 Records, 146 privileged
control cases, 144 Specs, 423 Command/Path vectors, 143 errno display values,
261 observation cases, 152 typed terminal cases, and the Scratch 42 + 35 + 38
+ 28 process/directory/error groups. These are component evidence; only reports
whose image pins match a final package apply to that package.

## Remaining acceptance work at this checkpoint

The full-process qualifiers explicitly record `error_diagnostics_exact: false`.
Successful outputs, accept/reject behavior, persistent records and terminal
receipts are compared; all unsuccessful command stderr text has not yet been
made byte-exact with the original Rust entry. This limitation must remain
visible until separately closed. The root START fixture also cannot replace
a real system systemd/DynamicUser end-to-end run. Product registration in a
new complete source closure, final cold rebuild, installation, and that real
manager qualification belong to final integration and must not reuse an older
source receipt.
