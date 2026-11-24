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
blocking wait and kill with EIO and EINTR. They compare return status, stdout,
exact stderr,
all resulting file metadata and content, original capture semantics, and
independently verify Witness-to-Exit hashes. Unique timestamps and directory
device/inode identities are validated before their comparison normalization.

`tools/qualify_hia_system_jobctl_start.py` preserves the 29 independent root
START/PTY cases and adds twelve exact engine-selection cases with `tools/hia_system_jobctl_start_fixture.c`. It runs in a
private mount namespace with isolated policy and registry and observes the
original fixed systemd command arguments and persisted records. This fixture
gate does not claim a real systemd manager execution.

The root START qualifier has two explicit profiles. The default remains the
original 41 cases; `--diagnostics` selects the additional 65-case byte corpus.
Each profile uses a new output directory containing `jobctl-reference`,
`jobctl-native`, and the compiled START fixture:

```sh
cc -std=c11 -D_DEFAULT_SOURCE -O2 -Wall -Wextra \
  tools/hia_system_jobctl_start_fixture.c -o QA/fixture
sudo -n unshare --mount --propagation private \
  python3 tools/qualify_hia_system_jobctl_start.py QA
sudo -n unshare --mount --propagation private \
  python3 tools/qualify_hia_system_jobctl_start.py OTHER_QA --diagnostics
```

The current integrated product is 3,573,751 bytes with SHA-256
`3a29a98dd34022d0127837bebfd43a7cebd8e57c58c772751c5d1714886a697d`.
The 76 packer, 54 supervisor, 52 syscall-fault and 41 START/PTY gates passed.
All 41 + 54 + 52 comparisons require exact stderr bytes, including failure
branches; the earlier records with unqualified diagnostics remain unchanged.
An additional 65-case native launch-error campaign compares every single byte,
every pair of bytes, valid Unicode, invalid and truncated sequences, 4 KiB
read boundaries, embedded NUL/CR/LF and a 9 MiB error stream against the fixed
Rust executable. All raw diagnostic streams are retained and compared as bytes.
The source-bound native builder produces exactly the same ELF as the packer
campaign and the actual fixed administrator-owned installation.

`tools/qualify_hia_system_jobctl_real.py` has passed thirteen actual systemd
and DynamicUser scenarios against that installed fixed path: exit, binary
stdin, capture truncation, timeout, cancellation, engine adoption, ghidra
selection, invalid worker PID claim, nonengine selection, surviving descendants,
missing adoption, native PTY and original PTY. The independent original Rust
entry reads the completed jobs' status and output. These workloads are owned
fixtures exercising the protocol, not executions of the actual jadx or ghidra
providers. The driver requires a private mount namespace before it creates
a private policy overlay; systemd itself and the resulting jobs are real.

`tools/qualify_hia_system_jobctl_visibility.py` has passed two additional
actual systemd controls. Both the original Rust and current native supervisor
refuse terminal publication and retain scratch with the same restricted
visibility error when forced to run with `ProtectProc=invisible`.

Earlier independent gates also cover 416 Requests, 274 Records, 146 privileged
control cases, 144 Specs, 423 Command/Path vectors, 143 errno display values,
261 observation cases, 152 typed terminal cases, and the Scratch 42 + 35 + 38
+ 28 process/directory/error groups. These are component evidence; only reports
whose image pins match a final package apply to that package.

## Engine launch correction

The fixed Rust reference unconditionally selected `ProtectProc=invisible`,
while its original process-group custody proof correctly refused a restricted
`/proc` mount. This caused real engine jobs in both original Rust and the
initial native translation to retain scratch without terminal publication.

The native START owner now requests a selection-only operation from the same
HIA ScratchOwner. Only noninteractive requests with exactly the argument
`rea-static-worker`, valid stdin JSON schema
`hepta.rea.static-request.v1`, and profile provider `jadx` or `ghidra`
select `ProtectProc=default`. That parser operation performs no filesystem
operation. The command and validated resource values are constructed before
the shared Value parser reuses its arena.

All other requests retain `ProtectProc=invisible`. The selected engine
supervisor gains the process metadata visibility required for a complete
group scan. DynamicUser, NoNewPrivileges, empty capabilities, filesystem and
network restrictions, credentials, resource limits and KillMode remain
unchanged. The complete group proof is unchanged and continues to reject
restricted visibility. The START gate preserves the original observations
and explicitly records the one-property correction in its three selected
engine cases; its nine other new cases require no argument difference.

## Ordinary release and matching cold construction

The ordinary HIASTD01 recipe compiles all twenty owners and the packer and
publishes `hepta-runtime-jobctl` within the existing stage 10. Its shared
64 MiB packer host recompiles the captured packer source and compares the
resulting flat before execution. The packer binds the complete adapter and
twenty relative calls in generated metadata, allowing verification without
invoking an assembler during construction. The native recipe separately checks
the complete generic packer host and final ELF bytes using the shared exact
sequential-layout guard: both ELF size words, every rel32 operand, every
adapter byte and all twenty contiguous program images are bound. It does not
apply the older aligned-placement or Pager-specific checker to this layout.
The final declarations retain ten stages and 71 products; the additional
recipe has 1,482 nodes and 44 publications, within the original 2,048-node limit.

`tools.build_hia_system_jobctl.build(output, compiler, cold_report)` returns
`output/hepta-runtime-jobctl` and writes `output/build.json`, schema
`hepta.hia.system-jobctl-source-build.v1`. The receipt binds the cold report,
compiler, native source builder, all captured sources, twenty flat images,
packer and actual ELF. The source inventory is checked again before
publication. An explicit development-seed build is marked as development;
it cannot stand in for the matching cold build required by production callers.

The native MCP bridge retains the fixed isolated-job command
`sudo -n /usr/local/libexec/hepta-runtime-jobctl`. Controller and worker
transport installation does not grant or choose another privileged entry.

## Root error diagnostics and ordering

The six previously differing START observations are closed: missing
InvocationID, ownership mismatch, empty launch failure, invalid UTF-8 launch
stderr, signal termination and PTY missing identity. Invocation errors remain
deferred to the original observation caller. A confirmed terminal receipt can
still supersede a failed property probe, and an internal PTY cancel still
ignores its error before killing and waiting for the original child.

For a failed captured systemd launch, the HIA owner first durably publishes
`launch_failed`, then streams the retained stderr memfd through the shared
diagnostic continuation. The conversion uses a 4 KiB input block, at most
three pending UTF-8 bytes, and a 12 KiB output block. It adds no whole-error
length ceiling, preserves valid bytes and embedded NUL/CR/LF, and matches
Rust `String::from_utf8_lossy` replacement boundaries. EINTR and partial writes
resume the current operation. The original prefix and final newline are
emitted exactly, and a signal-terminated launcher follows the same failure
path. This code does not change workload capture bounds or process ownership.

## Final integration scope

Final matching cold qualification, default distribution, ordinary whole
release, final worker/controller installation and final runtime-config binding
belong to final integration. Actual fixed-path lifecycle evidence does not
substitute for those final complete-source receipts.
