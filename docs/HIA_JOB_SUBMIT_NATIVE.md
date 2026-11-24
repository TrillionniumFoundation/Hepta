# Native job submission owner

`job_submit.hepta` and `job_submit_launch.hepta` own remote submission of the
fully selected v25 HIA job-supervisor profile. The executable reads one bounded
binary request from stdin. Directory custody, replay decisions, image identity,
staging, backend selection, process creation, and launch publication are HIA
decisions. The assembly adapter transports process argv/environment, Linux
syscalls, and calls between the four HIA components.

## Submission frame

The 64-byte header is little-endian `<8s7Q>`:

| Offset | Field |
| --- | --- |
| 0 | `HIAJSB01` |
| 8 | Encoded metadata byte length, 1 through 4 MiB |
| 16 | stdin byte length, 0 through 512 MiB; `UINT64_MAX` means absent |
| 24 | Terminal encoder image byte length |
| 32 | Terminal writer image byte length |
| 40 | Native supervisor image byte length |
| 48 | Bound native launcher image byte length |
| 56 | Reserved, exactly zero |

The header is followed by metadata, the four raw images in the table order,
optional stdin, and exact EOF. Each image extent is at most 1 MiB; fresh image
admission additionally requires at least 64 bytes and the bound SHA256. This
keeps raw image and stdin transport separate from metadata JSON. The metadata
retains the original request fields and all sixteen authority flags. It supplies
the three `hia_terminal_publisher` hashes and `hia_job_launcher_sha256`; the
controller removes the former hex artifact map and stdin text before framing.

The fixed `hia_job_entry_path` is supplied by the administrator's complete
native HostConfig, for the same trusted bootstrap installed at the SSH entry
boundary. It is used when systemd is available. This is a trusted installed
entry point, not a caller-selected workload path. The bootstrap validates and
seals the actual launcher image before executing it.

## Custody, staging, and replay

The owner captures and seals all incoming images and stdin before traversing the
job directory. It opens each path component without following links and checks
that the state/jobs/job suffix is owned by the effective uid with mode 0700.
Missing private components are created with mode 0700 and their parent directory
is synchronized. Existing permissions are never repaired during admission.

The regular, single-link, mode-0600 launch lock is held across replay or fresh
submission. Existing request, launch, and exit metadata use stable descriptor
captures with the original 4 MiB encoded limit, owner/mode/link checks, and
before/after/current-name identity checks. A previous request must match its
job id, directory, unit, fingerprint, request digest, and ordered execution roots.
It is never launched again. A completed or previously launched request returns
the original reuse response; failed and ambiguous previous launches refuse.
Fresh-only flags and artifacts do not turn a correctly bound replay into a new
launch.

Fresh submission checks every authority flag, all four image hashes, and the
original artifact tombstones. The native launcher archive is an additional
tombstone. It obtains a fresh nonce, writes each image and optional stdin with
exclusive creation, and synchronizes each file and the directory. The request
is also exclusively created and synchronized. Partial files remain evidence of
an uncertain submission. A bound launcher request includes the retained directory
device and inode, job id, nonce, fingerprint, terminal hashes, and authority flags.

## Backend execution

PATH discovery follows the original systemd-run selection, including an empty
PATH, missing components, executable checks, and the platform selection. The
owner preserves the original unit name, description, control-group kill mode,
stop timeout, optional CPU/memory/nice properties, and isolation/network options.
Inherited launcher environment receives the original XDG and D-Bus defaults.
Workload environment remains the responsibility of the bound launcher.

Systemd receives the original default simple service type. Its fixed native
entry is invoked as:

```
hia-job-entry --launch-base64 SHA256 JOB_DIRECTORY BINDING BASE64_CHUNK...
```

Each full carrier chunk encodes 49152 bytes as 65536 canonical base64 characters.
The final chunk has canonical padding. The entire launcher image is retained in
the transient unit's command, so submission can finish independently of the
eventual service exec. The native entry checks SHA256, seals the decoded image,
and executes the fixed launcher argv with backend `systemd`. No submitting
process descriptor needs to survive the asynchronous service start.

A nonzero systemd-run result follows the original explicit fallback policy.
CPU and memory restrictions cannot silently become detached execution. When
fallback is prohibited, `launch_failed` and its error are published durably.
The detached branch creates a new session, supplies `/dev/null` for the launcher
stdio, closes inherited descriptors on exec, and executes the sealed launcher.
A close-on-exec error pipe distinguishes an unsuccessful exec from a program
that actually started. Both branches preserve the original launch JSON and
reuse semantics. Publication uses an exclusive temporary file, file fsync,
directory-relative rename, and directory fsync.

The native internal profile bounds individual inherited environment strings at
8192 bytes, inherited entries at 128, directory strings at 4096 bytes, binding
JSON at 8192 bytes, and captured systemd diagnostics at 4 MiB. Diagnostics retain
strict UTF-8 decoding, universal newline conversion, and Unicode whitespace
trimming. These are explicit native transport limits. This owner does not add
an engine-scratch/REA worker profile or a non-Linux process backend.

## Source products and qualification

The ordinary product consists of:

- `job_submit.hepta`, the framing, custody, replay, and staging owner;
- `job_submit_launch.hepta`, the backend and publication owner;
- `job_submit_json.hepta`, the shared persisted-metadata decoder;
- `sha256_stream.hepta`, the existing HIA streaming digest owner;
- `job_submit_packer.hepta`, the ELF packer.

The packer consumes `HIAJSBK1`, four u64 lengths, and policy/launch/JSON/SHA flats
in that order. Its output bound is 4 MiB. Splitting the submission and launch
owners preserves the existing compiler function, block, instruction, workspace,
and per-image output limits. Checked-in HIA sources are sufficient for native
compilation; Python generators and qualifiers are development tools.

The first complete component qualification passed 54 fresh original/native
pairs and 19 malformed-frame/argv controls. It covers actual systemd execution,
CPU/memory/nice properties, isolation failure, detached execution, binary-safe
stdin, streams, deadlines, private-directory and lock refusal, every original
artifact tombstone, image identity, failed/ambiguous/reused requests, changed
identity and root policies, PATH lookup, strict diagnostic conversion, and exec
failure. Native traces contain only native executables. Each fresh terminal nonce
is checked against its persisted request and witness, with witness SHA bound to
the actual exit file; independent fresh nonces are not compared for equality.

The qualified submit ELF was 869477 bytes with SHA256
`68b220d6e6a7bd3767be4c24917b0441986dbe6951605a6f8ffd7ef2de1c454c`.
It used the bound launcher
`44347a0c7d35ead4d7cfe54763b4c03d19daf00bd5c6a96a00a798aca6e257ac`
and native entry
`fd60201de7918b218ba9c8fb725162e449ce67976052ec899a8bcc2e44875db1`.

Ordinary release registration, the v26 runtime transport, matching-source cold
builds, and the complete public tool campaign remain separate integration gates.
Component qualification does not declare the whole product closed.
