# HIA native Linux cancellation host

`job_cancel.hepta` owns the Linux host path for the existing HIA cancellation
authority and durable signal writer. It replaces the Python work surrounding
those two programs: bound metadata capture, image digests, sealed descriptors,
helper execution and deadlines, pidfd acquisition, process observations, grace
waiting, and response projection. The mechanical Linux adapter translates
bounded offsets and performs the syscall or HIA call selected by the policy.
The executable and its children require no Python, Rust, shell, libc, dynamic
loader, or systemctl.

This component implements the current Linux profile with both
`hia_cancel_authority` and `hia_cancel_writer` present. The surrounding runtime
continues to pin their bytes and the cancellation host itself. The authority
decides ownership; the writer owns durable publication and the pidfd signal.
The cancellation host never stops a reusable systemd unit name or kills a
workload process group.

## Request ABI

The executable accepts no command-line arguments. Stdin is one binary frame
with an 80-byte little-endian `<8s9Q>` header:

| Field | Meaning |
| --- | --- |
| Magic | `HIAJCQ02` |
| Grace | Nanoseconds, clamped by HIA to `0..30000000000` |
| Authority extent | Raw ELF bytes, `64..1048576` |
| Writer extent | Raw ELF bytes, `64..1048576` |
| Flags | Zero |
| Job-directory length | `6..4096` bytes |
| Job-id length | `1..128` bytes |
| Unit length | `1..512` bytes |
| Request-digest length | Exactly 64 bytes |
| Reserved | Zero |

The payload contains the job directory, job id, unit, and lowercase hexadecimal
request digest, in that order. These strings have no terminators or NUL bytes.
Next are two raw 32-byte SHA-256 digests, first authority then writer. Finally
come the two raw ELF images in the same order. There is no trailing data. The
adapter's total input limit is 3 MiB. Unknown flags, an invalid header, extra
arguments, or invalid custody fail with exit code 65 and no success response.

The runtime's JSON-based public request remains unchanged. Its transport
encoder supplies this binary envelope and performs no cancellation decision.
The grace value represents the same bounded wait after submission; it does not
authorize escalation or claim confirmed termination.

## Custody and sequencing

The directory walk and initial bound-observation checks reuse the native job
observation owner. Every component is pinned without following symlinks; the
last three directories must have mode 0700 and belong to the effective uid.
The request binds the job id, directory, unit and digest, retaining the original
fingerprint fallback only when the digest field is absent.

Cancellation rereads the request, exit, launch and started metadata in the
retained order after the initial bound admission. These files retain the
original 4 MiB capture limit and regular-file, owner, link-count and write-mode
checks. The status owner's narrower started-file limit is not applied here.
Each capture verifies descriptor and pathname identity before admitting its
bytes. Shared metadata decoding preserves UTF-8/16/32 detection, repeated keys,
surrogates, nonfinite unknown values, and the original integer limit.

A nonempty exit object returns `already_exited` before loading or invoking the
two images. An empty exit object follows the original truth semantics and does
not suppress submission. Frozen authority fields use strict UTF-8 and their
original 4096-byte limit. Identity dictionaries retain the original exact
`kind`/`value` key-set rule, including last-key-wins duplicate handling.

HIA hashes the supplied images, writes private mode-0500 memfds, and seals them
against writes, growth and shrinkage. Each authority request is a separately
sealed mode-0400 memfd using `HIAJCX01`. The authority's exact `HIAJCY01`
response is checked. The host opens the original supervisor's pidfd before
collecting process identity and UID and requesting phase-one authorization.
Failed or missing identity observations cannot authorize the writer.

After phase one accepts, HIA constructs the existing `HIAJRC01` writer frame
using the pinned pidfd, job id, nonce, caller pid and current milliseconds. The
child receives the retained job-directory descriptor as stdout and the pidfd
as an inherited capability. Acknowledgment requires normal child exit and the
exact 24-byte `HIAJRW01`, operation 7, result 0 receipt. The existing writer
publishes and syncs `cancel-request.json` before `pidfd_send_signal(SIGTERM)`.

## Helper and wait boundaries

Each helper has the original five-second execution budget. Parent-owned
nonblocking pipes admit exactly the bounded authority/writer response; extra
bytes, stderr where forbidden, bad tags, nonzero exits, or failed exec reject
the submission result. A monotonic deadline and bounded polling prevent a
silent helper from blocking indefinitely. A failed or timed-out helper is
reaped; a kill is directed only at an unreaped child created by this invocation.
The host never uses that cleanup path for the supervisor being cancelled.

The grace loop rereads the exit object and original process identity and sleeps
in bounded intervals. It returns when either changes or the grace deadline
expires. Supervisor and workload termination, escalation and output draining
remain with the original runner. The result is `term_sent` for detached jobs or
`stop_requested` for the corresponding systemd authority decision, with
`atomic_identity: true`, the frozen supervisor pid,
`termination_confirmed: false`, and `reconcile_via: "process_status"`.

## Native sources and build

The component adds:

- `examples/hia_bootstrap/job_cancel.hepta`;
- `examples/hia_bootstrap/job_cancel_packer.hepta`;
- `tools/hia_job_cancel_syscalls.S`.

The packer reuses the existing `job_observation_json.hepta` and
`sha256_stream.hepta` flat images. Its input is `<8s3Q>` with magic `HIAJCK02`,
policy length, metadata-decoder length and streaming-SHA length, followed by
those three images. Its output is one static executable of at most 1 MiB.
There is no additional metadata-decoder source role. The Python generator and
qualifier are authoring and independent comparison tools; the generated native
build and execution paths do not run them.

## Qualification

`tools/qualify_hia_job_cancel.py` compares the unchanged pinned runtime's
private-directory, bound-observation and cancellation constants with the
native executable. Every signal target is a fresh private child owned by the
qualifier; no existing service or unrelated process is used. Each implementation
must match the exact response for its own target and produce exactly one
observed signal and durable cancellation receipt when admitted. Rejected cases
must produce neither effect.

Cases cover detached/systemd decisions, existing and empty exit objects, grace
waiting, all metadata encodings, exact metadata and image limits, repeated
identity keys, changed ownership and start ticks, unsafe and malformed files,
image-digest and executable failures, response-shape failures, and helper
timeouts. Targeted parent-syscall injection separately denies pidfd acquisition,
process-stat access and UID observation. A private successful baseline locates
each injection, after which only the qualifier's own signal marker and receipt
are cleared before the rejected run. Native traces verify executable custody,
sync before signalling, and the absence of Python/Rust/shell child execution.
