# HIA native job observation

`job_observation.hepta` owns the remote read-only observation policy. Its fixed
Linux adapter gathers bounded stdin, calls HIA, translates buffer offsets and
executes the syscall selected by HIA. The product image runs without Python,
Rust, a shell, libc, or a dynamic loader.

The component implements bound `READ_CODE` and the v25 `STATUS_CODE` snapshot
profile with all six HIA status flags. HIA owns directory custody, persisted
metadata decoding, log cursors, systemd observation, process identity capture,
and the resulting snapshot. Existing HIA terminal and lifecycle owners consume
that snapshot. This component alone does not replace the Rust MCP controller,
SSH connection pool, job submission, cancellation, or the running service
configuration.

## Request ABI

The executable takes no command-line arguments. Stdin is one binary frame with
an 80-byte header, little-endian `<8s9Q>`:

| Field | Value |
| --- | --- |
| Magic | `HIAJOBQ1` |
| Mode | `0` for a bounded log read; `1` for a v25 status snapshot |
| stdout offset | Unsigned byte cursor |
| stderr offset | Unsigned byte cursor |
| Limit | Clamped to `1..16384` independently for each log |
| Job-directory length | `6..4096` bytes |
| Job-id length | `1..128` bytes |
| Unit length | `1..512` bytes |
| Digest length | Exactly `64` bytes |
| Flags | `0` for READ; `63` for the six-flag STATUS profile |

The header is followed by the job directory, job id, unit, and digest bytes in
that order. Strings contain no NUL bytes. The digest is lowercase hexadecimal.
The whole transport is at most 65536 bytes. Unknown modes, flags, lengths,
trailing data, and command-line arguments fail closed with exit code 65.

## Directory and file custody

HIA requires an absolute path without `.` or `..` components and with `jobs`
as the penultimate component. It opens every component relative to the previous
pinned descriptor with `O_NOFOLLOW`. Shared ancestors use `O_PATH`; the last
three directories must be owned by the effective uid and have mode exactly
0700. Existing permissions are never repaired.

Before opening logs, HIA captures and decodes `request.json`, and checks
`job_id`, `job_dir`, `unit`, and `request_digest`. If the digest field is absent,
it reads `request_fingerprint`. A present null or invalid digest does not enable
that fallback. `launch.json` and `exit.json`, when present, must also be valid
objects. This preserves the existing bound-observation admission sequence.

Each metadata file must be regular, owned by the effective uid, have one link,
and have no group or other write bits. It is opened nonblocking and without
following symlinks. Captures are limited to 4 MiB and compare device, inode,
mode, uid, link count, size, mtime and ctime before and after reading, including
a final pathname observation relative to the retained job directory. Atime and
allocation-block accounting are deliberately excluded from this identity.

The shared HIA metadata profile retains repeated keys and selects their last
value. It implements the persisted-byte conventions of `json.loads(bytes)`:
UTF-8, UTF-16 and UTF-32, BOM and no-BOM detection, isolated surrogate code
points, escaped surrogate pairs, and the accepted nonfinite literals. The
original encoded extent remains limited to 4 MiB; a separate 8 MiB buffer holds
normalized UTF-8/WTF-8. Integer lexemes retain the original 4300-digit limit;
floating-point lexemes are not incorrectly subjected to that integer limit.

The private profile permits 2097152 nodes. Its 32 MiB explicit stack permits a
maximum nesting depth of 699047. It does not copy CPython's incidental C-stack
exhaustion, whose boundary changes with process layout. The original oracle
accepts the qualified 56000-depth input. Typed nodes retain spans into the
normalized representation, while receipt custody retains the original bytes.

## Log response

Successful output is one JSON object with `job_id`, `stdout`, and `stderr`.
Each stream has `offset`, `next_offset`, `size`, `eof`, `text`, and `bytes_hex`.
Offsets always count source bytes. UTF-8 replacement for `text` has the same
consumption behavior as Python's `bytes.decode('utf-8', errors='replace')`,
including an incomplete sequence at a page boundary. The hex field preserves
every captured byte exactly.

Missing logs are readable only at cursor zero. A cursor beyond the initial
file length fails rather than silently rewinding. A log path must retain its
original device/inode; its retained fd must still have one link and must not
shrink below the initial size. Append-only growth is allowed. HIA emits no
partial response before both stream observations have passed validation.

## Status snapshot

Mode 1 with flags 63 corresponds to `hia_status_snapshot`,
`hia_status_terminal_facts`, `hia_status_terminal_witness`,
`hia_status_native_receipt`, `hia_status_lifecycle_facts`, and
`hia_status_lifecycle_owner` all being true. The executable returns one immediate
snapshot. Polling and the caller's wait budget remain with the enclosing owner.

Terminal observation preserves the protocol, witness, and pending-state
semantics of the retained profile. Terminal receipts require mode 0600 and at
most 1 MiB; witnesses require mode 0600 and at most 4096 bytes. `witness.raw`
contains the original encoded receipt bytes in hexadecimal, including any BOM.
The `receipt` object is emitted from normalized text, with isolated surrogates
escaped so the outer response remains strict UTF-8. Unsupported or unsafe
publication is pending rather than a manufactured completed state.

Started metadata has a 16 KiB capture limit and mode 0600. The systemd path
executes the absolute `/usr/bin/systemctl` with HIA-constructed arguments. It
preserves the inherited environment, adding the existing XDG and session-bus
defaults only when absent. A separate close-on-exec error pipe distinguishes a
failed exec from a real systemctl nonzero exit. Captured environment data is
bounded to 1 MiB and 4096 entries. No service is changed by observation.

Process identity comes from `/proc/<pid>/stat` and the kernel boot id; a
separate UID observation reads the process directory. The parser uses the last
`) ` separator so parentheses in process names are retained correctly. Missing
identity and missing UID remain separate observations. Invalid UTF-8 or failed
proc reads produce the same absent observations as the retained host profile.
The systemd path rereads the receipt after observing the unit to close the
existing collection race. Detached jobs retain the frozen supervisor checks.

Legacy receipts without a publication protocol keep their facts projection.
The existing exact HIA decimal-to-binary64 converter supplies float truth and
integer conversion, including underflow, infinity, NaN, and rounding at one.
Integer strings use the frozen Unicode 16 decimal-digit and whitespace tables,
signs, underscore placement, and 4300-digit limit of the retained oracle.

## Source and build boundary

The component consists of:

- `examples/hia_bootstrap/job_observation.hepta`: policy and JSON response.
- `examples/hia_bootstrap/job_observation_json.hepta`: native metadata decoder.
- `examples/hia_bootstrap/job_observation_packer.hepta`: deterministic ELF packer.
- `tools/hia_job_observation_syscalls.S`: mechanical Linux adapter source.

The native source compiler compiles the three HIA sources. The HIA packer input
is `<8s2Q>` with magic `HIAJOK01`, policy length, decoder length, followed by the
two compiled flat images. The packer returns the complete static ELF. Python
authoring and qualification modules are development tools; neither participates
in execution of the generated image.

`tools/qualify_hia_job_observation.py` compares the native executable with the
retained runtime's exact private-directory, bound-observation and READ Python
constants. It exercises valid and rejected custody, full metadata extents,
escaped and repeated keys, log bounds, missing logs, UTF-8 boundary behavior,
symlinks, hard links, writable files, and malformed request frames. Strace also
checks that the native read has exactly one exec and that a rejected binding
never opens stdout or stderr.

`tools/qualify_hia_job_observation_status.py` compares the unchanged six-flag
STATUS oracle and the native snapshot. It covers running and terminal jobs,
all supported metadata encodings, original-byte witness hashes, isolated
surrogates, large normalized responses, legacy numeric facts, safe and unsafe
receipt/owner files, unavailable buses, process names, and live read-only
systemd observations. Targeted syscall failures independently exercise missing
process identity, missing UID, and a systemctl exec failure. These tests do not
change shared services or signal unrelated processes.

## Reusable policy helpers

The authoring source is `tools/generate_hia_job_observation.py`.
`policy_source()` returns the HIA authoring text; `observation_json_source()`
returns its private JSON profile. The generator renders both through the same
checked HIA builder used by the native job supervisor.

`safe_file(w, at)` checks a Linux x86-64 stat record against the effective uid
stored at workspace offset 16. `same_stamp(w, left, right)` compares exactly
the metadata identity fields listed above. `request_bound(s, w)` operates on
the decoder's 72-byte node layout and selects the last matching field.
`quoted(w, at, source, size)` emits a JSON string from arbitrary log bytes with
UTF-8 replacement. `call(...)` produces a syscall plan; `decode(...)` produces
the bounded HIA decoder call plan. Their workspace offsets are component-local
and must be rebased when embedding the helpers in another owner.

`tools/generate_hia_job_metadata.py` exports `NORMALIZE`,
`metadata_json_source()`, and `MAXIMUM_METADATA_DEPTH`. `NORMALIZE` is HIA text
using the caller's `RAW_JSON` and `NONE` constants and `getn`/`copy_bytes`
helpers; `normalize_json(w, source, size)` returns a normalized length or
`NONE`. It is compiled into each policy and adds no runtime host dependency or
third observation image. `tools/generate_hia_job_observation_status.py` authors
the status extension and relocates the existing binary64 conversion scratch
without sharing mutable decoder state.
