# HIA native job observation

`job_observation.hepta` owns the remote read-only observation policy. Its fixed
Linux adapter gathers bounded stdin, calls HIA, translates buffer offsets and
executes the syscall selected by HIA. The product image runs without Python,
Rust, a shell, libc, or a dynamic loader.

The initial component implements the bound `READ_CODE` contract. A complete
native `STATUS_CODE` path is a separate extension. This component alone does
not replace the Rust MCP controller, SSH connection pool, job submission, or
the running service configuration.

## Request ABI

The executable takes no command-line arguments. Stdin is one binary frame with
an 80-byte header, little-endian `<8s9Q>`:

| Field | Value |
| --- | --- |
| Magic | `HIAJOBQ1` |
| Mode | `0` for a bounded log read |
| stdout offset | Unsigned byte cursor |
| stderr offset | Unsigned byte cursor |
| Limit | Clamped to `1..16384` independently for each log |
| Job-directory length | `6..4096` bytes |
| Job-id length | `1..128` bytes |
| Unit length | `1..512` bytes |
| Digest length | Exactly `64` bytes |
| Flags | Zero |

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

The HIA JSON profile retains the host metadata convention of accepting repeated
keys and selecting their last value. It decodes escaped keys and strings before
binding. The private profile permits 2097152 nodes and a maximum nesting depth
of 1000 so the 4 MiB input extent is not reduced to the general wire decoder's
smaller node/depth defaults. The typed node arena retains raw wire spans.

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
