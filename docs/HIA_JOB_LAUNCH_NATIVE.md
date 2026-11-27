# Native bound job launcher

`job_launch.hepta` owns the boundary between a persisted v25 remote job request
and the native HIA job supervisor. The Linux adapter transports argv, inherited
environment bytes, system calls, and bounded HIA subprogram calls. It makes no
path, admission, ownership, or output-policy decisions.

## Entry and custody

The ELF entry accepts `JOB_DIRECTORY BINDING_JSON [systemd|detached]`. Omitting
the backend selects the original detached behavior. The trusted launcher supplies
the binding, including the directory device/inode, job id, launch nonce, request
fingerprint, three terminal image hashes, and the sixteen v25 authority flags.

The HIA owner walks the absolute directory through no-follow descriptors. The
state/jobs/job suffix must be owned by the effective uid with mode 0700. It binds
the final descriptor to the supplied device and inode, then reads request.json
through that descriptor. Regular-file identity, owner, link count, write
permissions, size, timestamps, and the final directory-relative name are checked
around capture. Request and binding identities, publisher roles, and all selected
authority flags must agree before any workload is submitted.

The encoder, writer, and supervisor are independently captured, hashed in HIA,
and sealed. The workload image is captured with its physical source descriptor
retained as the Worker entry anchor. stdin is captured into a sealed descriptor.
The supplied executable and stdin keep the existing 64 MiB and 512 MiB limits.
The terminal image limit remains 1 MiB, and encoded request metadata remains
limited to 4 MiB.

The selected workload path may be a stable symlink, including a relative target
or a symlink in a parent directory. HIA records the selected entry before resolving
the physical pathname, then opens the physical final name with `O_NOFOLLOW`.
After capture, the source descriptor, physical final entry, followed selected
target, and selected entry are rechecked. Replacing the selected symlink, even
with another link to the same target, refuses the launch. The original selected
spelling remains `argv[0]`; the retained Worker entry descriptor identifies the
physical source file, not the sealed executable copy.

The physical source must have an execute mode bit and pass kernel execution
access for the effective credentials through
`faccessat2(fd, "", X_OK, AT_EMPTY_PATH | AT_EACCESS)`. This preserves permission,
ACL, and mount checks before the copy can become executable. Unsupported kernel
interfaces and denied access refuse the launch. Existing regular-file, write
permission, size, ELF, snapshot, and sealed-descriptor requirements remain in
force for executable aliases.

Metadata decoding preserves last-key-wins object keys, escaped and raw lone
surrogates, Python's byte-input UTF-8/16/32 detection, and nonfinite JSON atoms.
A separate normalized UTF-8/WTF-8 buffer supplies decoder spans; the encoded
capture limit is checked before normalization. These compatibility rules belong
to persisted job metadata, not to arbitrary public JSON schemas.

## Native owner request

HIA resolves the physical workload directory and allowed roots, including
relative symlink targets and nonexistent tails followed by dot-dot. It constructs
the original HIAJOB01 request with the retained directory and physical entry
anchor, exact argument/environment counts, deadline, output caps, and grace
period. Environment overrides preserve dictionary key semantics, filesystem
surrogateescape encoding, removal of the engine-scratch variable, reserved job
and Worker-entry values, and key ordering.

The image creates exclusive private output/receipt files, seals the owner
request, sets the explicitly retained descriptors inheritable, and replaces
itself with the sealed HIA supervisor. The unit main pid is preserved. The
supervisor continues to own workload creation, cancellation, output capture,
reaping, and durable terminal publication.

The present launcher ABI has a 4096-byte job-directory argument, 8192-byte
individual argv/environment strings, 128 mechanically captured inherited
environment entries, and the existing final limit of 64 arguments and 64
environment entries. Native realpath uses 8192-byte working paths and 256 active
symlink-expansion frames. These finite launcher limits are explicit; this
component does not establish unbounded POSIX pathname compatibility.

## Source and qualification

The checked-in product sources are:

- examples/hia_bootstrap/job_launch.hepta
- examples/hia_bootstrap/job_launch_json.hepta
- examples/hia_bootstrap/job_launch_packer.hepta
- examples/hia_bootstrap/sha256_stream.hepta

The packer accepts HIAJLNK1 followed by three little-endian u64 byte lengths and
the policy, metadata decoder, and streaming SHA native images. It emits a static
Linux x86-64 ELF. The source compiler and packer run natively; the Python authoring
tool regenerates checked-in HIA during development only.

`tools/qualify_hia_job_launch.py` extracts the unmodified runner and private
directory functions from the supplied runtime jobs.rs, builds independent
workload fixtures, and executes fresh original/native pairs. A native case
receives an empty PATH and an exec trace. Only the launcher, supervisor, and
explicitly requested workload may execute; the ordinary `/bin/sh` case requests
that shell as its workload. The comparison covers child admission, complete
workload streams, terminal fields, native receipt length, and witness binding.

Executable capture cases additionally check the original `argv[0]`, source
descriptor device/inode identity, stable aliases, relative selection, parent
aliases, dot-dot, surrogateescape, missing execution permission, effective-owner
denial despite another execute bit, unsafe write permissions, dangling links,
cycles, and an ordinary shell. Two races use a kernel file lease to block the
actual source open after the initial entry observation: one changes the target,
and the other replaces the selected symlink with a new entry to the same target.
Both must refuse before creating a workload child. A missing lease-break signal
fails the case rather than counting a timing-only mutation as race coverage.

`--case` restricts a run to explicitly named pairs. The optional
`--allow-untraced-observations` collects actual behavior on hosts that deny
`ptrace`; it records `success: false` and `BEHAVIOR_PASS_EXEC_TRACE_OPEN`, and
cannot supply an exec-trace qualification. The normal mode requires the trace.

The earlier shared metadata qualification passed 98 original/native pairs, including:

- all sixteen authority flags and changed job, directory, nonce, and image pins;
- arguments and environments at their original count/byte boundaries;
- Unicode and filesystem surrogateescape transport;
- physical-root containment, repeated symlinks, a 48-link chain, and cycles;
- deadline and cancellation through the actual native supervisor;
- eight metadata encodings, duplicate keys, nonfinite extra values, and the
  exact encoded metadata limit, 4300-digit integer boundary, 5000-digit float,
  and 56000-level nonsemantic nesting;
- the exact 512 MiB stdin and 64 MiB workload limits and their immediate refusals.

The qualified ELF SHA256 was
`44347a0c7d35ead4d7cfe54763b4c03d19daf00bd5c6a96a00a798aca6e257ac`
(592126 bytes). Qualification outputs are external to the source tree.

The executable capture revision was separately built through the pinned native
seed frontend, projector, backend, and HIA packers, then qualified on ROG against
the unmodified runtime runner at `fb42bd643458e3e1435a0584ba4690ea98071838`.
All 114 original/native pairs passed, including the full earlier boundary suite,
the 512 MiB stdin and 64 MiB executable boundaries, and the new executable cases.
The revised ELF is 522392 bytes with SHA256
`d5cfd680842886bc54ce25ed9d06d96ab6f9eb3c1d54836791b08ace2ae1c8f3`.
The source HIA SHA256 is
`331794f98fd890d60d933fb62a913488da981b7f69457f84dd15012b352cf71c`.
The complete report, raw exec traces and terminal evidence, original failing
controls, and native build call receipts are retained under
`docs/qualification/hia-job-launch-executable-capture-20261127-2ac5/`.
This is a launcher component qualification; the changed source still requires
the combined source freeze, cold qualification, release binding, and public
START/STATUS integration gates.

This checkpoint replaces the bound runner component. The remote START
submission owner, controller integration, ordinary release registration, and
default runtime selection are separate integration gates. This document does
not declare the whole language, CLI, or MCP controller fully rewritten.
