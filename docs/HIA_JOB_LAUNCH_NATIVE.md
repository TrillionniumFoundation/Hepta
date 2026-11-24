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
directory functions from a supplied v25 runtime jobs.rs, builds the original
static subprocess fixture, and executes fresh original/native pairs. A native
case receives an empty PATH and an exec trace. It must execute only native
images. The comparison covers child admission, complete workload streams,
terminal fields, native receipt length, and witness binding.

The first full qualification passed 94 original/native pairs, including:

- all sixteen authority flags and changed job, directory, nonce, and image pins;
- arguments and environments at their original count/byte boundaries;
- Unicode and filesystem surrogateescape transport;
- physical-root containment, repeated symlinks, a 48-link chain, and cycles;
- deadline and cancellation through the actual native supervisor;
- eight metadata encodings, duplicate keys, nonfinite extra values, and the
  exact encoded metadata limit;
- the exact 512 MiB stdin and 64 MiB workload limits and their immediate refusals.

The qualified ELF SHA256 was
`850d0b444e484d2418e6baa893c46bf979aaca6962a37dd4a9622b7707e6c235`
(589990 bytes). Qualification outputs are external to the source tree.

This checkpoint replaces the bound runner component. The remote START
submission owner, controller integration, ordinary release registration, and
default runtime selection are separate integration gates. This document does
not declare the whole language, CLI, or MCP controller fully rewritten.
