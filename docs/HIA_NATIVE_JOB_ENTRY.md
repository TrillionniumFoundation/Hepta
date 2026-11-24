# Native fixed job entry

`hia-job-entry` is the fixed Linux x86-64 native bootstrap selected by the host
administrator. It admits one of three installed job owners or the systemd
launcher carrier, checks the complete received image against its expected
SHA-256, seals the image, and executes the sealed descriptor with `execveat`.
Its HIA policy owns all admission, bounds, decoding, hashing, descriptor
inheritance and argument selection. The assembly adapter only copies initial
arguments/environment, dispatches requested Linux syscalls, relocates bounded
pointer tables and invokes the two compiled HIA images.

The installed entry path itself is part of the administrator-selected trusted
computing base. An asserted digest of that path is an installation binding,
not a claim that a process can protect its own pathname from later replacement.
Controller code must obtain target images from its verified Store and expected
pins from a complete host configuration. Public job requests must not select a
program path, target image, target digest, operation outside the typed interface,
or arbitrary entry arguments. The entry does not hash a target pathname and
then execute that pathname.

## Stream request

With exactly one process argument (the entry executable), stdin contains a
96-byte little-endian header followed by one raw ELF and one raw payload:

| Field | Width | Meaning |
| --- | --- | --- |
| magic | 8 bytes | `HIAJEX01` |
| operation | u64 | 1 submit, 2 observation, 3 cancellation |
| image length | u64 | 64 through 4,194,304 bytes |
| payload length | u64 | Operation-specific exact extent |
| image digest | 64 bytes | Lowercase hexadecimal SHA-256 |
| image | declared extent | Complete target ELF bytes |
| payload | declared extent | Complete target stdin bytes |

The declared extents must be followed by EOF. Truncation, trailing bytes,
noncanonical digests and arithmetic overflow are refused before target execution.
The image must have the expected ELF64 little-endian x86-64 executable header.

| Operation | Payload limit | Admitted prefix and flags | Fixed target argv |
| --- | --- | --- | --- |
| 1 | 64 through 545,259,584 bytes | `HIAJSB01` | `hia-job-submit` |
| 2 | 80 through 65,536 bytes | `HIAJOBQ1`; mode 0/flags 0 or mode 1/flags 63 | `hia-job-observation` |
| 3 | 80 through 2,162,688 bytes | `HIAJCQ02` | `hia-job-cancel` |

The maximum submission payload is 520 MiB plus its 64-byte header, preserving
the separate metadata, helper image and stdin limits of the submit owner.
The selected owner validates all remaining semantic fields. The entry captures
image and payload into separate memfds, verifies `F_GET_SEALS` after adding all
four seals, and maps the sealed payload to fd 0. Image bytes are hashed while
streaming through 64 KiB chunks. A 520 MiB request does not require a 520 MiB
entry buffer. Target image descriptors close on execution; unrelated descriptors
at or above fd 3 are marked close-on-exec before the fixed target is entered.

## systemd asynchronous launcher carrier

The second mode has this exact argument shape:

```
hia-job-entry --launch-base64 SHA256 JOBDIR BINDING CHUNK [CHUNK ...]
```

The administrator-bound entry path is stored directly in the transient systemd
command. The submit owner supplies the launcher bytes and digest through that
command's arguments. systemd retains those argument bytes independently of the
submitting process, so the original asynchronous `Type=simple` behavior does not
rely on a parent `/proc/PID/fd` path remaining alive. The entry never opens the
launcher by a supplied path.

`SHA256` is exactly 64 lowercase hexadecimal bytes. `JOBDIR` is an absolute,
nonempty string of at most 4,096 bytes. `BINDING` is nonempty and at most 8,192
bytes. Its interpretation remains the launch owner's responsibility. Nonfinal
base64 chunks contain exactly 65,536 characters (49,152 raw bytes); the final
chunk contains 4 through 65,536 characters, with length divisible by four.
Only the final quartet of the final chunk may contain canonical `=` padding.
The decoder checks unused padding bits and rejects whitespace, URL-alphabet
variants and interior padding. Total decoded image size is 64 through 1 MiB.

After complete digest and ELF verification and sealing, the entry executes
exactly `hia-job-launch`, `JOBDIR`, `BINDING`, `systemd` as the four target
arguments. It does not read or replace stdin in this mode. The inherited host
environment remains available to the target; target job environment policy is
owned by the launcher. There is no arbitrary program or argument pass-through.

## Shared bounds and failure behavior

The mechanical initial frame permits at most 128 arguments, each at most 65,536
bytes, and at most 128 environment records, each at most 8,192 bytes. The complete
encoded initial frame is bounded by 2 MiB. HIA independently validates all frame
extents and NUL terminators. Its state is 2 MiB and the mechanical argument frame
is separately bounded. Refusals return status 65 without output or target exec.
After an accepted exec, the target's own exit and output behavior is unchanged.

## Source closure and qualification

The policy is `job_entry.hepta`; the only companion is `sha256_stream.hepta`.
`job_entry_packer.hepta` accepts `HIAJEK01`, two u64 flat lengths, then policy and
SHA flats. The product is a static ELF bounded by 2 MiB. The checked-in authoring
source and syscall template regenerate both HIA files; host authoring tools do
not run in the resulting entry or target execution chain.

`tools/qualify_hia_job_entry.py --entry ELF --output NEW_DIRECTORY` exercises
both modes using small native probes that check their actual fixed argv,
executable seals and stdin handling. The gate includes maximum stream/image
bounds, canonical base64 cases, complete-image mutation, truncated/trailing
frames, overflow, role mismatch and malformed argument controls. Traces verify
sealed descriptor execution and that the launcher carrier does not read stdin
before exec. These probes establish bootstrap custody and transport; the submit,
observation, cancellation and launcher owners retain their independent original
oracle qualifications and the final installed public-tool campaign.
