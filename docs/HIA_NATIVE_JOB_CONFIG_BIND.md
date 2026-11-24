# Native Worker v26 Job configuration binding

The ordinary HIA Worker installer selects mode 3 of `hia-worker-config-bind`
after installing and verifying the v26 controller. The HIA configuration owner
captures that controller receipt, checks the installed manifest and the five
Job images, and writes the selected host's complete `native_jobs` profile.
The original mode 1 roots derivation and mode 2 Worker-only binding remain
available with their original framing and behavior.

## Request and custody

The sealed 192-byte `HIAWCB01` request retains its existing layout. Its
little-endian words are:

| Offset | Mode 3 value |
| --- | --- |
| 0 | Eight-byte `HIAWCB01` magic |
| 8 | Mode 3 |
| 16 | Expected parent PID, or zero |
| 24 | Absolute monotonic deadline in nanoseconds |
| 32 | Sealed input runtime configuration FD |
| 40 | Sealed explicit roots vector FD |
| 48 | Private installation directory FD |
| 56 | Sealed native subprocess runner FD |
| 64 | Sealed controller installation receipt FD |
| 72–127 | Zero |
| 128–159 | Raw SHA-256 of input configuration |
| 160–191 | Raw SHA-256 of subprocess runner |

All five selected descriptors must be distinct and at least 3. The controller
receipt is exactly 96 bytes of `HIACTO01`, with protocol 26, file count 20,
the 32-byte controller directory identity, the 32-byte manifest digest, and
a zero final word. It is an output of the already admitted native controller
installer, passed through the Worker's explicit inherited descriptor list.

This receipt is a trusted input from the installation owner. A caller choosing
its own sealed receipt is not authenticated merely by supplying matching
hashes. The installation owner, its admitted inputs, and the runtime's separate
controller admission retain their existing trust responsibilities.

## Captured release and output

The owner derives only fixed relative names under
`controller/<receipt-directory-identity>/`. It opens paths beneath the supplied
installation directory without symlink or magic-link traversal, captures stable
single-link regular files, checks ownership and write permissions, and seals
the captured bytes. It checks the manifest digest against the receipt and
requires the exact `hepta.hia.mcp.controller.v26` schema and all nineteen named
controller entries with lowercase SHA-256 digests.

The five new executable images are then independently captured, checked
against the corresponding manifest digest, and checked for the ELF header
accepted by the runtime. The limits agree with runtime admission:

| Host profile key | Fixed basename | Maximum bytes |
| --- | --- | ---: |
| `entry` | `hia-job-entry` | 2,097,152 |
| `submit` | `hia-job-submit` | 4,194,304 |
| `observation` | `hia-job-observation` | 2,097,152 |
| `cancel` | `hia-job-cancel` | 1,048,576 |
| `launcher` | `hia-job-launch` | 1,048,576 |

The manifest limit remains 16,384 bytes. Each host profile entry contains
`executable`, the absolute installed path, and `sha256`, the admitted image
digest. The profile is inserted into or replaces `native_jobs` inside
`hosts[hia_worker.host]`. It is not a top-level runtime configuration field.
Other hosts and unrelated configuration values remain intact.

The existing six Worker identity and path fields are still bound using an
actual native installed-entry identity query. Mode 3 orders edits by their
positions in the input, so either ordering of `hosts` and `hia_worker` works.
Existing overwritten values may contain lone surrogates; preserved values
retain the original rejection rule. The existing host-map, host-array, UTF
decoding, roots, and large-input behavior is retained.

Before publication the owner reopens and checks all ten captured installation
files: the four original Worker files, the controller manifest, and the five
Job images. It publishes `runtime-config.json` with mode 0600 using the existing
exclusive temporary file, synchronization, no-overwrite publication and failure
cleanup rules. The 96-byte `HIAWCO01` response retains version 1 and its existing
configuration and Worker-profile digests.

## Qualification

`tools/qualify_hia_worker_config_bind.py` retains all 37 original cases and
the original 67,108,865-character input and 120-second request budget.

`tools/qualify_hia_worker_job_config_bind.py` adds 56 component cases using
real native images with an explicitly synthetic controller receipt. It checks
independent JSON-update parity, exact five-role configuration, overwritten
values, both object orders, indexed hosts, UTF-16 input, quoted and Unicode
paths, every role's exact size limit and immediate excess, missing or substituted
roles, missing files, image and manifest pin mismatches, ELF and file custody
failures, receipt framing and sealing, preservation of existing files, and a
configuration larger than 64 MiB. Successful traced binding executes only the
HIA owner, subprocess runner and installed Worker entry, with an empty PATH.

Native source qualification separately compiles all three source images,
compares them with the packed and retained images, checks named-source order
independence, and rejects the seven original invalid source combinations.
These are component gates. They do not substitute for an actual ordinary
Worker installation, fresh runtime public-call qualification, or the complete
final source regression suite.
