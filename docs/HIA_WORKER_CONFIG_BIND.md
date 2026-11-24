# Native Worker runtime configuration binding

`hia-worker-config-bind` derives artifact roots and binds a runtime configuration
to an installed Worker. Both the decision owner and its JSON reader are HIA
programs. The ELF links their native objects with `sha256_stream`; its assembly
adapter only transports syscall requests and calls the linked native objects.
The Python authoring and qualification tools are outside this execution path.

## Input capabilities and output

The executable takes no arguments. Descriptor zero is a sealed 192-byte request
with magic `HIAWCB01`. Integers use unsigned little-endian 64-bit encoding.

| Offset | Field |
| --- | --- |
| 8 | Mode: 1 derives roots; 2 binds a Worker configuration |
| 16 | Parent PID, or zero for the admitted current parent |
| 24 | Absolute monotonic deadline in nanoseconds |
| 32 | Sealed configuration descriptor |
| 40 | Sealed explicit-root vector descriptor |
| 48 | Private installation directory descriptor; zero in mode 1 |
| 56 | Sealed native subprocess-runner descriptor; zero in mode 1 |
| 64 | Optional empty output descriptor for mode 1; zero in mode 2 |
| 72–127 | Reserved zero bytes |
| 128–159 | Raw SHA256 of configuration input bytes |
| 160–191 | Raw SHA256 of the runner, or zero bytes in mode 1 |

Mode 1 returns the normalized root vector directly, or writes and seals the
supplied output descriptor and returns a 64-byte `HIAWCR01` receipt binding its
length and SHA256. Root order and duplicates remain significant. Explicit and
configuration-derived roots must agree when both are supplied.

Mode 2 captures immutable copies of the installed entry, profile, descriptor,
and capsule. It verifies the capsule roots and profile identity, invokes the
real installed Worker through the native subprocess supervisor, and uses its
manifest query to replace these six fields under `hia_worker`:

- `worker_sha256`
- `backend_sha256`
- `catalog_sha256`
- `native_helpers_sha256`
- `python_executable` (the existing compatibility key for the native entry)
- `native_helpers_manifest`

Other configuration values are preserved. The owner writes a private exclusive
temporary file, synchronizes it, rechecks the captured installation identities,
and publishes `runtime-config.json` without replacing an existing output. The
result has mode 0600. Its 96-byte `HIAWCO01` receipt binds the output length,
output SHA256, and installed profile SHA256. Failed publication removes only
the temporary file created by this attempt; pre-existing output and temporary
files are preserved.

## JSON and path behavior

Configuration input has no fixed 64 MiB ceiling. The reader transcodes the
supported UTF-8, UTF-16, and UTF-32 byte encodings and sizes parser storage from
the actual input. It preserves the existing numeric and lexical behavior,
including the integer digit bound, non-finite numeric atoms, host selection
from objects and arrays, escaped key equality, and duplicate-key refusal.

Artifact-root conversion retains POSIX lexical behavior: redundant separators
and single-dot components collapse, `..` remains lexical, exactly two leading
slashes remain two, and supported surrogate-escaped path bytes are preserved.
This conversion does not authorize a filesystem path. Configuration strings
that would leave an unpaired surrogate in the published UTF-8 document are
rejected; surrogate values in the six replaced fields do not survive and are
therefore accepted.

Parser cursor and metadata accesses use the native v9 `buffer.load.u64.le` and
`buffer.store.u64.le` operations. Ordinary ASCII decoding avoids redundant
UTF-8 decoder calls. These operations preserve full-width offsets and the
original grammar while avoiding eight separate byte loops for every cursor
access on large strings.

## Reproduction and qualification

`tools/generate_hia_worker_config_bind.py` renders the owner, private JSON reader,
and packer. The checked-in `.hepta` programs are compiled and packed by the
native source builder; no Python or assembler executes during that native
compilation and packing path.

`tools/qualify_hia_worker_config_bind.py` accepts explicit `--elf`, `--runner`,
`--installation`, and `--output` paths. It executes the real native component
with an empty `PATH`, independent sealed inputs, and the real installed Worker.
Its 37 cases retain the 120-second owner deadline and include two inputs larger
than 64 MiB, path and encoding compatibility, all six replaced fields, unrelated
value preservation, descriptor seals and aliases, wrong hashes, decoded
key duplicates, changed installation files, unsafe directories, and existing
publication paths. A traced successful binding executes exactly the binder,
native supervisor, and native Worker. The component gate is separate from the
complete source/cold/Store/Worker installation qualification.
