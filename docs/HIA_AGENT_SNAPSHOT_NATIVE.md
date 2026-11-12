# Native Agent byte snapshots

The optional Linux x86-64 HIA kernel admits and materializes the existing
`bytes_hex` or `byte_length`/`fill_byte` borrowed-buffer descriptors. It checks
the exact field inventory and value tags, lowercase ASCII hex, even length,
1 MiB extent, and fill range 0–255. Boolean values are not integer values.
The caller still supplies separately owned buffers under the existing frozen
invocation profile; descriptors cannot carry paths, aliases or native addresses.

```sh
python -B -m tools.build_hia_agent_snapshot \
  --compiler /qualified/B3.image.bin --cold-report /qualified/cold.json \
  --output /private/new-snapshot-kernel
export HEPTA_HIA_AGENT_SNAPSHOT_MANIFEST=/private/new-snapshot-kernel/manifest.json
```

Selection is explicit administrator configuration. The default hosted path is
unchanged. An invalid selected artifact, malformed result or failed protocol
does not fall back to Python. Code source/image custody uses the existing host
trust root and immutable RX mapping, not a sandbox for arbitrary executables.

## Representation and failure boundary

The hosted caller has already decoded objects. A mechanical typed-field bridge
encodes a 32-byte version/mode/object-kind/count header followed by at most two
32-byte key/type/byte-extent/integer headers and UTF-8 payloads. Native HIA checks
the field set and chooses the error. Non-exact integers (including booleans),
negative/over-u64 integers, unsupported objects and unrepresentable/oversized
strings retain non-admissible type tags. No valid descriptor is lost: valid hex
is at most 2 MiB of ASCII. This is **not** a native JSON-object decoder.

The six-argument borrowed-buffer ABI has 64 private scratch bytes per call.
Size-only mode requires 8 output bytes; materialization requires 8 plus the
actual snapshot size. The little-endian header records that size. Status 0
means success, 1 malformed hex, 2 malformed fill, 3 wrong fields, 4 non-object,
5 insufficient output, and 4294967293 invalid internal protocol/scratch.
Every semantic, protocol and capacity check precedes any output write. Scratch
may change on refusal. The runtime bridge materializes only admitted bytes.

Independent Core VM observations precede any native seed. Tests include real
B0/B1/B2 fixed-point compilation, full 1 MiB materialization, generated valid and
invalid descriptors, Unicode/type/error parity, actual hosted argument callers
with both reference routines disabled, short-output canaries, malformed wire,
concurrent calls and failed artifact selection. These are finite observations,
not an all-input proof or a fresh whole-product acceptance.

Hosted decoding/transport, request dispatch, editing, persistence and filesystem
authority remain Python-dependent. The builder and custody path are also hosted.
This component does not close durable Agent transactions, native module/build
or runtime/library coverage, native-only installation, lifecycle/recovery or
clean-machine real-project acceptance. It changes no live service or default.
