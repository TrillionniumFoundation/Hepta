# Native JSON snapshot application

The explicit Linux x86-64 `hia-snapshot-json` application reads a single JSON
descriptor from stdin and writes only its admitted snapshot bytes to stdout.
JSON parsing, decoded-key duplicate rejection, exact descriptor admission and
byte materialization execute in HIA. No Python object transport, foreign JSON
decoder, libc or second executable is required at application runtime.

```sh
python -B -m tools.build_hia_agent_snapshot_json \
  --compiler /qualified/B3.image.bin --cold-report /qualified/cold.json \
  --output /private/new-snapshot-json
printf '%s' '{"bytes_hex":"0061ff"}' | /private/new-snapshot-json/hia-snapshot-json
```

The builder requires a completed matching-source cold receipt. It compiles the
checked-in HIA application and HIA ELF packer with that compiler. The packer
emits ELF headers, patches the relative entry call and copies the image. The
literal syscall/ABI glue template is hosted authoring input; it contains no
JSON or descriptor parser. Build orchestration, manifests and image custody
remain hosted. This is not native-only installation or a full Agent server.

## Wire and memory boundary

Input is at most 8 MiB, with at most 1,048,576 decoded nodes and depth 128.
UTF-8, escapes, trailing data and duplicate decoded keys are checked by the
existing HIA decoder. The root must contain exactly `bytes_hex`, or exactly
`byte_length` and `fill_byte`. Hex must be lowercase ASCII and even-length;
decoded snapshot size is at most 1 MiB. Fill length is an integer in
0–1,048,576 and fill byte an integer in 0–255. Booleans and floats are not
integers; JSON integer `-0` denotes zero. Escaped key/value spellings are
checked after JSON decoding. No paths, addresses or external buffers are
accepted.

The standalone application privately maps 88 MiB + 8,192 bytes: input plus
guard space, a 64 MiB + 4,096 byte decoded/output arena, and 16 MiB workspace.
It first decodes into the output arena, admits the complete descriptor, then
materializes bytes in place. Thus the **raw ABI arena may change on refusal**;
it is scratch until success, unlike the typed-field snapshot kernel's
no-output-on-refusal ABI. The Python bridge likewise keeps that arena private
and returns only successfully admitted bytes. It never decodes payload JSON.

Raw status 4,294,967,295 means invalid JSON/descriptor; 4,294,967,294 means
capacity refusal. Success returns the payload length, including zero for an
empty snapshot. Standalone exits are 0 success, 2 invalid, 3 capacity,
4 I/O/mapping failure and 64 unexpected arguments. Invalid descriptors publish
no stdout bytes. Accepted output is **not atomic**: a later I/O failure can
leave a prefix on stdout. Reads/writes retry EINTR; inherited signal behavior,
including SIGPIPE, is unchanged.

## Acceptance boundary

Independent Core VM parsing/packing controls precede native B0 compilation.
Tests compare B0/B1/B2 fixed points, VM/native packer bytes, 1,000 generated
descriptors, full 1 MiB snapshots, escaped and duplicate keys, refusal guards,
private concurrency, source-bound image selection, rejected failed cold
receipts, a copied ELF with empty PATH and syscall tracing, actual injected
EINTR and a real nonblocking partial-write failure. These finite controls do
not establish an all-input proof or whole-product acceptance.

Existing default Agent dispatch and its typed-field snapshot selection remain
unchanged. Agent editing, durable transactions/recovery, full runtime/library
coverage, native module/build integration, clean-machine native installation
and real-project acceptance remain open. No live service is switched.
