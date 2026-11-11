# Standalone native patch results

`hia-patch-result v1` and `hia-patch-result v2` consume one raw JSON array
`[BASE, PATCH]` on stdin. The required argument declares the patch schema and
must match the actual PATCH document. The executable writes the candidate Core
and the complete existing patch-result diagnostic as two opaque byte strings
in one bounded binary frame.

Two embedded HIA images perform all payload parsing, editing, diagnostic
construction and Core admission. The executable requires no Python, foreign
payload parser, interpreter, libc, dynamic loader, image sidecar or child
executable at runtime. The existing `hia-patch-core` command keeps its
candidate-JSON-only output and its existing argument contract.

## Four mandatory stages

1. Patch mode 0 strictly decodes the unchanged raw envelope and extracts
   canonical BASE. It grants no edit or publication authority.
2. The complete native Core verifier admits BASE, including declarations,
   operations, effects, ownership, returned loans and CFG.
3. Patch mode 2 checks the explicit declared schema, exact base SHA-256 and edit
   contract. HIA produces the canonical candidate and complete canonical
   diagnostic in private memory.
4. The complete Core verifier admits only the candidate slice. The adapter then
   writes the entire result frame.

An invalid original cannot be repaired past the first admission. A valid patch
cannot publish diagnostics claiming a checked candidate if that candidate fails
the final admission. Bytes written by stage 3 remain private until stage 4
succeeds. Both Core invocations retain the full primitive v1–v8 profile.

The only accepted command lines have exactly one argument, `v1` or `v2`.
The adapter maps it to workspace word `w[8] = 1` or `w[8] = 2` for mode 2.
Workspace word `w[0]` selects mode 0 or mode 2. The previous mode 0/1 kernel
contracts remain unchanged. Scratch is cleared before every image invocation;
code is RX and the anonymous data mapping is RW.

## Result frame

All header fields are unsigned, little-endian 64-bit integers. The frame has
exactly 32 header bytes, followed immediately by its two payloads.

| Byte offset | Field | Meaning |
| --- | --- | --- |
| 0 | Magic | The eight bytes `HIAPAR01` |
| 8 | Candidate length | Number of canonical Core JSON bytes |
| 16 | Diagnostic length | Number of canonical patch-result JSON bytes |
| 24 | Reserved | Must be zero |
| 32 | Candidate | Exactly the candidate length |
| 32 + candidate length | Diagnostic | Exactly the diagnostic length |

Each payload is between 2 bytes and 8 MiB. The adapter independently checks both
lengths before addition and requires `32 + candidate length + diagnostic length`
to equal the HIA kernel's returned extent. Candidate admission receives only
the candidate pointer and length. It cannot overwrite either payload because
the result region is disjoint from Core state and its decode arena. The literal
adapter does not decode, regenerate or normalize the diagnostic bytes.

The diagnostic matches the existing `hepta.hia.patch-result.v1` or `.v2`
contract, including before/after hashes, edit count, normalized edit domain,
interface changes and all claims. For primitive Core,
`original_input_sha256` identifies canonical BASE, even when stdin includes
different JSON whitespace or key order. It is not the hash of the input file.
`native_executed` remains false: the candidate program has not been run.

For v2, interface changes use the existing sorted function-name order and the
existing signature comparison, including returned-loan interfaces. Explicit
`preserve` and `migrate` retain their current meanings.
`external_callers_revalidated` remains false. The complete diagnostic is still
`verified_unpublished`; emitting a frame does not publish a durable Agent object.

## Build and use

```sh
python -B -m tools.build_hia_core_patch_result_cli \
  --compiler /qualified/B3.image.bin --cold-report /completed-cold.json \
  --output /new/private/core-patch-result
/new/private/core-patch-result/hia-patch-result v1 \
  < patch-envelope.json > checked-result.bin
```

The hosted builder requires a completed cold receipt for the complete current
source contract, all cold gates, three matching compiler generation digests,
and unchanged source/image bytes. It compiles the two payload images and this
independent HIA ELF packer. The output directory contains the executable,
`build.json`, the source-bound patch `manifest.json` and the separate
`admission-manifest.json`. Adjacency does not qualify either image.

The source packer has its own `HIARCLI1` build-frame magic and its own four call
relocations. It does not modify or extend an already built patch CLI.
Development images and local tests provide development evidence; they cannot
replace a fresh matching-source cold run after source changes.

## Limits and failures

BASE and PATCH retain their existing 8 MiB component bounds. The raw JSON
envelope ceiling remains 16,777,219 bytes, with 524,289 combined nodes and depth
129. Individual Core admission retains its existing stricter profile. The
combined result frame is at most 16,777,248 bytes.

The output region remains 64 MiB. The 96 MiB scratch reservation is reused as
64 MiB of patch workspace or 64 MiB of Core state plus a 32 MiB JSON arena.
Each embedded image retains the unchanged 1 MiB image limit. No user function,
block, arity or resource limit is reduced to the compiler's own source profile.

| Exit | Meaning |
| --- | --- |
| 0 | Both Core documents admitted and the complete result frame was written |
| 2 | JSON, snapshot, patch, declared-schema, result-frame or Core refusal |
| 3 | Wire, node, depth or output capacity |
| 4 | Descriptor I/O, mapping or invocation-profile failure |
| 64 | Missing, extra or invalid schema argument |

Stderr is empty. Input and output EINTR are retried. A successful partial write
followed by a returned I/O error leaves a frame prefix and exits 4. The caller's
signal disposition is inherited: a closed pipe with default SIGPIPE disposition
can terminate the process by signal before an exit code is returned. Callers
must require both successful completion and complete framing before consuming a
result. Stdout provides no durable file-publication transaction.

## Verification and remaining obligations

Source tests independently interpret the HIA packer and compare every output
byte. Synthetic native ABI controls separately exercise schema arguments,
scratch clearing, exact candidate slicing, reserved fields, length overflow,
extent disagreement and suppression of output on either admission refusal.
Those deliberately synthetic payload images test the adapter; they are not
HIA kernel qualification.

Actual HIA image tests compare candidate and complete diagnostic bytes with the
existing independent hosted reference, including all four edit kinds, v2
preservation/migration, returned-loan defaults, sorted interface changes and the
64-edit boundary. They cover the complete 1,024-function Core profile, malformed
and stale input, invalid originals and candidates, copied empty-PATH execution,
descriptor/mapping failures, partial writes, syscall traces and injected EINTR.

This component closes native result computation and its standalone transport.
Hosted source authoring/build, composite normalization, object/reference
custody, SQLite intent journals, crash recovery, adoption, installation and
whole-product default-runtime replacement remain separate obligations.
