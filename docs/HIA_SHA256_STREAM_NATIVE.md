# Incremental SHA-256 in HIA

`examples/hia_bootstrap/sha256_stream.hiaasm` implements initialization,
partial-block accumulation, SHA-256 compression, 64-bit bit-length padding and
digest serialization in HIA. The 1,184-byte private state and each at-most-8-MiB
update are bounded; the stream itself is not limited to one 8-MiB input. It
accepts up to 2^61-1 total bytes, the byte-aligned SHA-256 length bound. No all-input
cryptographic correctness or security proof is asserted by finite tests.

## Native state protocol

The existing disjoint `(readbuf, mutbuf, mutbuf) -> u32` ABI receives a command,
a digest destination of at least 32 bytes and the private mutable state.

- `00`: initialize; exactly one command byte, returns zero.
- `01 || bytes`: update; 0..8 MiB data bytes, returns zero.
- `02`: finalize; exactly one command byte, returns 32 digest bytes.

Invalid sizes, commands, phase, total-length overflow or inconsistent pending
length return `fffffffd` before writing state or output. Finalized states reject
updates and repeated finalization. Initialization resets the stream. The private
state is not an authenticated checkpoint or a portable serialized protocol;
callers must not mutate it or concurrently operate on the same state.

`NativeSha256Stream.new()` provides `update(bytes)`, `copy()`, `digest()` and
`hexdigest()`. `digest()` finalizes a private copy, so the source stream can be
read repeatedly or updated afterwards. Distinct contexts have disjoint state.
Python owns allocation, command construction, loading and chunk scheduling;
the executed hash/padding/state algorithm is HIA, not Python/OpenSSL.

## Explicit candidate build and selection

```sh
python -B -m tools.build_hia_sha256 --candidate sha256_stream \
  --compiler /path/to/B3.image.bin --cold-report /path/to/cold.json \
  --output /new/private/sha256-stream
```

Set `HEPTA_HIA_SHA256_STREAM_MANIFEST` to the produced local `manifest.json` to
select incremental native HIA for existing bytes-valued Core payload hashes,
including inputs larger than the old one-shot profile. This explicit selection
takes precedence over `HEPTA_HIA_SHA256_MANIFEST`. Invalid selected manifests
fail closed. Unsupported foreign Python input types retain the original API;
without selection the existing default is unchanged. The trusted manifest is
operator-local executable selection, never a submitted-wire option or sandbox.
Artifact/source identity hashes still use the separate host trust root.

## Whole-stack retirement boundary

**Whole-stack rewrite and old-stack retirement are still OPEN.** This library
does not replace the Python compiler/verifier, object bridge, runtime, worker,
module/build/install/release authorities or Rust/C/Lean implementations. Those
may be retired only after their HIA replacements pass full conformance and
negative controls, default paths are switched without legacy fallbacks,
source-only complete-toolchain bootstrap and modified-source rebuild pass,
fresh full regressions/cross-platform gates pass, and clean-machine real-project
build/install succeeds without the legacy toolchain. The final deliverable must
exclude old production implementations, not merely hide them behind flags.
Git history and non-shipped review evidence preserve recovery/audit custody;
no legacy code is deleted by installing this candidate.
