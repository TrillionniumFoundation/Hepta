# Bounded HIA SHA-256 library

**Whole-stack rewriting remains OPEN.** Five functions in
`examples/hia_bootstrap/sha256.hiaasm` implement SHA-256 message padding,
big-endian word decoding, the 64-word schedule, 64-round block compression and
digest serialization as ordinary HIA operations. The native payload path does
not call Python `hashlib`, OpenSSL, a foreign hash primitive or a C hash helper.
The authoring generator is a host development tool, not the executing algorithm.

The source accepts 0..8 MiB of immutable bytes, writes exactly 32 digest bytes,
and needs 1,088 private workspace bytes. It uses fixed 32-bit masks over native
u64 arithmetic, with explicit rotations and all message/padding bounds checked.
An out-of-profile input or short output/workspace returns `fffffffd` before any
write. No hidden heap is used by the HIA algorithm; host buffer allocation and
executable image loading remain Python. This is a one-shot byte library, not
streaming I/O, HMAC, a password KDF or a rewritten production runtime.

## Build and select

```sh
python -B -m tools.build_hia_sha256 \
  --compiler /path/to/B3.image.bin \
  --cold-report /path/to/completed-cold.json \
  --output /new/private/sha256-directory
```

The builder requires a completed matching cold compiler receipt and records
source, compiler and native image SHA-256. It does not activate a backend. Set
`HEPTA_HIA_SHA256_MANIFEST` to its local manifest to use HIA for bounded Core
`VerifiedProgram.sha256` and `input_sha256` payloads. The unselected path remains
the original reference, unsupported inputs preserve the original foreign API,
and invalid selected artifacts fail closed. The manifest is operator-selected
trusted executable code, never selected by submitted payloads.

Existing host SHA-256 still checks code identity and compiler/artifact custody;
those are trust-root operations, not a claim that all repository hashing is now
HIA. Other source hashing, proof/receipt code, runtime/library functions, object
bridges, CLI, build and installation tools are not replaced by this library.
Finite FIPS/vector/random/boundary/bit-mutation/concurrency observations do not
prove cryptographic security, all-input refinement or whole-stack closure.
