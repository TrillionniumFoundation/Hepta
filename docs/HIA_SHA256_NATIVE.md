# Bounded HIA SHA-256 library

**Whole-stack rewriting remains OPEN.** Five functions in
`examples/hia_bootstrap/sha256.hepta` implement SHA-256 message padding,
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

## Exact implementation qualification

Implementation `d6e94a90a9312591db036a4245b7a4a4a1a32e67` passes actual clean committed source recovery and
98 source tests, cold 11/11 plus 4,351 native compiler observations in
170.913 seconds under the unchanged 180-second deadline, language 1,242/1,242
and 10 report assertions, 33 native SHA/JSON tests, 83 explicitly installed
consumer tests, 83 default consumer tests and 55 selected-backend incremental
tests. All qualification steps preserve the clean source checkout.

Finite receipts are retained in `sha256-native-library-summary.json`; the
static whole-stack inventory reconstructs byte-for-byte from v28 plus
`implementation-boundary-sha256-delta.json`. Current-source full-repository
regression remains a separate requirement; the older v31 run cannot qualify
this implementation. No release lock, main branch or production runtime is
promoted by these library observations.
