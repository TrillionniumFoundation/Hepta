# Separate cold seed profiles: actual component qualification

The new cold bulk and endian profiles remove only identity transfers from
both passes of an admitted block-edge parallel copy. Their original parent
profiles remain unchanged. The transformation and its limits are explained
in `docs/HIA_COLD_SEED_EDGE_PROFILE.md`.

All results here are finite component observations. **A full cold, source
release, installation and installed rebuild have not been qualified by these
records.** The previous ROG and GitHub Actions cold timeouts remain failures.

## Actual native results

| Qualification | Result |
| --- | --- |
| New cold bulk seed | 463 independent wire cases, 13 original rejection observations and 5 actual SIGILL / partial-write cases pass; B1 from original v1, B2 equals B3 |
| New cold endian seed | The same complete 463 / 13 / 5 cases pass; B1 from original v1, B2 equals B3 |
| Original bulk and division/bulk | Both original B1 == B2 == B3 gates pass; each retains 420 fill/DF cases, 10 original traps, null-empty, alias and mixed-operation controls |
| SHA | Complete original native qualifier passes, with 27,043 group-counted observations including concurrent/copy checks; all original arbitrary-u64, padding and boundary cases retained |
| Foreign offset aliases | 2,000 complete owner-buffer comparisons pass with unchanged canaries |
| Codec | All original 45 cases, entry/chunk boundaries, 1,000 random/structured chunks, 2,000 grammar mutations and the separate 2,028 complete 4 MiB malformed/overlap comparisons pass |
| Retained failed-run samples | 19 actual encoded samples, all 57 pack/decode/fingerprint full-workspace comparisons pass; canonical packed bytes remain exact |
| Actual entry preparation | 53 independent native invocations / 14 source pins pass; constructed seed and SHA bytes equal the independently qualified images |

The constructed driver becomes 378,122 bytes instead of 550,238 bytes.
The exact alias-dispatched SHA image becomes 107,635 bytes instead of 116,455.
Its original alias fallback remains unchanged. Seven interleaved finite local
sample timings show roughly 1.8–2 times faster LZ packing and 1.4–1.7 times
faster decoding on the selected larger original samples. SHA gains are smaller
and timing varies. These are component measurements on exact retained samples,
not a prediction or claim that the 180-second full cold deadline passes.

## Original observations and failed fixture retained

`native-component-evidence.tar.gz` is 2,502,348 bytes, SHA-256
`b12eed4f6a694f0ac9f15162575a2ae775511b340fe86e6f682dd2310fe59f84`.
Its 59 members include every raw qualification observation stream, native
construction receipts, exact SHA images, actual journal samples, the unchanged
old codec probes, the experiment driver and complete per-file hashes.

The first new direct-wire fixture incorrectly placed an edge's argument list
before the edge record. The original parent compiler refused that malformed
wire before any candidate comparison. That failed run and its exact original
fixture source remain in the archive as `original-refused-fixture`. The
corrected fixture uses the original wire boundary layout; no product admission
rule was changed. The subsequent complete qualification is retained separately.

The development source was prepared above exact base `cd2002be2f`; the original
component reports bind the actual source bytes directly. Their temporary paths
and all original pass/fail fields are preserved. Neither an intermediate Git
head nor a source-only check is substituted for a native cold receipt.
