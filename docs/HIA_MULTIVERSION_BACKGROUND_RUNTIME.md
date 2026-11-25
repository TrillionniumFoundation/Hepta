# Native multiversion background provider

This checkpoint qualifies the fixed native provider used by the background optimizer. It executes the actual native runtime with captured normalizer, primitive proof and builder images. It does not close the full public runtime, all original exception mappings, or the complete background optimizer.

## Entry and ownership

The shared object exports `hia_mv_background_runtime` with the existing six-word source/output/workspace ABI. The immutable request is `HIAMVBQ1`; the exact field layout remains in [HIA_MULTIVERSION_BACKGROUND_RUNTIME_ABI.md](HIA_MULTIVERSION_BACKGROUND_RUNTIME_ABI.md). Output is at least 128 bytes and the process-owned persistent context is at least 1,024 bytes. The five operations are actual lock-consistent snapshot, conditional publication using the original Future token, independent runtime clone, runtime drop, and owned-reply drop.

Every snapshot/publication takes an independent strong reference before inspecting the runtime object. The provider holds this reference throughout preparation, selection and result capture. The caller can concurrently drop its last public reference. Active calls prevent context destruction. Replies are independent immutable payload capabilities and remain valid after the runtime has retired until their own final drop. Arbitrary pointers are not a public API: registry membership and fresh node nonces are verified before object dereference.

There is no u64 generation, selection-epoch or reference-count surrogate. Expected generation and epoch are canonical decimal strings; the actual 21 MiB + 1 digit case remains accepted as a stale comparison. Publication uses the original selected generation, epoch, immutable baseline, real same-token commit and actual preparation result.

## Budget and selection order

The provider now records actual monotonic entry time before allocation, strong-reference acquisition and decimal scanning. The additive private `HIAMVEX4` operation 2 places this captured time at byte 216; effects verifies it against its own fresh clock and retains it as the preparation start. The original three effect request magics remain unchanged. Original explicit handoff time, measured-publication rules, preparation budget, stale checks and Future commit behavior are not renewed at the boundary.

The actual counterfactual gate delayed provider allocation by 200 ms under a 100 ms original budget. Both images reject with the original timeout text and leave the token uncommitted. The previous image had already consumed a new generation before rejecting; the fixed image rejects before preparation. A subsequent real successful publication proves the distinction by selecting generation 2 versus generation 1.

## Qualification

| Actual group | Result |
| --- | --- |
| Constructor, proof, build, load, snapshot, same-token publication and final ownership | 8 groups; 18 provider calls |
| Concurrent clones/snapshots, two writers, last user drop during preparation and 21 MiB decimal | 5 groups; 1,086 calls; 140 transactional private refusals |
| Native allocation failures before and after commit | 7 cases; 50 provider calls; every injected case balances allocation and release |
| Native pack/link and exact bounds | 135 gates; 48 roles; original 4 MiB per-role and 16 MiB text bounds |
| Actual entry-time counterfactual | 2 cases using a real delayed malloc effect |
| Legacy effects on the same new policy | 17 original actual-effect groups |

The image is 8,020,752 bytes, SHA256 `64a092a0b4bd028d37c9c815e08cb892a59c458b08e2c67351bcf565f06991a0`. Its 48 role pins, actual native packing and linking receipts, complete individual reports and development qualification programs are preserved in [HIA_MULTIVERSION_BACKGROUND_RUNTIME.json](HIA_MULTIVERSION_BACKGROUND_RUNTIME.json).

## Errors and remaining obligations

Structured result status 1 currently carries the original MultiversionRejected messages for closed runtime, stale generation/epoch, preparation timeout, cancellation, already-committed token and live-selection budget. Status 2 represents an actual allocation failure. Status 3 is an explicit unclassified dependency/internal failure; consumers must not relabel it as MemoryError or assert that selection did not occur. In particular, real token state 2 and the committed field survive an output allocation failure after selection.

The remaining original profile/proof/OS exception details must be captured and mapped before declaring the original public exception surface complete. Full runtime history and snapshot capture, including retirement's last-attested state and actual loader error string, remain separate open work. None of the component results sets a whole-product flag.

## Source construction

The new runtime sources are `multiversion_background_runtime.hepta`, its HIA packer, and the readable mechanical bridge `tools/hia_multiversion_background_runtime_bridge.S`. Existing `multiversion_runtime_effects.hepta` gains only the explicit entry-clock request. The packet is `HIAMVBK1` with provider and payload followed by the 46-role runtime-handle closure. The fixed linker accepts the same five imports: dlopen, dlsym, dlclose, malloc and free.

Author Python and fault-injector C files are development evidence only. Product construction uses actual HIA compilation, the HIA packet packer, and the closed HIA shared linker; no hosted business implementation executes inside the provider.
