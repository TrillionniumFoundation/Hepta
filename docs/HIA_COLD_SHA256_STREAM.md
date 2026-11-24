# Separate cold SHA compression profile

This profile is a separate pure HIA incremental SHA-256 implementation for cold
qualification tools. It preserves the original six-argument entry and 1,184-byte
state layout, 8 MiB maximum update chunk, 2^61 - 1 maximum total length,
initialization, byte update ordering, finalization, refusal-before-write rules,
and output behavior. The original sha256_stream.hepta is unchanged.

Only compression implementation is transformed: the helper for constant rotates
is expanded exactly (including the unmasked right-shift arm for noncanonical
full-u64 state), word reads use the existing word_load operation, each word write
expands into the same eight ordered byte stores, and the initial big-endian
four-byte decode loop is expanded. No new instruction, algorithm, state size,
compiler capacity, or acceptance condition is introduced.

## Independent construction

Both the original and new actual native flat images were constructed from their
HIA sources by the fixed independent HIA assembly frontend, HIA reference
projector and original HIA seed backend. The target self-host compiler and its
successor images did not participate. The captured build report records each
source, Core, projection, executable, and tool hash.

The new source has 4 functions, 57 blocks and 1,229 operations. Its independently
constructed flat is 48,349 bytes, SHA-256
d22c50dca15cf0b530b02e3c9aac4f73ccf2dbf371fd3597b28081cf3d9f4c34.

## Actual qualification

The qualification compares every byte of the source, output and state for
26,903 native transitions between the previous and new actual native entries,
with guards before and after all buffers. The original full-u64 state ABI is
tested, rather than restricting to canonical SHA state. A fresh independent
original Core VM supplies 54 complete public-transition witnesses and 6 separate
foreign-pointer alias witnesses. The alias tests are ABI stress cases, not
claims that those overlapping views are admitted affine Core programs.

The original three FIPS vectors, all original 16 padding lengths with every
split, repeated digest/copy/update behavior, one million 'a' bytes, 1,000 seeded
random partitions, all public protocol refusals, exact and exceeding chunk
boundaries, and streams larger than the former one-shot limit are retained.
Additional 256 noncanonical full-u64 state transitions check the optimization
outside standard hash states. All 128 concurrent private-state operations and
6 copy/reuse groups pass. Total recorded checks: 27,043.

The standard hash expectations are computed outside the product by hashlib.
The product executes the independently constructed HIA code; the Python harness
only allocates test buffers, invokes both entries, and compares observations.
These finite witnesses are not an all-input refinement proof.

## Measured performance

One measured pass on the same ROG host, including normal high-level stream setup:

| Payload | Previous native | New native |
| --- | ---: | ---: |
| 1 MiB | 0.085820 s | 0.053409 s |
| 4 MiB | 0.349219 s | 0.213099 s |
| 8 MiB | 0.686963 s | 0.427203 s |

The 8 MiB case improves from 11.65 to 18.73 MiB/s. There is no new performance
acceptance threshold and no change to the original cold replay deadlines.
This component evidence does not claim completion of the final cold master.

## Reproduce the native comparison

Run the external qualification observer with the two independently constructed
flats and a new evidence directory:

    python3 -m tools.qualify_hia_cold_sha256_stream --old OLD.flat --new NEW.flat --output NEW_DIRECTORY

The machine-readable qualification index alongside this document records the
fixed source and image hashes, the complete build evidence and the report paths.
