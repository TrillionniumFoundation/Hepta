# Original float artifact byte readback

The existing native float workflow at commit `44dd9edebacdf1a7c22b9c8a4df0d0828ef1edd8` completed on its two named hosted platforms in run `41644357962`, attempt 1. This independent read-only job verifies the original two 1,443-byte ZIP artifacts. It does not rerun the tests, compilers or any archived source.

The input file pins artifact IDs, digests, byte counts, original jobs, exact source commit/tree and four original source paths. The reader fetches those source bytes by immutable commit, checks Git blob/SHA-256/size, and parses the test syntax to bind the exact 23 test names. Each artifact must contain exactly `compilers.txt` and `tests.log`, pass ZIP CRC and size checks, contain all 23 distinct original successful cases with the complete unittest summary and no skip/failure, and preserve the pinned Rust 1.90.0 compiler record and both recorded compiler digests.

API requests cannot redirect with their Authorization header. The signed archive URL is used only by a fresh HTTPS request without that header and is never printed. The reader does not extract ZIP paths or execute members. Compressed, returned decoded-member and derived-output byte limits are explicit; they are not general process-RSS guarantees. Output contains fixed public identities, exact member hashes, verified test names and normalized compiler metadata. No raw log payload or signed URL is published.

The workflow runs only on this independent research branch with contents/actions read permissions. Its own three operative tracked files are compared with Git bytes before and after the readback. Synthetic rejection controls validate the reader itself and are labelled separately from the historical native cases.

A successful readback closes only this original-artifact integrity gap. It does not independently rebuild every transitive original compiler input, rerun historical binaries, prove all HIA P0–P7 or HCSN P0–P6 acceptance, authorize production, or satisfy Library clearance. The existing product branch is unchanged.
