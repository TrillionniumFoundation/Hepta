# Complete record decoding and metadata cohort checkpoint

The direct native decoder consumes every byte of each canonical record and preserves the complete 256-byte decoded representation. Noncanonical spelling, escapes and other unsupported direct shapes use the existing full decoder. All 3772 cases match the separately compiled original Rust decoder: 949 direct and 2823 full fallback. Original Rust execution, source-construction payload and raw observations are retained.

The same native source passes 178 real/public and continuation controls: native 30, continuations 60, archive 37, usage 22, HTTP 23 and parallel-public 6. The parallel fixture contains 16385 retained records. The fixed 1/2 ms collection windows, maximum 8 members and original 3-second query deadline are unchanged. Actual observed cohort sizes are in the raw report; this does not assert that every HTTP cohort collected all eight callers.

The earlier parallel failure remains beside the successful original-method run. Complete raw output/product archives are read back and hashed. All construction sources bind to the exact source commit in the manifest.

This is a component checkpoint. Pending-index cap/watermark/read-only tail and the two original-reader lanes remain open. The separately qualified PR980 B3 source fix has not yet been merged into this source. Whole cold/release/install/rebuild remain false.
