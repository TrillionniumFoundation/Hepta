# Native cold journal result field boundaries

The plan executor retains the same complete `HIAQJL01` logical stream. This change partitions a process result at its existing `HIAQRR01` field boundaries before applying the existing native codec and exact current-journal back references. No process result, allocation event, shared byte, failure field, or plan node is omitted or reused from another execution.

The seven end offsets separate the 64-byte header, full process receipt, stdout, stderr, first up to eight shared bytes, remaining shared bytes, and original request. The original 16,384-byte maximum still applies within every segment. Empty fields cause no empty chunk. Header extent arithmetic uses `amount <= size - position` before every addition. A malformed or unknown partition header falls back to the original entire-result chunking; it does not create a new acceptance or rejection rule.

The executor reads the header from its actual sealed result descriptor. Partition state is cleared at every node, and becomes active only after the complete header extent is consistent. Temporary header bytes occupy 62064..62127; the flag, cursor and seven ends occupy 1501200..1501271. The existing 4 MiB workspace, 8,192-entry current-phase cache, all node limits, and all process and archive capacities remain unchanged.

Every chosen chunk is still actually encoded, decoded, and compared in full. A back-reference hit still requires the private original encoded SHA, the actual prior encoded read and full byte comparison, and another independent decode against the current raw bytes. The journal stream hash, fsync/readback hash, immutable archive snapshot and all archive custody passes remain in place. The physical formats remain AZ01, AZ02 and AZ03; existing readers require no change.

## Evidence

The source was constructed through the independently pinned native assembly, projector and bulk seed. Both resulting flat modules exactly match the independently projected construction. The old SHA and the qualified fused-schedule SHA combinations each pass all 18 original driver controls. There are 350 partition/extent cases and 16 stale-control fallback cases, including full u64 overflow values, empty and consecutive zero spans, shared extents 0 through 9, wrong final sizes and unknown headers. Full-workspace canaries outside the private control region remain unchanged.

The actual unchanged base plan has 3,394 nodes; the actual unchanged signed plan has 22,544 nodes. Both were executed afresh with the old and new consumers. Each signed run consumed its matching fresh base products. Every published byte matched the previous actual program products, and both native archives verified all files in full. The component comparison uses prior independent-reference publications as explicit inputs and is not a replacement for pre-B0 references in a full cold run.

With the qualified fused SHA companion included, base driver time was 14.818 s old versus 14.928 s new, while archive time was 2.731 s versus 2.291 s. Signed driver time was 21.365 s versus 19.558 s, and archive time was 7.371 s versus 6.563 s. Base physical journal size fell from 14,676,744 to 12,298,498 bytes; signed fell from 53,517,788 to 47,966,273 bytes. Logical extents remained 455,119,187 and 1,170,777,775 bytes respectively. These are actual component timings, not a claim that the complete 180-second cold gate passes.

The adjacent JSON records the exact native sources, products, plans, observations, qualified helper coverage and evidence digests. All prior whole-run failures remain retained. A new complete 60-phase run is still required.
