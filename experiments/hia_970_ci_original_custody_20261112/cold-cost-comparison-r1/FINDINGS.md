# Original cold costs: 970 success and bde timeout

This analysis reads the original artifacts and executes no product code. The historical 970 cold run completed in **137.407936075 seconds**; bde timed out in **180.194632726 seconds**. The original 180-second limit, two workers, 38 phases and all cases remain unchanged. The full 5,400-second retained suite is outside this evidence.

## Same-workload comparison

The second reader joined all **35 complete phase reports** available in both artifacts. Their check dictionaries are identical. All **4,897 unique recorded native invocations** have matching case, format, status, input-image-output hashes and result fields, with multiplicity. All 17 independent reference payload hashes also match. This supports a comparison of the same work rather than different selected cases.

| Boundary, summed across those 35 phases | 970 seconds | bde seconds | Change |
|---|---:|---:|---:|
| Worker process wall | 166.773507158 | 220.053662434 | +53.280155276 |
| Recorded native-call wall | 97.031651486 | 145.958482233 | +48.926830747 |
| Clock interval inside native calls | 66.424345239 | 113.365747088 | +46.941401849 |
| Phase body excluding recorded call wall | 62.128323558 | 64.446859190 | +2.318535632 |
| Worker wall outside measured phase body | 7.613532114 | 9.648321011 | +2.034788897 |

These are overlapping two-worker sums, not elapsed critical-path components. The dominant measured increase is inside calls to unchanged native compiler images. The original records measure a clock interval around the call, not process CPU time, so they do not distinguish scheduling contention from a changed machine service rate. Neither is asserted as the established cause.

`names-original` increased from 17.972830110 to 31.551650674 seconds. Its recorded internal native intervals increased by about 12.876 seconds, versus only about 0.539 seconds of additional phase-body work outside call wall. Identical reverse-1536 six-function compilation inputs took approximately 1.23–1.29 seconds per native call in 970 and 2.45–2.59 seconds in bde. The existing phase reports retain these observations; the separately documented 46 overwritten earlier companion histories are not represented as recovered raw files.

## Preparation and scheduling

The first phase began 38.679082490 seconds after the old owner start and 52.641244892 seconds after the new start. This covers the whole pre-phase path, not B0 alone: 17 fresh references, two independent observer VM references, B0, the six-generation chain, observer builds and the ordinary prefix.

The 17 reference worker wall durations sum to 48.946451859 and 65.916093316 seconds. The old actual two-worker reference span is 26.485183218 seconds. The new parent start/end records would have been in its absent final qualification report; they are not reconstructed from child durations. Six sequential B/M generation calls increased from 4.434185969 to 7.162321403 seconds, with 2.693999181 seconds of that 2.728135434-second increase inside their native intervals.

The first 34 phase execution window increased from 77.177053547 to 97.659574204 seconds. Across the two slots, time without a live measured worker increased from 5.553454100 to 6.817159528 seconds. This interval includes input preparation, report validation and archive queue backpressure; it is not all compression time.

The archive writer is byte-identical between the two source copies and **already uses DEFLATE level 1** at both ZipFile and per-member writes. It has one archive worker and two pending slots. Summing each archive's delay double-counts queue overlap. Accounting for the single archive lane gives a service-time upper bound of 21.812987640 seconds old and 23.942933610 seconds new, including delay before submission. The casts/traps-to-CLI transition visibly waits for archive completions in both runs. These records do not justify treating archival as the main new cost or deleting any of its readback checks.

## Measured response-byte opportunity, with protocol limits

Among the old **6,098 physically retained invocation receipts**, 5,221 normal observer returns require **5,549,407,769 response bytes** under the current protocol. Workspace accounts for **3,249,538,064 bytes**; the parent selects only **421,592 bytes** into its 17 fixed 8-byte header fields. The remaining **3,249,116,472 workspace bytes** are still part of the current response framing requirement. These totals exclude overwritten earlier histories and abnormal responses, and are not a claim of all attempted wire traffic.

The new incomplete run's 5,914 physically retained invocation receipts include 5,081 normal observer returns and 3,115,320,336 workspace response bytes. Its unfinished phases mean this is not a full 38-phase traffic denominator.

An explicitly versioned compact observer transport could retain every currently recorded header value while reducing unused workspace transfer. It would need corresponding HIA flat/linked observer generators, independent reference checks, response framing and full original A/B comparisons. Merely deleting response bytes from the current protocol is not a compatible fix. The redundant preliminary `frame()` allocation is another bounded opportunity, but neither change is claimed to recover the entire deadline from these observations.

## Durable originals and limits

`ORIGINAL-COSTS.json` is 5,950,379 bytes, SHA256 `b501c800bfe986f7d068cc9e893f0bccc68de440bf0b366e9d5fd0e4e3437071`. Its complete bytes are preserved losslessly as four base64 chunks of one deterministic gzip, with offsets, compressed and original hashes in `ORIGINAL-COSTS-CUSTODY.json`. The complete paired finding report and both reader scripts are separate files.

The first reader used the field label `same_180_seconds_two_workers_38_families`. The precise meaning is **38 phases, formed from 19 families and two compiler variants**, as explicitly corrected in `PAIRED-FINDINGS.json`; the original report is preserved unchanged. The new run's missing final qualification and incomplete phases, all old receiver HOLDs and the names custody gaps remain unchanged.
