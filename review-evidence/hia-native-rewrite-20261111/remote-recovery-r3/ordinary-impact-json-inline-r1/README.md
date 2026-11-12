# Actual HIA JSON string call inlining

This checkpoint contains seven complete HIA assembly sources derived from the actual retained impact images, plus the exact JavaScript source editor and full byte-identity evidence. It is inactive: no new HIA parse, B3 compile, VM run or native run has occurred. The text edit itself was executed and its products were checked.

For roles24/26/27/57/59/60/63, only decode_string changes semantically at the source representation level: the original write_scalar body and its exact one-block get/put calls are expanded in place. Every original per-byte access, checked shift, partial write and per-scalar workspace cursor read/write remains in the same order. The unchanged Unicode decoded helper remains a call. Other functions remain byte-identical except the exact alpha renaming of original role27 f2. Its original largest SSA spelling was v2840 with only1281 unique values; the bijection preserves every definition/use and is completely reversible. No whole-range precheck, bulk memory access, cursor cache, early error, capacity change or VM modification is introduced.

The result of old put is not assumed to be zero: original roles24/26/27 return the passed value. All expanded parameter-return call results are verified unused before elimination. Function-call accounting and instruction counts can change, so arbitrary-fuel/stack-observation equivalence is not claimed.

All original limits remain. The new textual profiles fit128 functions,1536 blocks,8192 operations,256 blocks per function,16 block parameters and numeric SSA<2048; this is a source check only. There is no128-operations-per-block limit. Actual Core verification and B3 remain mandatory. The source editor never interprets or executes HIA.

Next integration must bind all63 actual original images, freshly compile the seven replacements, use the actual unchanged HIA packer, and rerun all original13 groups329 cases under paired90CPU/180wall/1GiB. The original90CPU large-input failure is unchanged until that entire new gate completes. Public CLI/Worker/Store/native installation remain open. No production selection or deletion is authorized by this checkpoint alone.
