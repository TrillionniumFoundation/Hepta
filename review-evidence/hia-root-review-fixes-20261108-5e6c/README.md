# Root integration of the three additional PR808 review repairs

This record keeps the first local failure and the targeted recovery. The first
run executed 66 test entries and failed only to import two unchanged committed
test fixtures missing from the sparse local restoration. Both fixtures were
restored byte-for-byte from commit d6431f233619e1339cec5532741d9303ecfcf150.
No implementation test was deleted, skipped or changed to turn that failure
into a pass.

The second run passed 34 tests: the updated release inventory checks, all eight
external-root tests and the eight prepared-analysis replay tests. Together with
the 46 unchanged successful source/contract/machine-plan tests from the first
run, these cover 80 distinct current tests. The earlier release-inventory
results are superseded by the second run, not counted twice. Both phases verify
the same complete 250-file frozen compiler closure before and after testing.
The initial overall result remains failed in its original report.

The registration review was taken before the final CFG repair document was
materialized. Its recorded pending-document observation is historical; root
must check the delivered document and final Git tree before publication.

This is an integration check. It does not substitute for the independently
retained 1183-check native qualification and complete fresh cold replay, nor
for final source-commit CI, a merged-source CI-generated lock, a private runtime
probe or an actual online installation readback. General Core, whole-compiler
machine proofs, the original Agent delta and NDU value retain their separate
acceptance boundaries.
