# Nine-role exact typed identity-call substitution

Status before FOLLOW55 CI: **NEW SOURCE, NOT QUALIFIED**. This is a bounded optimization of existing HIA programs. It does not activate an installed entrypoint or complete the HIA migration.

## Exact change

Roles 2, 24, 25, 26, 27, 57, 59, 60 and 63 contain respectively 16, 1, 17, 2, 3, 2, 2, 2 and 2 calls to helpers that take one u64, have one block and zero operations, and return that same u64. Exactly these 47 call lines become u64-to-u64 `int.cast` operations in wrap mode. The helpers remain present. The result and operand SSA identifiers, function and block layout, all memory operations, branches and every other source byte are retained.

The exact seven-role ASCII predecessor layer is preserved, with its own complete inverse proof nested as `prior_ASCII_layer`. Roles 2 and 25 start from their complete original retained sources. Each candidate reverses first to its actual source predecessor and then, where applicable, through the ASCII and inline layers to the original role input. The builder requires complete source-byte equality at each boundary; it does not use a normalized reconstruction as an original.

Removing a call changes instruction count, call depth, stack use and timing. The claim is the same mathematical u64 result with unchanged surrounding memory ordering. It is not equivalence under arbitrary exhausted VM fuel or stack budgets. Actual Core admission, B3 and full original test execution remain mandatory.

## Fresh qualification

The original 63-role baseline is regenerated with six fresh B3 compilations and one actual HIA packing entry. All 63 original HIA sources, images and the complete executable must match before the nine candidates are built. The new side uses nine further B3 compilations and a second actual HIA packer. Total planned fresh B3: 15.

The original test program is retained byte-for-byte except for its directory and the expected fresh compilation count of 15. Its original 13 groups and 329 input/oracle/case sequences all run again. The previous 327 completed cases are not inherited. The two failed large cases in FOLLOW54 remain failures; their exact process return code and streams are still unknown until their originals are independently read. This optimization makes no measured speedup claim before new execution.

The original B3 10 CPU seconds, 20 wall seconds and 256 MiB limit, source/output/work limits, and bootstrap shape limits are retained. The original complete-group process-tree CPU predicate `<=90` and wall predicate `<180` remain unchanged, with the same 1 GiB address limit. The existing common storage/seal phase is separately accounted; it is not represented as a new independent 90/180 qualification.

## Dependencies and failure evidence

The CI driver binds 17 additional repository inputs by complete length, Git SHA1 and SHA256, including the actual FOLLOW54 build console bytes, both predecessor proofs and the old full original manifest. Historical proof paths stay at their real committed locations. The active builder and driver are the final layer-metadata versions; the two earlier unexecuted drafts are retained only under `prior-unexecuted-layer-metadata/`.

Failed-group pending/process JSON files are retained as original bytes. The new bounded console exporter emits complete base64 frames up to an explicit aggregate cap, and records omissions. It does not change the target harness, interpretation, timeout or oracle. Complete output remains in the existing evidence archive.

Two independent source reviews are included: all 18 old/new HIA files and 47 edited typed calls; and the exact builder/test/CI derivations, 17 inputs and unchanged 329-case test. These are source reviews with zero AST, B3, VM or native execution. The existing finally/reporting boundary noted by the build/test reviewer is retained and is not described as fixed.

The whole project remains OPEN. Production activation and old-implementation deletion are both zero.
