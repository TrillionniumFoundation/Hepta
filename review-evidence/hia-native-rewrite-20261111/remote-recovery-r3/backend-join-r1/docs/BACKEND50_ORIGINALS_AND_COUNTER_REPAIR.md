# FOLLOW50 first backend cross: original-data readback and counter repair

Status: new source only. No new AST, HIA generation, B3, VM or native execution has been performed for this revision.

The original FOLLOW50 job 131190424091 in run 43220473879 failed after 21 successful fresh HIA component compilations and the C mechanics build. The first cross case completed both target carriers, then stopped at the original strict entries/calls/commands comparison. Its original group remains FAIL with zero completed cases and 4,904 aggregate native entries. Its complete raw log, 21 build panels, C build, first-group JSON, 25 exact profiles and seal record are preserved separately under observations/follow50-originals.

## Exact source correction

The original Python Mechanical initializes calls as an empty dictionary. Its fixed C adapter initializes all roles 1 through 21 to zero. In the first case, roles 12 through 16 have zero aggregate calls, so these keys are missing on one side and present on the other.

The only harness source substitution initializes all 21 Python keys to zero. Increments, target input, all production HIA generators, C mechanics, source/image bindings, entry numbering and command issuance remain byte-identical. The original combined entries/calls/commands assertion and complete final-slot, native return, event and ACK comparisons remain unchanged. The existing CI driver changes only the harness byte count, SHA256 and Git blob pin.

The retained full schedule is still 22 groups, 133 cases and 72 private controls. This is a planned new complete run, not an inherited PASS. The fresh B3 calls keep 10 CPU seconds, 20 wall seconds and 256 MiB; every subject group keeps 90 CPU seconds, 180 wall seconds and 1 GiB.

## Independent original-data reader

read_backend50_originals.py accepts the extraction of artifact 13946102285, the frozen observation JSON from FOLLOW51, the exact read-only helper, and the repaired harness source. It imports only standard-library modules and the explicitly pinned read-only helper. It does not import the product, instantiate a native image, run a VM, call a compiler, spawn a subprocess or execute the repaired harness.

Before artifact JSON is interpreted, it copies and completely compares the original compressed archive, JSONL ledger, custody record, reader/helper source and observation/repair inputs. It then verifies the exact archive and ledger lengths/SHA256 values and reads every regular tar member, checking unique safe names, original paths, modes, lengths and all bytes against the complete ledger. It clears tarfile's member cache after each member.

The transport is the complete inner archive plus ledger. The original outer ZIP ID, size and digest are recorded as download metadata; this script does not claim to have independently read the outer ZIP bytes.

The helper checks exactly one observed role for each ID 1 through 21, the original 21 complete HIA source/image bindings and compile receipts. Each receipt's source SHA, input SHA and input byte count must equal the independently read actual source SHA and byte count. It reads the original C trace, all image/input records, every native entry/return, every command/ACK and the terminal. It reconstructs every original Python full-memory snapshot from its complete compressed CAS pages and delta ledger, rehashes every effective byte, and then replays only the already-recorded fixed buffer mechanics. This is an evidence reconstruction, not a product interpreter or a new HIA execution.

The replay compares each entry's complete recorded operands, preserves read-only permissions, applies only actual recorded GROW/ZERO/COPY/RELEASE/PROTECT/VIEW events, and compares every ACK byte. It reconstructs the Python carrier's final slot table and compares every byte and permission with the original independent C final-slots file. Finally it compares the actual recorded object, text and metadata spans with the original reference files. It separately records the sparse/dense dictionary difference instead of discarding it.

The proposed repair is also checked by a unique complete-byte forward and inverse substitution against the actual original harness member. Neither the original assertion nor its later comparisons is weakened.

## Result accounting

Even if the reader passes, the original job and original case remain FAIL / zero completed cases. A read-only PASS means only that the preserved originals were read and the listed comparisons were reconstructed. The original native entries are observations, not newly executed entries. New B3/VM/native execution and newly qualified case counts remain zero.

The reader records full versus partial archive progress and saves original inputs before semantic assertions. Its finally block independently checks each input and extracted member again; a missing input is reported without replacing an earlier failure. It retains failure evidence and does not delete original or extracted bytes.

The reader sets CPU=90, AS=1 GiB, core=0 and a 180-second wall alarm, with final aggregate CPU/wall checks after evidence writes. The native subject tests remain in the existing independent job. No new evidence seal phase runs in this reader. The original FOLLOW50 seal measurements and earlier FOLLOW49 storage scope are not reinterpreted as newly proved resource gates.

## CI binding

The separate read-only job needs actions:read and exact artifact ID 13946102285 from run 43220473879. Download it into HIA_BACKEND50_ORIGINALS. Run the reader with the command in backend50-originals-workflow.json. HIA_CI_OUTPUT/readback must be new; upload the complete output directory even on failure. Use the project's existing Ubuntu 24.04/x86-64 and CPython 3.12.14 setup. It needs no Z3, common.prepare, source archive recovery or compiler.

The existing backend-join job continues through the updated ci_backend_join_r1.py. Its common/output environment, original limits, complete source closure, 22-group schedule, 21 B3 calls, full intermediate-CAS small cases, large-boundary trace scope and per-group evidence checks remain unchanged.

Whole public backend, real public Core admission, implementation-file custody join, native installed build and complete native release closure remain open.
