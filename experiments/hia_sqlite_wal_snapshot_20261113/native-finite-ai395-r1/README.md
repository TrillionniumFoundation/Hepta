# WAL committed snapshot: finite native request

Status: native qualification has not been executed. This directory prepares one fixed 180-second qualification with the original 3-second cleanup.

## Population and sources

The original Source12 test file is retained in full: 12 original methods and 608 actual VM input/output/state rows. The native child substitutes only its explicitly admitted NativeImage backend, poisons the Core VM machine, and keeps all original methods, including the 513-byte base-size rejection, large-extent streaming, protocol refusals, and caught reentry controls. Source12 was a source/VM qualification; none of its PASS results are treated as native qualification.

One separate thirteenth method supplies 144 complete-frame scenarios: eight page sizes (512 through 65536), both checksum orders, and nine recovery/lookup shapes per size/order. This contributes exactly 2096 calls. The frozen total is 2704 HIA native starts, normal returns and independently validated returns, with exact per-method counts.

The two independent SQLite versions each receive 639 finite recovery/find calls: 175 selected original drives and 464 full-page drives. Domain selection is fixed before HIA execution. Large virtual extents, bridge/protocol controls, and non-oracle cases remain in the HIA population. C recovery and find return codes, all 32 raw words, and complete read-pair buffers are recorded before comparison or projection. Projection applies a separately specified committed-snapshot boundary and database-page limit; it never promotes checksum validity to a commit.

## Exact trace and resource bounds

The expected complete trace is 203187698 bytes: HIA 5408 PRE/POST rows totaling 58947530 bytes, and C 2556 PRE/POST rows totaling 144240168 bytes. Both streams share the original 256 MiB trace limit. The original 1 MiB row limit, 4 MiB chunks, 384 MiB/192-file output limit, 1 GiB initial free space, 512 MiB reserve, and 4096-free-inode gate remain.

One owner contains one HIA compile (20 wall seconds, 10 CPU seconds, 1 MiB image/workspace), two original C compiles under their unchanged 20/10/1 MiB envelope, the original 12 native methods plus the separate full-page method, complete trace rereads, and source/system/input verification. No retry, quota increase, or substitute compiler is permitted. The parent proves its exact current owner/request/wrapper and ECHILD closure before reading child output bodies; unknown ownership stays HOLD.

The compiler is the fully retained historical v87 development B3 with SHA256 9de8606c153e50f2e742a18d4eb9f3b7c210b404f005346e95b550648d8f2892. All seven original compiler files and receipt/output-prefix joins are required. It is not a matching-current-cold compiler claim.

## Review and execution order

1. Read REQUEST.json, LAUNCH.json, CONTROL-PINS.json and this scope.
2. Read model.py and matrix.py for independent finite expected bytes and oracle domains; read trace.py for whole-stream comparison.
3. Read native_cases.py for original test preservation, native start/return counters, C raw recording, projection, and all buffer canaries.
4. Read support.py, compile_io.py, compile_child.py, worker.py, launch.py and clean_exec.py for image/source/compiler identity, exact environments, complete ownership closure, and preserved limits.
5. Read NEW-C-ORACLES.json, the two full adapter.c sources, C-oracles-static.json and STATIC-REFERENCE-JOINS.json. The static model cross-check matches 321 already-retained VM rows; it is not a new VM or test execution.
6. Root independently reviews the frozen request and uniquely invokes the exact LAUNCH command. This request creates no CI/ref, changes no product default, and grants no current cold, SQL, locking, checkpoint, transaction, crash-durability, or whole-SQLite qualification.

## Remaining production boundary

The HIA kernel determines the committed snapshot and latest visible page location using bounded packets. External file reads, locking, snapshot lifetime, page transaction integration, database-page I/O, checkpointing, and AgentStore activation remain separate work. The finite in-memory C oracle does not close those boundaries.
