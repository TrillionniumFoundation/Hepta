# Recovery source checkpoint r3 — independent execution remains required

This commit saves the current reconstruction sources and adds isolated, recovery-branch-only GitHub Actions jobs. It does not activate production, retire any owner, or claim whole-stack HIA closure.

## Concrete changes

* The candidate harness now has a fresh 87-case complete-ELF replay, 44 private witness cases / 82 actual planned native entries, and exact 8 MiB / plus-one-byte tests. The three new groups have **not run at this checkpoint**.
* The prior candidate fix already passed 17 complete-ELF cases on ROG in r2. Those results remain separate. The new CI reconstructs and reruns the 17 cases under a new execution identity, including the six original differences and three success controls.
* The CLI directory contains 24 exact source files and a detailed dependency index. Their UTF-8 bytes, Git blob IDs and SHA-256 were independently read back. Prior ROG component results were capture 358 / wire+pretty 397 / file 212 cases. The entry controller and packer are saved source; the outstanding ROG launch has no observed terminal result. Business operation 17 still has no success ACK and remains open.
* The new filesystem 14-group test source and journal bridge r3/r4 source are preserved. The r3 bridge is superseded by r4. No VM/native pass is inferred from these drafts.

## Independent CI

The candidate and CLI jobs independently rebuild their own components. The CLI job reruns capture, wire/pretty and file qualification, builds the seven-image ELF, and checks parser, help, catalog and real file-refusal behavior. Valid-file business handoff remains an explicit open path; exit 126 is never counted as business equivalence. These exit-126 controls cannot distinguish an unhandled operation 17 from an ABI refusal, and therefore do not prove that the handoff event was reached.

The new workflow runs only on the recovery branch (or explicit workflow dispatch). It uses read-only repository permissions, exact CPython 3.12.14, Unicode 15.0.0, and z3-solver 4.15.4.0. Each development driver has one allowed CPU and 1 GiB address space. The original B3 10 CPU / 20 wall / 256 MiB and candidate public native child 90 CPU / 180 wall / 1 GiB limits remain unchanged.

The a3c reconstruction checkout and independent 0ef reference are divergent histories. CI therefore explicitly checks out both; it never assumes current main contains the reference. It verifies every baseline/reference Git blob, byte size and file mode, restores the published archive members, and uses the same frozen B3 image and all 63 semantic owners. Only roles 59 and 60 are replaced by the already-published candidate source. Their newly compiled image hashes must equal the separately observed ROG hashes.

Successful and failed CI executions preserve complete stdout/stderr, process records, original inputs, new sources/images/ELF, and a tar archive whose original/member bytes, SHA-256 and modes are read back. This job is component qualification, not the matching-source whole-stack cold gate. Python orchestration here remains development and test infrastructure; it is not evidence that the tooling rewrite is closed.

The earlier HIA Core-only workflow at d786 failed in its selfhost contract and cold-replay steps. Its actual job/step results are saved in prior-ci-observation.json. Log retrieval timed out, so this checkpoint does not invent a cause or suppress those failures.

## Evidence still outstanding

ROG transport timeout leaves the root retained-fixture restore, CLI entry launch and filesystem/journal preparation outcomes unknown. A successful new CI run would be a different observation and would not resolve those old operations. Complete ROG raw archives for the latest CLI/records components remain pending transport. The inaccessible local R15 sources and counts are not inherited by these new revisions.

Full installed CLI business routing, worker business/schema/journal persistence, namespace transactions and migration, compiler/proof/VM/library/tooling coverage, the final cold/full gate, and the eventual default switch and legacy cleanup remain open. See status.json and MANIFEST.json for exact scope and source identities.
