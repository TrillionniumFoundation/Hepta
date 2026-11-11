# Artifact-page original run: incomplete executor continuity

The product result is **HOLD / UNKNOWN_EXECUTOR_CONTINUITY**. The single planned
42-case development differential run retained five completed PASS observations.
It did not retain a final product report or its final guardian receipt. The
original exec session later returned `Unknown process id 46203`. Its startup
record only identifies supervisor PID 2; it does not retain the original
start-ticks/boot identity. The current namespace observation found no matching
page command, but this does not prove historical process-tree cleanup or explain
the interruption. The original run was not replayed or relabeled.

The five completed cases are empty payload, public 512-byte page, public
65,536-byte page, complete 67,108,864-byte ASCII artifact, and complete
67,108,864-byte artifact with an invalid final byte. Each completed case compared
the actual HIA page and HIA wire output against the retained policy, including
every SQL command/argument and each encoded wire payload's byte length and hash.
The retained page policy, cursor digest and base64 implementation were poisoned
on the native side. Full input observation extents and reference alias identity
were also checked. The two complete 64 MiB cases took 15.193197985 and
16.106252525 seconds in the native branch; these measurements are retained,
without a claim that ordinary service latency requirements have closed.

The original page generator, HIA source and adapter have **not changed** from
the prior draft: e30b021f / 4cedc0e1 / 91baeeb4. A fresh actual development build
using the pinned 0e09ccca B3 reproduced the original f2aaee2b image in
0.238036506 seconds. That separate compilation has a final natural guardian
receipt, ECHILD, empty remaining children and stable inputs. This does not
provide cleanup evidence for the subsequent interrupted boundary run.

The independently materialized source contains 1,666 canonical d2 members,
the exact six-file final wire delta from handoff commit
514a13be3c4f956a8efa95bbfeb8bc43be896e49, and three draft page files, for 1,671
executed members. Every source member was checked against its original hash,
Git blob and mode after the interruption. `executed-source.zip` is retained as
three ordered lossless parts; `SOURCE-PARTS.json` records reassembly identities.
All 1,671 ZIP members were independently read back and their byte hashes and
modes verified. This is a source materialization, not a complete Git object
database or a refreshed global source contract.

`originals.tar.xz` preserves all 38 selected original control, progress, stdout,
stderr, source identity, request, compiler, image and custody files. Every member
was read back and checked against its original bytes and mode. `CUSTODY.json`
indexes those originals. `STATUS.json` is a separate derived status record;
the original progress and logs were not rewritten. The exact three-file draft
is also available under `source-delta/` for review, with its manifest.

The remaining 37 cases, including the complete four-byte UTF-8 artifact and
the planned 230000 double-wire boundary cases, have no completed result from
this run. Ordinary selector integration, installed distribution, all lifecycle
fault combinations, full capacity qualification, complete AgentStore ownership
and whole native delivery remain unqualified. SQL in this run was real
in-memory SQLite; no disk durability result is claimed. This evidence does not
authorize retirement of the retained implementation.
