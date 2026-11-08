# Cold qualification scheduling and process ownership fix

This change addresses the real 180-second cold replay failure on source commit
`14b2c03c35f0d8d4f3b77133cf3deecde92a2f40`. It preserves the compiler, the
qualification subjects and the existing resource limits. Independent host
qualification work now runs in at most two processes at once. A separate Linux
process owner confirms cleanup before the cold runner accepts a result.

The local fresh main qualification passed all **1,183 checks** in
**88.129021575 seconds**. A second, fresh source-only cold replay passed
**11/11 checks**, including its complete **1,183-check** nested qualification,
in **88.084033772 seconds**. The 11 cold checks are the original ten plus one
explicit process-tree cleanup check. These are local results on the precise
252-file source manifest, not CI results for a future integration commit.

The HIA compiler source remains
`b6062d03a72079de32b5a3ebbebb66d575297b9b89b1625f5a6b42cba9432168`.
All 212 Python closure files under `hepta/` are unchanged. The public three-buffer
`f0 -> u32` ABI, v13 bounded profile, compiler limits and strict Agent proof
gate are unchanged. General multi-result calls and returns, returned-resource
contracts and general compiler correctness remain outside this result.

## Original failure and successful control

The failed exact-source run and the successful unified run are both retained.
The successful run does not erase or qualify the failed run.

| Observation | Exact-source failure | Unified successful control |
|---|---:|---:|
| Run | [42524208424](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42524208424) | [42524213997](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42524213997) |
| Artifact | 13635311052 | 13634184809 |
| Original ZIP bytes | 18,625,316 | 47,796,598 |
| Cold result | FAIL, 5/10 | PASS, 10/10 |
| Cold elapsed seconds | 180.127351883 | 119.995411250 |
| Completed native receipts with elapsed time | 1,458 | 1,699 |
| Sum of those invocation wall times, seconds | 152.580675820 | 101.293146509 |
| Sum of those native execution times, seconds | 76.724226953 | 39.663718311 |

The failed ZIP SHA-256 is
`119fbe8a7ba5d32da056f5de51acddc0914e513b731013fc198cbcc5ec29ff1b`.
The successful ZIP SHA-256 is
`88ee7b16d15087df33265b4de138b4427b12044c3efc6706d38d4e50b3eb9692`.
The failed job was `128864044255`, cold step 14. Its last retained request is
`modified-capacity-8192.request.json`; it has no corresponding receipt, and
the nested qualification report was not written.

All **250** source members, totaling **5,243,162 content bytes**, were read
from both original ZIPs and compared byte for byte. Their manifest digests and
their actual contents agree. The retained selection contains **6,317 original
request/receipt members**: 2,918 from the failed run and 3,399 from the successful
run. Each was independently reread from the ZIP and compared with its retained
copy. These counts include seed receipts and the failed run's incomplete final
request; they are distinct from counts of completed native invocations.

For the same 1,458 completed invocations, the successful run used
85.234487270 seconds of summed wall time, compared with 152.580675820 seconds
in the failed run. The remaining 241 invocations took another 16.058659239
seconds in the successful run. Native execution itself also differed: B3 used
2.667214285 seconds in the failed run and 1.137842470 seconds in the successful
one; the 262,144-node capacity case used 5.451947441 and 2.305540838 seconds.
Thus the evidence does not justify attributing the entire failure to Python
startup or dismissing it as a harmless CI retry.

Summed invocation times exclude B0 construction, reference checks and parent
preparation/evidence work. ZIP timestamps are coarse and are not a precise
phase trace. The original timeout path has no whole-descendant cleanup receipt;
its historical cleanup outcome is not retrospectively claimed to be confirmed.

## Scheduling changes and unchanged checks

`qualify_hia_selfhost.py` still creates a fresh B0, then executes the dependent
B1/B2/B3 and M1/M2/M3 generations in order. It does not reuse an earlier seed,
compiler image, native process or qualification result.

After that sequential work, ten independent qualification families each have
an original-compiler and modified-compiler phase: capacity, CFG worklist, ELF,
chain, owned resources, bulk operations, loans, resources, tail calls and
scalar selection. These **20** phases run through a two-worker coordinator.
Every phase has a new isolated Python process and a distinct private output
directory. Native compiles and executions inside each phase still use their
individual disposable, resource-limited children.

Each phase checks the same complete source manifest before and after execution
and hashes its explicit inputs, including the fresh compiler image. The ELF
phase receives the current run's freshly generated sample image, not a stored
reference image. The coordinator verifies the actual worker PID, return code,
source digest, input digests and isolation flags. It accepts only the complete
closed family/variant inventory with nonempty, disjoint boolean check maps.
False checks remain false. Checks cannot overwrite earlier checks.

The coordinator observes every future, including exceptions raised before a
worker starts. Its atomically replaced `phase-index.json` retains each completed
or failed phase. It collects all worker exceptions before refusing the batch;
control exceptions are re-raised. Each started worker retains its request,
stdout, stderr, process receipt and report. A failed or missing report cannot
become an omitted successful phase.

The general native invocation helper adds `-S` to its existing isolated Python
command. A separate import-time observation found only about 0.9–1.8 milliseconds
of startup improvement in that small probe. That observation is retained and
is explicitly insufficient to explain or resolve the timeout by itself.

This is a qualification-harness scheduling change. It can use two host-oracle
processes concurrently and does not establish that the compiler became faster,
that total CPU cost decreased, or that any performance benefit is stable across
hosts. No per-child limit, subject or check was removed or relaxed.

## Process ownership and admission

The original cold runner used `subprocess.run(timeout=180)`. Killing only its
direct qualification child did not establish that ordinary descendants were
gone. In particular, the normal linker capture starts its own session, so one
outer process-group kill cannot prove complete cleanup.

The new `hia_selfhost_process_owner.py` uses a fresh, single-threaded Linux
supervisor with `PR_SET_CHILD_SUBREAPER`. This property is set only in that
disposable process and read back before qualification starts. The computation
deadline is still **180 seconds**, starting before the owner is launched.
The separate **three-second cleanup budget** cannot admit a late report.

The supervisor observes the leader without reaping it prematurely. During
cleanup it identifies actual direct children by PID and start ticks, kills
live owned children while their identities remain unreaped, and reaps terminal
children. Ordinary descendants, including processes in separate sessions,
become adopted children as their parents exit. Cleanup repeats until the
kernel reports `ECHILD`. Completion requires that observation, no remaining
owned children, no cleanup error and no exceeded cleanup deadline.

A nonzero leader exit remains a qualification failure after successful cleanup.
A zero leader exit with ordinary surviving descendants is admitted only after
their termination and reaping have been confirmed. Timeout, interruption,
identity mismatch, missing owner receipt and unconfirmed cleanup all prevent a
cold PASS. The runner does not read a nested successful report while cleanup is
unconfirmed or after a missed computation deadline.

The ordinary-process assumptions and seven harmless Python lifecycle controls
are documented separately in
[HIA_SELFHOST_COLD_PROCESS_OWNER_20261108.md](HIA_SELFHOST_COLD_PROCESS_OWNER_20261108.md).
They include actual child and grandchild processes in separate sessions after
timeout, leader exit zero and leader exit seven. These are process-lifecycle
controls, not HIA native tests or a security sandbox. The owner does not claim
an exhaustive historical list of descendants already reaped by their parents.

## Final local qualification

| Qualification | Result |
|---|---|
| Source, contract, language inventory, phase protocol and owner controls | 39 distinct tests validated; original narrow-checkout missing-fixture failure retained |
| Fresh B0, original and modified main qualification | 1,183/1,183 PASS, 88.129021575 seconds |
| Exact comparison with original successful CI | Same 1,183 check map; same 1,699 logical native receipt inventory; same non-path request inputs and compared behavior fields |
| Existing changed report assertions against the retained main result | 2/2 PASS; no repeated native execution |
| Fresh source-only cold replay | 11/11 PASS, 88.084033772 seconds |
| Cold nested full qualification | 1,183/1,183 PASS, 87.168068504 seconds; same 1,699-subject comparison also PASS |
| Cold process owner | Exit zero; cleanup confirmed in 0.000718163 seconds; leader reaped, `ECHILD`, no remaining child or cleanup error |
| Final language coverage | 910/910 PASS, 65.057833179 seconds; a separate fresh original/modified generation chain |

The 39-test source run initially had 38 successes and one import error because
the narrow local source export lacked the existing supplementary release
preflight helper. The original log is retained. The exact helper was copied
from the root integration checkout and only that failed inventory test was
rerun, successfully. Neither the 252-file execution closure nor production
code changed for that local fixture correction.

The B1/B2/B3 machine image remains
`cb7cde17ace8aedce7b599c56790e816f9ccb92e3e7fe68bea8bb071c9287515`.
M1 remains
`5af46ec8c3438dc9cd1a72eb995d51793c19c788e097eef1d8176cf1f38c2dec`;
M2/M3 remain
`0889a2bd0dd37d25dfa2be323d3e0a9d993ca3b37e56ab3c486f04b6e2639ffc`.
All six are byte-identical to their corresponding original CI images.

The comparison separately retains **279 differing host-linked shared-object
identities**: 121 seed-shared, 130 linked-selfhost and 28 allocator witnesses.
They are not declared byte-identical. The old CI records GNU ld 2.42 and Python
3.12.16; this local host records GNU ld 2.44 and Python 3.12.14. These observed
toolchain differences and the finite matching runtime observations are retained
without claiming general cross-toolchain equivalence.

## Source and evidence identity

Nine repository files differ from the exact 14b closure:

- `tools/qualify_hia_selfhost.py`
- `tools/replay_hia_selfhost_cold.py`
- `tools/hia_selfhost_process_owner.py`
- `tools/hia_selfhost_contract.py`
- `tests/test_hia_selfhost.py`
- `tests/test_hia_selfhost_contract.py`
- `tests/test_hia_selfhost_process_owner.py`
- `docs/HIA_SELF_HOSTING_CORE.md`
- `docs/HIA_SELFHOST_CORE_SUPPORT.json`

The language inventory was regenerated and remains byte-identical. The two
new owner files expand the complete closure from 250 to 252 files; the support
JSON pins the other 251. The standalone qualification reports and this summary
are evidence, not inputs recursively embedded in the source lock.

The source manifest, exact per-file SHA-256/Git blob identities, original CI
receipts and arithmetic recheck, independent scheduler review, all setup
failures, new finite-input comparisons, test logs and final reports are retained
under `review-evidence/hia-selfhost-cold-parallel-20261108-5e6c/`.
The selected original CI evidence does not pretend to contain every large
buffer from the two original ZIPs; their exact ZIP identities and selected
member identities are recorded.

Each complete new main, cold and language raw archive has a per-file byte/SHA
index and an independent full archive-member readback. Large expanded output
directories are removed only after that verification, Git blob persistence,
and a further comparison of every current file with the index. Final compiler
images and complete reports are retained separately as well.

The main, cold and language results belong to their recorded 252-file source
closure. Repository CI, public installation acceptance and online service
identity must still be evaluated for the eventual integrated commit; none of
these local or historical records is relabeled as a future commit's CI PASS.
