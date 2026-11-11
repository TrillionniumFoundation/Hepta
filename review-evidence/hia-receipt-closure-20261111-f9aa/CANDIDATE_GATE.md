# Fixed-candidate gate: HOLD

All qualification and CI runs started for this work are now terminal. The code fixes, supporting documentation and exact original evidence are reviewable. The combined release gate remains **HOLD** because the original cold deadline failed repeatedly.

## Frozen source pairs and follow-ups

| Delivery | Fixed source | Purpose |
| --- | --- | --- |
| [Hepta #891](https://github.com/TrillionniumFoundation/Hepta/pull/891) | 7c20b6cfc792f0147b5418968f94734b8890fcca; tree d76c851edfb51fd649aca26a799ed4874af54489 | Actual full-ABI observation/replay checks and current-source admission for identity-helper builds |
| [Runtime #119](https://github.com/TrillionniumFoundation/hepta-runtime/pull/119) | 7924a0c3545125f7a1c3c888adc63f6515668063; tree 9cdc4061df2d805be33a1e7d51f716c19ed1ff51 | Cold/source/import custody and actual MCP, SSH, native-helper lifecycle against Hepta 7c20 |
| [Runtime #120](https://github.com/TrillionniumFoundation/hepta-runtime/pull/120) | a0dcdda1991ec536d5e2d252c006a778993fa566; tree 98d96c88d54082637c27f1cbfae61a66d0dd81e7 | One-line hidden-source archival repair against the same Hepta 7c20; separately qualified |
| [Hepta #892](https://github.com/TrillionniumFoundation/Hepta/pull/892) | c0fec2a233c64e492f633eb86235438b699d99f1 | Documentation-only support matrix and corrected current/historical descriptions; no new execution qualification claimed |

The machine-readable [candidate-gate.json](candidate-gate.json) records each run, source, result, skip and archive digest. Counts from independent, focused, CI and peer-review suites overlap; they are not summed into a unique-test total.

## Completed functional evidence

- Original candidate-binding push/PR runs: 159 tests each, no failures/errors/skips.
- [Core push 43015496423, attempt 1](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43015496423/attempts/1): 312 source tests; cold 11/11; language 1242/1242 plus 10 assertions; 14 native groups / 581 test executions.
- Runtime 7924 [joint push](https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/43016837973) and [joint PR](https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/43016939924): each source controls 20/20, cold 11/11, language 1242/1242, native/MCP lifecycle 10/10, with 39 calls across four transport sessions.
- Full Rust CI for both Runtime candidates: push and PR all succeeded on attempt 1. Six actual executed jobs each reported all-features 2400 passed/0 failed/40 skipped and no-default-features 2371 passed/0 failed/28 skipped. Exact-head Python controls were 817 passed/1 optional-pypdf skip; prospective-merge controls were 750 passed/0 skipped. Feature suites overlap.
- Format, both check/clippy modes, release builds and actual release MCP cancellation/same-owner recovery passed. All six release binaries had SHA256 1a2ed2585ea78fa841b2adbf89fc06f15b9d1fa83dbff62cd94f8a90b6f17964. Complete candidate-specific reviews are in [Runtime evidence](https://github.com/TrillionniumFoundation/hepta-runtime/tree/86fe5592cf89e0370865db80106bc67b4cc423af/review-evidence/hia-source-admission-20261111-f9aa/ci-review).

Prospective merges used the respective stacked PR bases. They do not establish default-branch integration or production activation.

## Exact upgrade-contract scope

The [retained original compiler-extension report](ci-originals/hepta-7c20-extension-github-original-report.json) reports **PASS_REGISTERED_FINITE_UPGRADE_DOMAIN**: two old source images compared, 18 old native observations, four old refusals, five new admission deltas, 64 complete-program observations, 200 separate projection observations, and fresh replay. Its 25 local obligation instances use eight unique query hashes.

The genuine 24-byte ABI negative fixture, old source-admission regression and corrected controls remain in development evidence. Both producer and replay now reject a correct output/low32 result paired with a nonzero high32 ABI status; raw stdout, augmented receipts, witness rows and retained byte identities are rebound.

The finite report still declares original_agent_four_claim_gate=HOLD, adoption_authorized=false and agent_proof_receipt_issued=false. Other source/runtime inputs, all old grammar, all new select programs, all resource/capacity states, general compiler refinement, historical checker identity, original strict Agent acceptance and original provider costs remain unproved. These fields were not relabelled as success.

## All original cold outcomes remain separate

| Source/run | Attempt | Cold result | Actual wall seconds | Consequence |
| --- | ---: | --- | ---: | --- |
| Runtime 7924 joint push 43016837973 | 1 | PASS 11/11 | 121.620193704 | Language and actual native/MCP lifecycle completed |
| Runtime 7924 joint PR 43016939924 | 1 | PASS 11/11 | 170.448923344 | Language and actual native/MCP lifecycle completed |
| Hepta PR 43015503275 | 1 | FAIL 6/11 | 180.152330827 | Language and 14 subsequent native groups skipped |
| Hepta PR 43015503275 | 2, one bounded diagnostic rerun | FAIL 6/11 | 180.146567810 | Language and 14 subsequent native groups skipped |
| Runtime a0dcdda joint PR 43022234643 | 1 | FAIL 6/11 | 180.187798546 | Independent language passed; native retained HOLD with empty checks |

Every invocation kept its original 180-second qualification and 3-second cleanup budgets. The two Core PR attempts used merge 71520ff1114b0dd95b78ccc4563864713baccc67 with the exact frozen 7c20 tree. Each completed 34/38 nested phases, with all completed reports PASS and zero phase exceptions. Names had requests but no final reports; exports had not reached request creation. Pending work is not counted as passed.

Cleanup completed in 0.081381248, 0.080203272 and 0.084347305 seconds for the three failed invocations above. Original failure statuses and skipped downstream work remain unchanged. No further qualification retries or budget increase was used to produce a passing gate.

The original [attempt-1 ZIP](ci-originals/core-pr-43015503275-original.zip) is 47,477,486 bytes, SHA256 b3e1ffd27ce32357017b781e2fc289d81aea104be74af7f658da36145de528ce. The original [attempt-2 ZIP](core-pr-attempt2/artifact-13854688251.original.zip) is 47,624,762 bytes, SHA256 426d6a2439aba21ff4c391e9e50783554dee4c4e2f58cf447b3eaf194898fdfd. Full hashes and every ZIP member CRC were checked; the second archive's 637 source exports match the actual frozen Git contract. Its [diagnosis](core-pr-attempt2/DIAGNOSIS.md), [phase comparisons](core-pr-attempt2/PHASE-COMPARISON.md), raw logs and process receipts are retained beside it.

These durations measure whole cold qualification, including references and qualification families. They are not compile-self latency or production hot-path throughput measurements.

## Cause and performance limits

The actual inspected jobs used the same relevant source closure, Python executable and linker identities. Cold execution used the same isolated environment, two qualification workers and the same 19 original/modified families. The Core implementation and complete Hepta/examples trees were unchanged from the parent candidate.

Observed duration increases span multiple stages. The retained data does not isolate CPU scheduling, I/O, host contention, caching or an algorithmic defect. A specific performance repair is therefore not claimed. Passing observations cannot erase failed observations or establish stable completion under the existing bound.

## Archival repair verified without changing qualification results

Both original Runtime 7924 ZIPs passed full size/SHA/CRC checks and retain 633/637 declared source files. The four hidden workflow files omitted by the uploader are preserved separately from exact fixed Git blobs. The first independent completeness-check failure and the original ZIPs remain unchanged.

The a0dcdda original ZIP itself contains **637/637** declared source files, including all four hidden workflows, with zero mismatches and no supplement. Its 6209 member CRCs passed. The existing seven upload roots did not include .git, the private worker sibling, SSH keys or agent.sock. Its archival repair is verified while its cold/native qualification remains FAIL/HOLD. Original archives and immutable source-specific custody files are in [Runtime evidence](https://github.com/TrillionniumFoundation/hepta-runtime/tree/86fe5592cf89e0370865db80106bc67b4cc423af/review-evidence/hia-source-admission-20261111-f9aa).

## Remaining boundary and gate

[SUPPORT_DOMAINS.md](SUPPORT_DOMAINS.md) and the corrected [official support matrix](https://github.com/TrillionniumFoundation/Hepta/blob/c0fec2a233c64e492f633eb86235438b699d99f1/docs/HIA_EXECUTION_SUPPORT_DOMAINS.md) separate complete primitive admission, direct emission, bounded selfhost compilation and individual standalone commands. Multiple results, recursion, owned resources, allocator contracts and public ABI limits remain explicit.

This work establishes reviewable fixes and finite actual execution evidence. It does not establish a wholly native JSON/journal worker, whole-language compiler correctness, the historical strict Agent gate, unfamiliar-agent learning, production activation or net performance benefit. The repeated cold deadline failure keeps the combined release decision at **HOLD**.
