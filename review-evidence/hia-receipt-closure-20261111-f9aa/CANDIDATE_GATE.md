# Fixed-candidate gate: HOLD

The functional candidate is Hepta `7c20b6cfc792f0147b5418968f94734b8890fcca` / tree `d76c851edfb51fd649aca26a799ed4874af54489` and Runtime `7924a0c3545125f7a1c3c888adc63f6515668063` / tree `9cdc4061df2d805be33a1e7d51f716c19ed1ff51`.

[Hepta #891](https://github.com/TrillionniumFoundation/Hepta/pull/891) closes actual ABI-status and identity-builder source-binding defects. [Runtime #119](https://github.com/TrillionniumFoundation/hepta-runtime/pull/119) closes cold/source/import identity substitutions and qualifies the exact pair through real MCP, SSH and native helpers. [Runtime #120](https://github.com/TrillionniumFoundation/hepta-runtime/pull/120) separately repairs omitted hidden source files in CI archives.

## Completed functional evidence

- Candidate bindings: 159 tests passed in each original push/PR run.
- Finite compiler extension: old-domain preservation, explicit new admission, 64 complete-program native observations, 200 separate projection observations and fresh replay passed. The actual 24-byte ABI-status counterexample and old source-admission failure remain in development evidence.
- [Core push, attempt 1](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43015496423/attempts/1): source 312; cold 11/11; language 1242/1242 plus 10 assertions; 14 native groups / 581 test executions.
- [Runtime joint push](https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/43016837973) and [joint PR](https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/43016939924): each source controls 20/20, cold 11/11, language 1242/1242, actual native/MCP lifecycle 10/10.
- [Runtime full PR CI](https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/43016940004): exact-head and prospective-merge both passed; each Rust all-features run had 2400 passed and 40 skipped, and no-default-features 2371 passed and 28 skipped. Exact-head Python controls had 817 passed/1 optional-dependency skip; prospective-merge Python controls had 750 passed/0 skipped. Prospective merge is against the stacked #118 branch, not the repository default branch.

These counts overlap and are not a unique-test total. See [candidate-gate.json](candidate-gate.json) for individual runs, identities and artifact digests. The Runtime full push and #120 qualification were still pending when this evidence snapshot was written.

## Original failures remain failures

[Core PR attempt 1](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43015503275/attempts/1), job 130505421753, failed cold at 180.152330827 seconds under the original 180+3-second budget. The checkout was merge 71520ff1114b0dd95b78ccc4563864713baccc67 with the exact candidate tree. It completed 34/38 nested phases with no phase exceptions; language/native stages were skipped. Cleanup completed in 0.081381248 seconds.

The exact 47,477,486-byte original ZIP is retained as [core-pr-43015503275-original.zip](ci-originals/core-pr-43015503275-original.zip), SHA256 b3e1ffd27ce32357017b781e2fc289d81aea104be74af7f658da36145de528ce. Size, full SHA256 and all 4367 ZIP member CRCs were checked before publication. The [raw cold report](ci-originals/core-pr-attempt1-cold.json) and [original job log](ci-originals/core-pr-attempt1-job.log) remain separate.

One explicitly bounded [diagnostic attempt 2](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43015503275/attempts/2), job 130524053433, again failed the unchanged cold deadline with 6/11 outer checks and no downstream native execution. The same source/tree was used. Its archive is artifact 13854688251, 47,624,762 bytes, SHA256 426d6a2439aba21ff4c391e9e50783554dee4c4e2f58cf447b3eaf194898fdfd; API/upload-log identity is verified and full custody is being completed. No further retries or budget increases are authorized as part of this diagnostic record.

Passing runs establish completed observations for their own invocations. They do not erase either failure or establish stable cold performance. Source comparison found the cold implementation and complete Hepta/examples trees unchanged from the parent candidate; that alone does not determine the timeout cause.

## Source archive completeness

Independent Runtime push archive readback verified the full ZIP digest and CRC and found 633 of 637 declared source files. Four .github workflow files were omitted by the default hidden-file filter. They are recovered into a separately labelled exact-Git source supplement. The original ZIP remains unchanged and is never relabelled as containing all 637 files. The first supplemental completeness-check failure is retained.

The archival follow-up #120 adds include-hidden-files only inside the same seven explicit upload roots. Disposable SSH keys and private worker/controller state are stored in a separate, unlisted sibling directory. Its new candidate is a0dcdda1991ec536d5e2d252c006a778993fa566, with the same Hepta pin; results for the parent are not counted as new executions for that head.

## Scope and remaining gate

[SUPPORT_DOMAINS.md](SUPPORT_DOMAINS.md) distinguishes complete Core checking, direct emission, bounded selfhost compilation and standalone commands, including multiple returns, recursion, resources, allocator and ABI contracts.

This work does not establish a wholly native worker, whole-language compiler correctness, fresh-agent learning, production activation, arbitrary privileged-writer protection or a performance improvement. Hosted JSON/journal policy remains, and live service cutover was not performed.

The current gate remains **HOLD** for repeated PR cold deadline failure. Native-helper functional integration and finite upgrade-contract evidence are available for review while that gate is investigated.
