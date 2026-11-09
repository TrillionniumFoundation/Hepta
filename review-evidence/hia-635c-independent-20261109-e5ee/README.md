# PR #819 exact-source artifact: independent read-only review

**PASS for identity and scope consistency of commit `635c57bd7fd0b9f37480b4da091af4dddfd53a36` only. Overall six-item acceptance remains HOLD.**

The reviewed source tree is `f696b321aa98dcfa183fc72be67904b06eef0424`. The source-only v14 release lock has SHA256 `79116dee28075d8ad9fefbe41bc8490d2790beb292e7a698b33a6b182338e0dc`. Its runtime mapping remains `4cd85c99c5f5a480832c48fbde8561bb365f67a9`. This review neither publishes nor activates that lock.

## Primary evidence

- [PR #819](https://github.com/TrillionniumFoundation/Hepta/pull/819)
- [Exact-source CI run 42552813567](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42552813567)
- [Artifact 13646795635 metadata](https://api.github.com/repos/TrillionniumFoundation/Hepta/actions/artifacts/13646795635)
- Original downloaded ZIP: **32,398,297 bytes; 23,715 members; SHA256 `577e5ab4311d6bd6f66a106eb676806277e809225f408b83851c5e2e5b1a5cee`**. Its bytes match GitHub's digest.

Original API body text for the PR and artifact collection is retained in `metadata/`. The complete nontruncated Git tree and the 19-run API response are retained as gzip-compressed original API text. Stored and uncompressed hashes are recorded in [audit.json](audit.json); compression does not change the decoded API text. The large original CI ZIP is referenced by its official artifact identity and digest rather than duplicated in this package.

The 19 associated workflow runs were successful: **17 `pull_request` runs and two `push` runs**. The convenience PR-only wrapper omitted the two push runs. Its filtered count did not mean two missing gates. The actual exact-source artifact's `source.txt` binds the reviewed commit and tree. Association metadata alone does not attest that every other job checked out the head rather than a prospective merge commit.

## Checks actually performed

The review used segmented standard-library ZIP/JSON/hash inspection, read-only Git object comparison, and static reading of exact public source. **The reviewer executed no project compiler, solver, generated native image, or dynamic project test, and imported no project module.** No claim is made that one saved command reruns this whole review. The report-writing step serializes those results and rechecks ordinary file/hash bindings.

1. All **252 exported cold-source files** match their SHA256 entries in the cold manifest and release lock. Their computed Git blob identities match the complete exact-head GitHub tree. The language report uses the same manifest. Full per-file hashes are in [source-closure.json](source-closure.json).
2. The retained cold report records **11/11** checks, its nested qualification **1,215/1,215**, and the language qualification **1,026/1,026**, with **1,050** reference scalar witnesses. All six B/M image byte hashes were checked. The intended mutation relation is **M1 differs from M2; M2 equals M3**. The 180-second qualification and three-second cleanup limits remain unchanged.
3. **Eight existing NativeTests assertions** passed on the same freshly produced language report; the report digest matches. These assertions did not execute an additional compiler chain. These overlapping counts must not be added as unique tests.
4. All **555 files** in the original C1 fragment artifact manifest match. Its recorded checkout is the reviewed exact head. Frozen C0, C1 and patch bytes match their original identities. The new qualifier, replay, test and scope-document bytes match the release lock and exact public Git blobs.
5. Five positive fragment validations and five independent replay reports agree on all six scope fields: **subject, property, profile, assumptions, checker and unproved_obligations**. Checker source identities match the independently hashed source export. Each exact Core/object/final image and its unchanged 35-byte copied interval are bound by actual byte hashes.
6. **25 original SMT obligations and 25 replay queries recheck the same 25 obligations. They are not 50 independent proofs.** All 50 retained query-file hashes and recorded result files agree. The reviewer did not rerun the solver.
7. Five typed outputs contain **four distinct complete images and two distinct copied byte strings**. The u64/usize duplication is not a separate statistical sample. The **200 projection calls** and **64 complete-program calls** remain distinct finite observations.

[fragment-bindings.json](fragment-bindings.json) records the exact five subjects, 25 obligation identities, original/replay query paths and shared checker identity. [audit.json](audit.json) records the scoped decision, recorded CI outcomes and input hashes.

## Scope and unchanged refusals

The copied-byte lemma assumes initialized, disjoint, normalized stack slots supplied by its new projection. It does not prove these preconditions or reachability in arbitrary surrounding original programs. The original compiler seed-to-machine refinement remains an explicit assumption.

The original strict Agent report remains `HOLD_REAL_DELTA_STRICT_GATE`. The new fragment report retains `original_agent_four_claim_gate=HOLD`, `evaluation_performed=false`, `adoption_authorized=false`, `agent_proof_receipt_issued=false` and `whole_compiler_or_original_agent_delta_proved=false`. Provider tokens and fees remain null. The conditional fragment check does not issue an Agent acceptance receipt.

The original lock retains `source_lock_only=true`. Its agent-first-use, default-branch, production-deployed, source-only runtime-loading and NDU-value qualification flags remain false. General Core, compiler/ABI/resources/FFI/ISA/loader correctness, original Agent evaluation/adoption, complete provider evidence, and stable NDU economic value are not established.

## Qualification does not transfer

This review applies only to `635c57bd`. Its 52 changed paths overlapping `2aa20688` contain 44 identical blobs and eight differences. A subsequent integration must preserve both parents' original evidence, reconcile its three fixture differences without weakening identity/deadline checks, retain the 723-ID guard and leader/streams scope, and obtain its own exact-head CI.

The five `2aa`-only documentation/evidence paths are listed in `audit.json`. Original failed runs and older reports keep their original subjects. This review does not qualify a subsequently merged tree or change the public v9 selection or online installation.
