# Independent review of public 7511 CI artifacts

Both audits passed on their first completed run using the unchanged parameterized reader committed in `ecfb4706fc9cdf62b5a1bc4bb6901e383d44e410`. This review reads ZIP members, retained logs, and immutable Git metadata/blobs only. No project modules, model, tokenizer, compiler, solver, native program, or test suite were executed.

## Source and artifact identities

Public `7511d99b80511b33082a76d71109adf4ecdb1395` and local `ee99df40e3bec5f573a1096ee0c5c60336f0a808` directly resolve to tree `d8f1da628700153df48a5b3959d5a5905d3e476b`. Both public and local commit objects were readable during these audits.

- Source/application run `40814938595`, artifact `12871838818`: 61,784,693 bytes, SHA256 `8ee4f588345158f4c3f95b5bbe7f88c3321a62ad66d24548a2bb43e399dd4810`.
- Broad run `40814938579`, artifact `12872741610`: 4,839,913 bytes, SHA256 `d096338a826d9b22ade9a917a2a1ede9e5d340638a1af120e8d23df16639bbc0`.

Both downloaded ZIPs match their recorded official metadata digest and size. Every inspected member has a safe, unique, unencrypted name; no archive member was extracted or executed. Source bytes are bound directly to the immutable local Git tree.

## Test identities and scope

- Source regression: **249 executions / 249 distinct test IDs**, zero failures, errors or skips.
- Broad regression: **761 executions / 761 distinct test IDs**, zero failures, errors or skips; 80 different module names.
- Safety: **37 executions / 37 distinct test IDs**.
- Overlaps: source/broad **229**, source/safety **7**, safety/broad **24**, all three **5**. The actual union is **792 distinct retained unittest IDs**, not 1,047 independent tests. Distinct IDs themselves do not establish statistical independence.
- Scalar lowering: **449/449** recorded obligations, their Core/LLVM/SMT hashes and full manifest match. The five original negative controls remain four refutations and one profile rejection. Saved SMT files contain the documented appended check-sat command; the recorded query digest is verified against the exact pre-suffix bytes. No solver was rerun.
- **2,774 distinct source Git blob paths** match across both audit source inventories. The V8/common+broad audit checks 2,774; the V9/common audit checks 929, all contained in that union.

## Two reference profiles

| Profile | Protocol digest | Snapshot source files | Reference rows | Public case observations | Hidden case observations | Artifact files checked |
|---|---|---:|---:|---:|---:|---|
| V8 | `09faff43f1d7e97f2f10745f3973391cf0fa40bde593016c22e2121fc6ff5746` | 170 | 19 | 54 | 472 | 19 ELF, 8 HIA objects, 8 HIA Core |
| V9 | `3728cbe786092e05070986410357ecf13ad351c82eeeec2ae925cb13242a253c` | 176 | 19 | 54 | 472 | 19 ELF, 8 HIA objects, 8 HIA Core |

The ZIP prefixes `agent-tool-native-references/` and `agent-tool-native-references-v9/` have distinct protocol and study-version attribution. Each contains exactly the registered 19 ordered IDs and no extra ROW files. The same 19 registry IDs recur in the second profile: **38 profile-qualified control records do not mean 38 distinct tasks, model successes, or independent semantic cases**. Each profile has 19 executable files but 15 distinct executable hashes.

All public compilation, native artifact identity, finite resource counters, output/expected pairs, HIA VM observations and terminal hidden records are consistent with the retained gates. Actual ELF, object and Core bytes match their recorded digests. Rust records have no HIA VM execution; their original `vm_contract_passed` flag does not create an independent Rust VM proof. The audit does not regenerate every fixture or prove language/compiler soundness.

Each wrapper records **zero model requests, zero tokenizer invocations, zero Agent successes**, and `capacity_qualified = model_qualified = false`. These controls cannot replace the separately measured tokenizer-capacity or model-qualification experiments. The separate broad job log retains 36 successful native NDU observations; this is neither a new NDU run nor evidence of net economic benefit.

## Reusable evidence and limitations

`COMMANDS.json` preserves the actual two commands. `review_ci_artifacts.py` is the exact unchanged reader used in those commands; `summarize_ci_7511.py` derives cross-suite/profile counts from the two completed receipts and the recorded profile plans. The complete output receipts and read-member identities are stored in losslessly compact JSON. `RECONSTRUCTION.json` records original and stored sizes/hashes and the verified recipe to reconstruct the exact original pretty-JSON bytes. The unmodified originals remain under `/tmp/hepta-ci-artifact-review-20261029/7511-v8-01` and `7511-v9-01`.

Remote tool identities, source-stability flags, and process outcomes are retained producer records checked for consistency. They are not independent remote hardware attestations or local reexecutions. Scientific safety, language-wide migration, performance, NDU net-benefit and Agent-productivity gates are unchanged.
