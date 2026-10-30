# Official e0 and b121 full-release failures

Both complete official workflows finished with **failure**. The exact original selected logs distinguish the earlier fixture errors from the remaining compiler-environment inconsistency.

| Source | Run / job | Candidate full unittest | Standalone full unittest | Integrated full unittest |
| --- | --- | --- | --- | --- |
| `e0b9012a249167b5bc5b0f3bd243899344621080` | `41055033720` / `124060301525` | 4,335 tests; 3 errors, 2 skips | 4,335 tests; 3 errors, 2 skips | 4,335 tests; 3 errors, 0 skips |
| `b121c9b4a57a8a58e53360d1d67387d953348f57` | `41059230300` / `124074454191` | 4,335 tests; process exit 0, `OK (skipped=2)` | 4,335 tests; process exit 0, `OK (skipped=2)` | 4,335 tests; zero failures, errors or skips, `OK` |

The three e0 errors all occur in `SameCoreBuildInputTests` while preparing the actual native IR fixture. The original error is `E_HIA_FILECHECK_TARGET: Clang LTO requires an ELF linker driver spelling`. These errors are absent from the b121 original unit records after the existing fixture repair. The earlier e0 six-outcome workflow's startup-timeout failure is a different original run and is not substituted for these full-release errors.

Both candidate verbose logs name the two skipped `ConvergedNativeGraphTests` methods: `test_all_eight_arms_execute_and_keep_sealed_artifacts_and_resource_gates` and `test_native_representations_have_distinct_owned_sessions_and_caches`. Their recorded reason is `requires actual stream identity, Clang and Z3`. The standalone `-q` logs record the count of two skips without naming the methods; attribution there also uses the identical test prerequisite and producer environment, rather than pretending the quiet log contains method names.

The exact b121 source shows the environment mismatch. The workflow's selected verification-tool export writes `CLANG` but omits `HEPTA_CLANG`. The standalone qualifier likewise configures only `CLANG`. The unchanged two-method decorator requires `HEPTA_CLANG`. The integrated qualifier configures both names to its one explicitly selected compiler; the original b121 integrated report records `/usr/lib/llvm-20/bin/clang` for both, and all eight integrated gates pass. The candidate and standalone zero-skip rules correctly refuse qualification when their unit processes exit zero with skips. The candidate's `test_count: 0` is its strict qualified-count field; it does not mean that zero tests executed.

The proposed minimal repair synchronizes `HEPTA_CLANG` to the same explicit selected compiler in the workflow and standalone environment and retains existing restoration on exit. It does not alter the test decorator, selector set, source admission or zero-skip requirement. The repair needs its own frozen-source actual executions; these two official full workflows remain failed.

## Correction of an initial triage inference

An early message inferred that canonical step 24 was skipped because earlier steps failed. The actual workflow condition requires `HEPTA_QUALIFICATION_PROFILE == 'integrated'`, while these runs use `full`. Its skipped status follows that profile condition. The original job-status metadata did not justify the early causal inference. The corrected interpretation is retained in `triage.json`.

## Original-byte retention scope

Official artifact `12984706769` is 434,000,149 bytes, with metadata SHA-256 `cebec9bdb0030c7624f3dd5a4be439b5b61cb66b4b78734f5bd64ebcb613f082`. Artifact `12990041651` is 433,999,060 bytes, with metadata SHA-256 `6e562619a1d5d1e15450a3197e904d2a360ba7485cf15d5ecef0c06a2b7e6fa4`. These are the original API-reported whole-ZIP identities; this triage did not download or hash either complete ZIP.

The reader fetched the ZIP directory and selected original unit logs and qualification reports using HTTP 206 byte ranges. Each selected member was decompressed and checked against its ZIP CRC. The e0 selection downloads 2,255,927 range bytes for four members; the b121 selection downloads 2,822,478 range bytes for six members. An earlier b121 directory-only probe downloaded another 1,145,875 bytes and is separately retained. Each directory has 8,513 members, including historical material; only the exact listed current producer members are used for this conclusion.

The two complete connector-decoded job log fields are retained as JSON and encoded exactly to UTF-8, including their BOM and final newlines. Their receipts do not assert byte identity with a separate undecoded transport. Five relevant b121 source files are retained from raw Git with exact identities. Signed transport URLs are outside this evidence directory and must not be published. No native program, project test, or build was run by this triage. All 27 broad P0–P7 obligations remain open.
