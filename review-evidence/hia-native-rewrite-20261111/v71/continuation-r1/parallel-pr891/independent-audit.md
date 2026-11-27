# Independent review of PR891 against 673, 8b9 and normalization r9

This is a bounded development review, not full compiler, cold, SMT, candidate, or public-normalization qualification. No product source, Git ref, deadline, resource limit, or existing evidence was changed. The exact PR891 test definitions ran with the current 8b9 shared child/admission dependencies, so this measures the proposed transplant; it is not qualification of the entire PR891 tree.

## Identities

- Reviewed PR891 head: `7c20b6cfc792f0147b5418968f94734b8890fcca`, base `8dae9d0b74f8520d1522548e0a04c0c077b3f074`.
- Previous source: `67382498b9d60bfecf3696d8c2cb632d8f20281b`.
- Current parent candidate: `8b9fbcbeb943447bdbd4e534f081f92e5f1ad8b2`, tree `1766691461d2ba7fef644e2b4e436566016f2226`.
- Local 8b9 input is the verified 821-file source-contract closure, not a complete checkout and not an asserted clean Git worktree.
- Normalization comparison is the separately frozen r9 33-file packet, Git blob `24b81724ffedfdbab536ff64eb58765dacbeeb85`. No r9 CPython 3.14.4-specific note ABI was executed here.
- Actual executor: Linux x86-64, Python 3.12.14. Per-child limits are the unchanged shared child limits. No C compiler, HIA compiler, cold run or SMT solver was invoked.

## Confirmed observations

1. **The existing select producer and replay omit ABI failure status.** The exact acceptance expressions were extracted from the 8b9 source AST, not reimplemented. An independent 24-byte machine fixture writes the expected eight output bytes and returns status=1, low_u32=7. The real child reports result_u64=4294967303, core_u32=7 and abi_status=1. Both old expressions accept it. PR891's producer and replay validators both reject it. The zero-status narrow and full-width-output controls pass both old and proposed validation. This demonstrates a qualification acceptance gap, not a claim that the real HIA compiler produced this invalid artifact.

2. **The proposed replay catches raw-vs-augmented type drift.** After a successful actual machine call, the retained raw stdout JSON alone was changed from abi_status=0 to abi_status=false. The old replay predicate still accepts; the new replay rejects while the augmented receipt and witness remain unchanged. The original raw bytes were restored, and the changed observation is retained separately. There was no second native execution in this control.

3. **The shared compile primitive is still less strict than the new r9 builder.** Current `compile_stage` rejects a nonzero ABI status, but controlled substitutions for false/float-zero ABI status, integer source_unchanged, false forbidden-module-list, boolean core_u32, mismatching result_u64 and wrong return_encoding all pass its existing checks. Its actual image slicing and receipt publication run in these controls; the transport return is explicitly substituted, so these are not spontaneous native compiler failures. The r9 `admit_compile_receipt` rejects every malformed case and accepts the unchanged positive control. PR891 does not modify `tools/qualify_hia_selfhost.py`, so transplanting that PR alone does not close this general receipt boundary.

4. **The foreign-cold identity gap is already closed in 673/8b9.** Five independent cases per builder (foreign profile, changed unrelated source hash, boolean returncode, float returncode, integer check flag) all refuse before output mkdir and without calling compilation. Current and PR891 `admit_cold_build` function source is byte-for-byte equal; the earlier 673 function is also equal. Our identity builder additionally captures/rechecks produced image bytes and records the profile. Replacing it with the PR891 file would remove those existing properties.

5. **The preserved PR891 test definitions pass in the explicit transplant setup.** All 13 tests passed: four original fragment provenance tests, four actual complete-output observation tests, and five identity admission/custody tests whose compilation is explicitly stubbed. Zero failures, errors, skips, expected failures or unexpected successes. The independent additional controls described above also completed. 837 held source/input files were unchanged. Total bounded harness time was 0.778208484 seconds; this is not a performance qualification.

## Narrow transplant recommendation

| Path | Preserve or change |
| --- | --- |
| `tools/qualify_hia_original_select_fragments.py` | Add exactly `validate_complete_output_observation` and `replay_complete_output_observation`; replace the old whole-output predicate in `qualify_case`. All old source/projection/SMT boundaries remain. |
| `tools/replay_hia_original_select_fragments.py` | Import and call the new replay helper for each retained whole-output witness. Preserve manifest, projection and fresh-SMT checks. |
| `tests/test_hia_original_select_fragments.py` | Preserve the existing four-test class unchanged and add the exact four-method `CompleteOutputObservationTests` class with its genuine machine counterexample and raw receipt controls. Run that class on an actual Linux x86-64 native gate with zero skips. |
| `tools/build_hia_agent_identity.py` | Keep the current implementation; no foreign-cold product transplant is needed. Do not drop its image readback or profile field. |
| `tests/test_hia_agent_identity_source_binding.py` | Preserve the PR's original source in evidence. If adding the five tests to the current tree, patch both `admission.current_sources` and the current builder's already-imported `current_sources` alias in test setup. This is an explicit setup adaptation only; retain every assertion and the clearly stubbed compile boundary. Current standalone-builder tests already cover broader malformed cold cases across seven selections. |
| Shared compile receipt checks | Treat further exact-type/input/output admission as a separate bounded change with actual child positive/ABI-failure controls plus controlled malformed transport controls. Do not label the PR891 transplant as fixing this untouched function. |
| Source contract / workflows / docs | Parent must add the new helpers/tests to its current union and regenerate the current contract. Do not copy PR891's older full support JSON or workflows over current owners. Preserve its prior cold-timeout evidence and conditional proof scope. |

Three exact textual transplant patches are included for review. No patch was applied to either source tree. `DIFF-ANALYSIS.json` records two new functions and one changed qualifier function; the replay function changes; the original test class has no AST changes.

## Boundaries retained

The raw replay helper uses the retained artifact manifest as its source of bytes; this review does not invent authenticity for arbitrary externally supplied manifests. No network or public exploit was asserted. The independently authored machine fixture proves a missing ABI check, not the behavior of all real compiler outputs. Controlled transport substitutions remain separately labeled. No original source or test failure was relabeled as a pass. Normalization's physical recursion, public/default route, installed current-source qualification and whole-stack deletion conditions remain open.

The durable evidence includes exact source snapshots, Git/SHA manifests, the unchanged PR tests, original raw child stdout/stderr/request/receipt/output/image bytes, all malformed-transport observations, independent harness and its complete result. Original 673/8b9 files are retained alongside the proposed versions.
