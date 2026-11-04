# Seven-certificate first-four diagnostic: proposed frozen design

Status: design only, awaiting independent design review. No runner implementation, Lean invocation, publication, proof admission, or performance conclusion is authorized by this document.

## 1. Inspected baseline and scope

Inspected actual generator, tests, source proposal, old diagnostic source builder/runner, capture collector, SafeRoot, original validators and workflow in `/workspace/shared/hepta-capture-replay`. Local checkpoint `e528c75b93133474f0dfc0a98411fe869e3aaacc` has tree `4a61b5a3f0e40bcac587f34ec34d928828090800`, matching the reported published `94e13f3` tree. Three seven-certificate source files remain untracked. The reviewed unpublished source-tree identity is `725609c15603fd7c54190893e993cc91f6404f49`; independently recheck that identity before implementation. Never publish checkpoint history in place of the published parent.

Read-only Python source construction and full source validation reproduced the seven manifest: 20,819 bytes, SHA256 `605e611b25c9b258150b7109d8f174c8514daac11b919d8f00363ab8db154787`. This establishes source facts only.

New entry points are proposed as `tools/core_seven_certificate_diagnostic_sources.py`, `tools/diagnose_core_seven_certificate.py`, and `tests/test_core_seven_certificate_diagnostic.py`. Leave all acceptance entry points and old source/diagnostic protocol semantics unchanged. A narrow enumerated collector mode is the only required shared capture change. Independent implementation review must inspect that change and its old-mode regression tests.

Schedule exactly Baseline, SyntaxData, CertPart01, CertPart02. Exact namespace-resolved axiom inventories are 56, 547, 271, 54, respectively. Counts supplement, never replace, the authenticated subject lists and print sequences. Unscheduled stages are exactly CertPart03, CertPart04, CertPart05, CertPart06, CertPart07, ConnectionsTransportRejections, WrongArm. Do not derive this list from the old original stage names.

CertPart02 consists of original global theorems 784 through 837 inclusive: 54 theorems and 42 definitions (96 declarations). First declaration is `HiaCoreSyntaxSlice.linear_k3_0`; first theorem is `linear_kd3_0`; final theorem is `linear_p0`. Its predecessor ends at original theorem 783, `linear_p154`. There is no linearRaw, linearBytes, root theorem or auxiliary byte-fact group in this target. All of those remain in CertPart03, unscheduled.

## 2. Distinct schema and frozen four-marker plan

Use protocol `seven-certificate-first-four-diagnostic-v1`, source-manifest schema `hepta.hia.seven-certificate-first-four-diagnostic.v1`, and result schema `hepta.hia.seven-certificate-first-four-result.v1`. Both are diagnostic-only and acceptance-ineligible. Use distinct logical collector target `SevenCertificatePart02`, which is not a Lean module name. Its capture files are `SevenCertificatePart02.stdout`, `.stderr`, `.events.jsonl`; its actual Lean source/output remains `HiaSyntaxResearch/CertPart02.lean`/`.olean`.

Freeze exactly these four sites, in source byte order:

- 000: before the complete definition `HiaCoreSyntaxSlice.linear_k3_0`, after import/namespace framing.
- 001: immediately after the complete theorem `HiaCoreSyntaxSlice.linear_p3` (original ordinal 810).
- 002: immediately after the complete theorem `HiaCoreSyntaxSlice.linear_p2` (ordinal 814).
- 003: immediately after the complete theorem `HiaCoreSyntaxSlice.linear_p0` (ordinal 837), before the namespace close.

Each exact command is `#check "HIA_SEVEN_DIAG_v1_P02_NNN"` followed by a single LF. Every command is 35 UTF-8 bytes, total 140. IDs are contiguous 000–003; maximum collector cap remains 24, but this protocol requires exactly four. Do not use old `HIA_DIAG_v1_P02_` IDs with new semantics. The final marker means only that a reporting command after p0 was observed. It precedes all 54 axiom prints and serialization, and cannot establish target completion.

Use exact marker row keys: id, text, sha256, original_offset, instrumented_offset, anchors, previous_command, next_command. Offset units are bytes in the uninstrumented seven-certificate source and its instrumented derivative, not offsets in the old partition. Derive command descriptors and qualified anchors from actual validated bytes, not producer-supplied rows. Freeze anchor descriptions and ordinals above independently of generated metadata. Require all offsets to be exact integers (reject bool), ordered, distinct, inside source bounds and at complete command boundaries. Bind neighboring commands by kind/name/start/end and recompute them.

Strip only the four recorded exact byte intervals. Prove the result equals all 21,943 original target bytes; reject unknown markers, additional #check commands, reordered/duplicate IDs, gaps, changed line endings and injected proof text. Independently recompute the site plan and manifest after stripping. First three stages must be identical to the seven-certificate proposal including imports, metadata and inventory. No source difference except the four exact marker insertions is permitted.

The collector's fixed target table must map the new logical target to its new filenames/prefix, preserving both existing mappings byte-for-byte. Never accept caller-supplied arbitrary prefix or filenames. Old observers must reject new planned IDs and new observers must reject old planned IDs. In the new mode, a complete marker-looking output line with a known foreign namespace must fail closed; do not reinterpret it. Preserve old raw observers unchanged: they do not recognize new IDs, and old validators reject new plans/manifests before capture. Cross-protocol rejection means refusing foreign evidence, not retroactively changing old raw-observer behavior. Ordinary diagnostic text is not a marker. Recognition remains exact complete stdout records only; stderr lookalikes do not count. Test cross-mode raw streams as well as planning arguments. The default capture target remains unchanged.

## 3. Source validation and exact retention

Before marker derivation, any evidence write or launch: run the complete unchanged original validation, then `seven.validate_sources` over all eleven candidate sources. This must perform independent framing/declaration inversion to all old transformed sources, invoke unchanged byte-fact validation and complete old partition/original checks, recover all five original transport byte streams and consumers, and check all five byte/input bindings, 7,685 definitions, 4,215 original theorems, 2,975 byte facts, 66 targets and ten negatives. Preserve current and historical negative-coordinate ledgers separately. Also require fixed seven DAG, complete independent inventories, root ownership, reference visibility and consumer isolation. Marker derivation must not substitute a four-stage check for this whole-input validation.

Retain exactly 23 Lean source files:

- Eleven original exact-partition files under `original/<old-name>.lean`, totaling 2,400,382 bytes. Old names are Baseline, SyntaxData, CertPart01–06, Connections, TransportRejections, WrongArm.
- The eleven uninstrumented seven-layout files, totaling 3,192,972 bytes. Place the first three directly at `HiaSyntaxResearch/Baseline.lean`, `HiaSyntaxResearch/SyntaxData.lean`, `HiaSyntaxResearch/CertPart01.lean`; these are their sole retained copies and execution paths. Place the other eight at `seven/CertPart02.lean` through `seven/CertPart07.lean`, `seven/ConnectionsTransportRejections.lean`, `seven/WrongArm.lean`.
- One instrumented target at `HiaSyntaxResearch/CertPart02.lean`, exactly 22,083 bytes.

Total retained source bytes: 2,400,382 + 3,192,972 + 22,083 = **5,615,437**, leaving 2,773,171 bytes under 8,388,608. Largest source remains 550,810 bytes, under 2,097,152. No separate marker-text file, duplicate parent execution copy or source-containing display/evidence archive is planned. The 140 marker bytes are counted within the marked target; manifest metadata also binds their exact text. Any independently retained marker/source copy must be included as actual bytes in `validate_retention` before writing/launching, including copies outside the import package or in an evidence bundle. A manifest claiming zero execution copies in the source-only proposal is not the run's accounting: retain that proposal unchanged and record the run's additional marked copy explicitly in the diagnostic manifest.

The old transformed eleven are temporary bounded validation intermediates only, never a third retained source generation. Do not weaken validation to avoid reconstruction. Do not write intermediate source files or archives. A layout that saves originals + old transformed + new transformed exceeds the budget and must be rejected.

First-four uninstrumented sizes/hashes:

- Baseline: 30,632; `8c615ecd34ae3e67c6ecc78d57cacca3437cc53ec3efcbd18c6b505f54127f31`.
- SyntaxData: 325,951; `18bad1174ea82a3f5a2e401c58672df6378f8f45c1c426f695bc5856de64fc06`.
- CertPart01: 118,863; `4e441e13fcb6d90223c0691dcdc4d3cce540bebbce9dad2f5d7e0d0c4fe724e0`.
- CertPart02: 21,943; `910e0b5d81fcb8acb783fc906b58addc6734101243dc9ee220585c049ba27206`.

Generate, independently validate and freeze the marked SHA256 and exact byte offsets during implementation review; this document does not fabricate them. Both new manifests individually remain <=32,768 serialized bytes. Preserve the original manifest's existing cap/schema rather than retrospectively changing it.

## 4. Fresh execution and fixed budgets

Baseline has no generated parent. SyntaxData's direct generated parent is `HiaSyntaxResearch.Baseline`; CertPart01's is `HiaSyntaxResearch.SyntaxData`; target's is `HiaSyntaxResearch.CertPart01`. Their corresponding parent module paths end in `/Baseline.olean`, `/SyntaxData.olean`, `/CertPart01.olean` under `HiaSyntaxResearch/`. Baseline's locked external support plus implicit Init must be validated independently; do not confuse external support with fresh generated-parent receipts.

Create an exclusive SafeRoot. Reject existing output, symlinks at every ancestor, hardlinks, nonregular entries, unexpected directories/files, path escape and support-prefix shadowing. Enforce stable descriptor/inode identity and source/support/binary hashes before and after preparation, every process and finalization. Set LEAN_PATH only to this run's package, remove LEAN_SRC_PATH, use the pinned sysroot and exact pinned executable bytes. No old olean or old receipt may be copied/imported.

Each first-three parent needs its own started/finished receipt, full raw stdout/stderr, exact permitted axiom inventory and nonempty bounded olean. Require strict integer exit 0, timeout=false, incomplete=false, output_truncated=false and authentic command/environment/timeout receipt. Bind source, exact parent receipt hashes, parent module hashes/bytes, run identity, stdout/stderr hashes and produced module hash/bytes. Only after all checks may it enter this run's temporary parent map. This is diagnostic dependency admission, never full connection acceptance.

The target capture needs a prelaunch started record binding the same-run parent map, instrumented source, logical capture target, identity and manifests. Its terminal record must bind that started record. This explicit target provenance must not be omitted because the old runner only kept target process metadata. No target output enters the accepted-parent map, even with exit 0. Freeze it solely as untrusted bytes if present. No fifth process can launch, regardless of target outcome. A completed target may receive a separate exact 54 inventory receipt marked diagnostic-only; missing/extra/forbidden axioms invalidate that receipt. Target timeout/partial logs never yield an inventory success receipt.

Preserve 60 seconds/process, 540 seconds new-launch deadline, 600 seconds external command, 15 minutes job, at most four diagnostic invocations, 2 MiB per source, 8 MiB total retained sources, 32 MiB per olean, 128 MiB total oleans and 1 MiB diagnostic/presentation cap. Preserve collector cleanup 2 s, total 1,048,576, display-label reserve 1,024, durable-total 523,776, raw 507,392, metadata 16,384, internal 12,288, terminal reserve 4,096, read chunk 16,384 and marker cap 24. No fallback, retry budget, fifth launch or limit increase. If launch counting becomes uncertain, record uncertainty and stop. A failed pre-spawn collector counts zero only with a trustworthy process_started=false receipt.

Plan for possible target exit 0 with all 54 inventory print lines, not merely marker output. Conservative illustrative JSON sizes using 60.999999 seconds, five-digit offsets and three-digit chunk bytes: receive 93 bytes; marker 209 bytes. Fifty-eight separately received lines (54 prints + 4 markers) plus four marker events require 6,230 bytes before the start record, leaving 1,962 of the 8,192 live budget. The old observed 1,433-byte start would leave 529, but the new actual start receipt may differ. Implementation review must serialize its actual bounded path/argv/start record and a representative full 54 inventory trace, verify fit, and test overflow. This is a scenario, not a guarantee: arbitrary fragmentation, longer receipts, warnings/errors or multi-line output can exhaust metadata. Existing batch reservation and fail-closed truncation rules stay unchanged; no receive coalescing or dropped replay records is proposed.

## 5. Frozen evidence and independent replay

Fixed preparation files: RUN.json, IDENTITY.json, original-manifest.json, seven-manifest.json, diagnostic-manifest.json. RUN binds protocol/schema, exact four-stage schedule, invocation limit, Git/source baseline and all three manifest hashes plus IDENTITY hash. IDENTITY binds exact source-path hash map, full support map and pinned Lean binary. The diagnostic manifest binds original/seven manifests, complete four-stage source/module/parent/inventory identities, target original/marked identities, fixed marker plan, unscheduled names and exact path/byte accounting.

Frozen file allowlist consists only of preparation, the 23 source files, four possible output oleans, first-three started/stdout/stderr/finished receipts, target-started receipt, three new capture files, optional diagnostic-only target inventory receipt, EVIDENCE.json and RESULT.json. Record receipt names explicitly; do not allow arbitrary extensions or files based on a supplied manifest. EVIDENCE hashes every retained noncontainer file, including untrusted partial modules/logs; RESULT binds EVIDENCE. Keep EVIDENCE/RESULT acyclic. Do not overwrite original frozen hashes when mutation is detected. Report failure and reject trusted presentation instead.

### Exact receipt names and terminal prerequisites

Preparation means all five files listed above plus every one of the 23 source files. The four allowed output paths are exactly `HiaSyntaxResearch/Baseline.olean`, `HiaSyntaxResearch/SyntaxData.olean`, `HiaSyntaxResearch/CertPart01.olean` and `HiaSyntaxResearch/CertPart02.olean`.

Parent receipt/log files are exactly:

- `Baseline.started.json`, `Baseline.stdout`, `Baseline.stderr`, `Baseline.finished.json`.
- `SyntaxData.started.json`, `SyntaxData.stdout`, `SyntaxData.stderr`, `SyntaxData.finished.json`.
- `CertPart01.started.json`, `CertPart01.stdout`, `CertPart01.stderr`, `CertPart01.finished.json`.

The target's prelaunch receipt is exactly `SevenCertificatePart02.started.json`. Its optional completed-only inventory receipt is exactly `SevenCertificatePart02.inventory.json`. Target process terminal metadata lives only in `SevenCertificatePart02.events.jsonl`; there is no target finished/admission receipt. The capture raw names are exactly `SevenCertificatePart02.stdout` and `SevenCertificatePart02.stderr`. Containers are exactly `EVIDENCE.json` and `RESULT.json`.

Prerequisites are derived from fixed stage order and actual launch history, not merely a claimed final status:

1. A successful parent stage requires preparation, its started/stdout/stderr/finished files and its nonempty bounded olean, plus all earlier successful parent chains. Its finished status is `parent_checked`. A later started receipt cannot exist without every earlier successful parent chain. Parent invocation accounting remains exact where known, bounded by four always.
2. A failed parent stage permits only the successful earlier prefix, that parent's started record when launch was attempted, and whichever raw logs/output actually exist. If its started receipt exists and finalization succeeds, its finished receipt is mandatory with status `failed`, failure details and the actual process outcome when available. No inventory success or accepted module identity may be synthesized from its partial output. Freeze any available failed olean as untrusted bytes. No later parent or target started/capture/inventory file is allowed. If preparation itself fails or a filesystem failure prevents mandatory receipt/container closure, report incomplete evidence; never claim a validated failure container or markers. Valid earlier parent chains may be reported only after their own independent verification.
3. Any actually started target requires preparation, all three complete successful parent chains, `SevenCertificatePart02.started.json`, and all three target capture files with one collector start and one terminal. Target-started parents must exactly equal those chains. The target may have a partial or absent olean except in completed status. No target inventory receipt is allowed unless completion is independently verified.
4. `diagnostic_completed` requires exactly four invocations, the first three successful parents and target, every prerequisite in item 3, all four marker observations, exact 54-subject target inventory receipt, and nonempty bounded untrusted target olean. Require all completed-only process flags stated below. Target remains unadmitted.
5. `diagnostic_timeout` requires exactly four invocations, item 3, timeout-consistent terminal/result flags, and no target inventory receipt. Target olean is optional and untrusted. Complete timeout replay can validate only observed marker frontiers. Cleanup or drain failure instead yields incomplete target evidence and no validated marker observations.
6. `diagnostic_output_limit` after target launch requires exactly four invocations and item 3 if a complete terminal container was written; the inventory receipt is forbidden. The result/terminal must identify the raw or metadata limit reached and agree on retained/observed byte counts and truncation. Partial capture files remain hash-bound but cannot yield validated target marker observations. A missing mandatory terminal/container means incomplete evidence, not a successful output-limit replay.
7. `diagnostic_failed` and `diagnostic_infrastructure_failed` are stage-sensitive. A parent failure follows item 2. A target failure after launch follows item 3 with exactly four invocations and no inventory receipt. A target pre-spawn infrastructure failure requires the three successful parent chains and target-started record, a trustworthy process_started=false outcome, and exactly three invocations; there must be no target olean or inventory receipt. Capture files are allowed only if the collector created them, and all existing bytes must be bound. Preserve the existing collector write order: its kind=start row is a setup-start record written before subprocess.Popen, not evidence that a process launched. A pre-spawn failure may therefore have zero or one setup-start row, according to failure location: early platform/preflight failure may have none, while spawn failure may have one. Any such setup-start row and the terminal must retain process_started=false; no receives, marker events, process_started=true assertion or target output module is allowed. A claimed complete container requires exactly one consistent nonstarted terminal, last in the event stream. A missing capture terminal is recorded as incomplete failure evidence, never inferred process success. An uncertain launch count must be marked uncertain, bounded, and stops all launches; it cannot satisfy a completed/timeout terminal classification.
8. No failed status may include a fourth admitted module, downstream stage, success inventory from an unsuccessful target, or files outside this fixed allowlist. Every claimed complete container requires EVIDENCE and RESULT and all status-specific prerequisites. Files missing because finalization was interrupted are reported as incomplete rather than retroactively waived. Hash-valid failure containers can establish only the failure and independently validated evidence, never acceptance.

Replay/presentation must first verify the entire allowlist and exact path set, every hash and cap, canonical JSON and strict field types, protocol/schema and all DENY/unproved/false flags. Reconstruct original preparation from pinned source identity and compare every retained original source and original manifest; reconstruct candidate objects from every retained seven source and independently derived inventories. Invoke full unchanged original validation and seven-source inversion/validation, then validate marker derivative. Do not trust candidate-supplied expected lists or simply reuse the old diagnostic's provenance verifier, which assumes six certificate parts and a per-file byte-fact inverse. No Lean process is permitted during replay.

Recompute total source retention from actual files and any separately retained copies. Recompute stage DAG, inventories, manifest chain, source identity path set, support/binary bindings and all parent receipt/module chains. Require sequential first-three success receipts before target start; verify target-started parents exactly match this run, and reject any target admission or downstream receipt. Reconcile invocation counts and statuses with started/finished/capture evidence; partial failures may be reported only as failures, never successful missing stages.

Replay every raw stdout/stderr byte through the exact new observer in the recorded receive order, with contiguous offsets, exact sizes, finite nonnegative monotone receive times, stdout-only complete marker recognition and immediate corresponding marker-event rows before the next receive. Require one start when actually started, one final terminal, no unknown events, no events after terminal, exact marker event equality and terminal raw identities/count/last marker. For diagnostic_completed only, require strict integer exit 0, leader reaped, drain complete, cleanup not incomplete, no output truncation, all four marker observations, the exact 54-subject diagnostic inventory receipt and a nonempty bounded target olean retained as untrusted bytes. These exit-0/completion requirements do not apply to diagnostic_timeout or diagnostic_failed. For a timeout, require the collector's timeout/deadline and cleanup termination semantics, actual return code (or its explicitly incomplete state), and agreement between terminal and result. For a process failure, require its actual nonzero exit or explicitly recorded collector error, never inventing a successful receipt. A timeout or failure with complete, consistent raw/event replay and completed drain/cleanup may expose its observed marker prefix as asynchronous diagnostic observations, never a target inventory or admission. If truncation, missing raw/event bytes, incomplete drain/cleanup or inconsistent terminal prevents complete replay, retain and hash-check available failure bytes but do not present validated target marker observations. Enforce all raw/metadata/durable-plus-display budgets using actual serialized bytes. Failed/incomplete replay is never presented as validated marker evidence.

Only after all evidence passes may presentation emit bounded output, and it must reread/recheck every frozen file and directory identity immediately before emitting any trusted text. Missing final RESULT is explicitly incomplete, not inferred success. Hash binding is integrity within the verified run, not a signature proving provenance on a hostile host; publication must also authenticate the workflow/run/HEAD source.

## 6. Source identity and publication review

The exact identity key set is the union of the current `tools.diagnose_core_byte_facts.source_identity()` map (including its transitive original identity and all current hepta Python sources), the new source generator, diagnostic source builder, runner, their tests and design/source proposal docs. Appendix A enumerates the current inherited path set. Add, explicitly:

- tools/core_seven_certificate_sources.py
- tools/core_seven_certificate_diagnostic_sources.py
- tools/diagnose_core_seven_certificate.py
- tests/test_core_seven_certificate_sources.py
- tests/test_core_seven_certificate_diagnostic.py
- docs/seven-certificate-source-proposal.md
- the eventual checked-in diagnostic design document

Keep existing capture/old marker/byte-fact/source/validator/helper/workflow dependencies in the inherited map, even if imported only for validation. Bind any added replay helper/test/workflow file explicitly if implementation introduces it. Freeze both key set and bytes in the reviewed implementation; reject deletions/additions/substitution after preparation. Source identity is not just the three new source files or Git HEAD.

Before publication, require independent design approval, implementation approval with adversarial/old-mode tests, actual marker-manifest/retention/metadata serialization audit, unchanged original validators/acceptance gates, pinned workflow bounds and a clean exact reviewed tree. Recheck published remote HEAD and build any authorized publication commit with that actual remote parent; do not push local checkpoint history. Workflow must invoke only the new nonaccepting runner at the exact reviewed HEAD, retain diagnostics through its new replay gate and preserve outer limits. Verify remote commit/tree and workflow run head after any separately authorized publication. The current design is not publication authorization.

All results retain DENY_ALL, all 12 obligations unproved, kernel_core_syntax_connection_checked=false, actual_core_bridge_proved=false, python_exporter_refinement_proved=false, body_prefix_refinement_proved=false and all_edge_transfer_proved=false. Command exit must remain nonaccepting, including diagnostic_completed. Four successes would say nothing conclusive about linear roots, later inputs, combined consumers or complete connection. No timing estimate follows from this design.

## 7. Required tests and independent review gates

1. Whole-source round trip, explicit unchanged full validator calls, all five bindings/66 targets/ten negatives; force old validators to fail and require diagnostic rejection before source writes or any process.
2. Exact 96 declaration/54 theorem target, no root/fact group; shifted cuts, altered definitions/proofs, deleted/duplicate names, forward/cyclic references, WrongArm contamination, dropped support prints and forged/rehashed inventories all reject.
3. Exact four sites and complete byte stripping; false ordinals, wrong neighbor descriptors, bool offsets/counts, duplicate fields, noncanonical JSON, extra unknown fields, altered newline, malicious marker command and old/new schema confusion reject.
4. Old two collector modes remain byte-compatible. All combinations of old/new marker plans, logical target, manifest reference and filenames fail cross-protocol checks. New mode rejects old raw IDs; old raw modes ignore new IDs exactly as before and cannot validate a new marker plan or evidence container. Split chunks and exact stdout records work; stderr/lookalike/partial lines never count.
5. Preflight exact 5,615,437 source bytes; detect duplicate parent copies, evidence copies, separate marker text, forbidden intermediate generation, per-file/aggregate overflow, manifest overflow and actual 54-print metadata scenario/fragmentation overflow without changing caps.
6. Mock successful first-three parents and target exit 0 with 54 inventory rows: exactly four invocations, target never admitted, no fifth stage, all denials fixed. Missing/extra/forbidden axiom and bad completed flags reject. Parent timeout, exit failure, missing output, stale/same-name foreign receipt, changed support/source/binary, wrong module path and forged parent graph prevent later launches.
7. Fresh-root/ancestor/file symlink, hardlink, inode replacement, unexpected file, stale target olean, output-prefix shadowing, permission/write failure and output oversize fail closed. Test state mutation at every preparation/prelaunch/postlaunch/finalization/replay boundary.
8. Replay mutations of every manifest/identity/receipt/raw/event/module/source, even with downstream hashes recalculated, must reject semantic inconsistencies. Test target parent receipt substitution, missing target-started record, reordered receives/markers, holes/overlap, NaN/bool timestamps, missing/duplicate terminal, stream swap, manifest swap, invocations>4, partial containers and all budget limits.
9. Successful mock replay must run full inverse validation and emit nothing trusted before its final complete reread. Deliberate mid-replay mutation must suppress trusted presentation. Foreign protocol containers must never be accepted by old or new presentation/acceptance paths.
10. Independent reviewer verifies actual source tree and new protocol's frozen manifest before any real execution. Mock/static tests and source serialization are not Lean or performance evidence. A real bounded diagnostic, if later authorized, is a separate measurement and remains nonaccepting.

## Appendix A: exact inherited source identity paths at inspection
- .github/workflows/hia-core-syntax-kernel-research.yml
- .github/workflows/hia-guarded-slice-kernel-research.yml
- benchmarks/hia_reduction_release/affine.hepta
- benchmarks/hia_reduction_release/linear.hepta
- experiments/hia_initialization_frontiers_20261103/ByteFactsResearch.lean
- experiments/hia_initialization_frontiers_20261103/CoreSyntaxSlice.lean
- experiments/hia_initialization_frontiers_20261103/GuardedUsizeSlice.lean
- experiments/hia_initialization_frontiers_20261103/StructuredTransport.lean
- formal/HiaInitializationPrefix.lean
- formal/proof-dependencies.txt
- formal/toolchain-lock.json
- hepta/__init__.py
- hepta/__main__.py
- hepta/agent_contract_diff.py
- hepta/agent_semantics.py
- hepta/artifact_publication.py
- hepta/ast.py
- hepta/backend.py
- hepta/borrowed_storage.py
- hepta/c_aliases.py
- hepta/c_allocation.py
- hepta/c_backend.py
- hepta/c_contracts.py
- hepta/c_definite_assignment.py
- hepta/c_import.py
- hepta/c_loop_control.py
- hepta/c_migrate.py
- hepta/c_migration_project.py
- hepta/c_parameter_types.py
- hepta/c_project.py
- hepta/c_project_matrix.py
- hepta/c_record_views.py
- hepta/c_resource_matrix.py
- hepta/c_scalar_matrix.py
- hepta/c_translation.py
- hepta/cfg.py
- hepta/cfg_analysis.py
- hepta/checker.py
- hepta/clang_capture.py
- hepta/cli.py
- hepta/concurrent_ir.py
- hepta/concurrent_lowering.py
- hepta/core.py
- hepta/cpp2hepta.py
- hepta/cpp_bridge.py
- hepta/cpp_callback_project.py
- hepta/cpp_class_migrate.py
- hepta/cpp_composed_migrate.py
- hepta/cpp_composed_project.py
- hepta/cpp_contracts.py
- hepta/cpp_gsl_final_action.py
- hepta/cpp_host_toolchain.py
- hepta/cpp_json_checkpoint.py
- hepta/cpp_owned_migrate.py
- hepta/cpp_project_migrate.py
- hepta/cpp_scoped.py
- hepta/cpp_unique_assignment.py
- hepta/cpp_unique_capture.py
- hepta/cpp_unique_project.py
- hepta/cpp_unique_reset.py
- hepta/darwin_capture.py
- hepta/debug_info.py
- hepta/elf_shared_abi.py
- hepta/executable_core.py
- hepta/executable_core_qualify.py
- hepta/executable_core_runtime.py
- hepta/flow_ir.py
- hepta/hia_adaptive.py
- hepta/hia_agent_assembly.py
- hepta/hia_artifact_session.py
- hepta/hia_background_optimizer.py
- hepta/hia_bounded_memory.py
- hepta/hia_bounded_unroll.py
- hepta/hia_bounded_wire.py
- hepta/hia_bundle_atomic.py
- hepta/hia_call_expansion.py
- hepta/hia_capability_flow.py
- hepta/hia_continuation.py
- hepta/hia_core.py
- hepta/hia_core_upgrade.py
- hepta/hia_crc_kernel.py
- hepta/hia_crc_linear.py
- hepta/hia_durable_queue.py
- hepta/hia_economic_search.py
- hepta/hia_edit_batch.py
- hepta/hia_edit_query.py
- hepta/hia_empty_reduction.py
- hepta/hia_finite_actions.py
- hepta/hia_finite_context.py
- hepta/hia_full_cost_gate.py
- hepta/hia_guarded_batch.py
- hepta/hia_guarded_optimization.py
- hepta/hia_heap_bound.py
- hepta/hia_host_region.py
- hepta/hia_incremental.py
- hepta/hia_inductive.py
- hepta/hia_initialization.py
- hepta/hia_invocation_bank.py
- hepta/hia_json_preflight.py
- hepta/hia_l1_receipt.py
- hepta/hia_migrate.py
- hepta/hia_multiversion.py
- hepta/hia_narrowing.py
- hepta/hia_native_differential.py
- hepta/hia_native_paired_replay.py
- hepta/hia_native_retirement.py
- hepta/hia_ndu.py
- hepta/hia_ndu_cache.py
- hepta/hia_ndu_cost.py
- hepta/hia_ndu_optimizer.py
- hepta/hia_ndu_response.py
- hepta/hia_ndu_session.py
- hepta/hia_ndu_stateful.py
- hepta/hia_opcodes.py
- hepta/hia_optimization.py
- hepta/hia_optimization_contract.py
- hepta/hia_oracle.py
- hepta/hia_paired_holdout.py
- hepta/hia_patch_impact.py
- hepta/hia_planning.py
- hepta/hia_prepared.py
- hepta/hia_program.py
- hepta/hia_program_aarch64.py
- hepta/hia_program_composite.py
- hepta/hia_program_llvm.py
- hepta/hia_program_runtime.py
- hepta/hia_program_source.py
- hepta/hia_program_tools.py
- hepta/hia_queue_commit.py
- hepta/hia_reduction.py
- hepta/hia_routes.py
- hepta/hia_rust_byte_cleanup.py
- hepta/hia_rust_byte_dag.py
- hepta/hia_rust_crosscheck.py
- hepta/hia_scalar_call_validation.py
- hepta/hia_scalar_lowering_check.py
- hepta/hia_scalar_state.py
- hepta/hia_scalar_totality.py
- hepta/hia_schema.py
- hepta/hia_source_bridge.py
- hepta/hia_specialization.py
- hepta/hia_stateful.py
- hepta/hia_static_budget.py
- hepta/hia_stb_specialization.py
- hepta/hia_swap_opt.py
- hepta/hia_translation_validation.py
- hepta/hia_x86_search.py
- hepta/hmir.py
- hepta/hsir.py
- hepta/lexer.py
- hepta/llvm_ir_profile.py
- hepta/llvm_owned_aarch64.py
- hepta/llvm_owned_backend.py
- hepta/llvm_owned_pipeline.py
- hepta/llvm_ssa_backend.py
- hepta/llvm_ssa_pipeline.py
- hepta/llvm_ssa_target.py
- hepta/migration_ir.py
- hepta/modules.py
- hepta/native_local_views.py
- hepta/native_mapping_identity.py
- hepta/native_resource_gate.py
- hepta/native_tool_identity.py
- hepta/object_structure.py
- hepta/object_symbols.py
- hepta/owned_aarch64_link.py
- hepta/owned_aarch64_runtime.py
- hepta/owned_drop_plan.py
- hepta/owned_target_layout.py
- hepta/packages.py
- hepta/parser.py
- hepta/pipeline.py
- hepta/protocol.py
- hepta/protocol_v3.py
- hepta/resource_ir.py
- hepta/resource_lowering.py
- hepta/resource_source.py
- hepta/runtime_concurrency.py
- hepta/runtime_io.py
- hepta/runtime_task_io.py
- hepta/runtime_task_tree.py
- hepta/scalar_host_abi.py
- hepta/semantic_ir.py
- hepta/source_map.py
- hepta/ssa.py
- hepta/ssa_reaching.py
- hepta/ssa_verify.py
- hepta/static_resource_contracts.py
- hepta/windows_capture.py
- hepta/workspace.py
- tools/bootstrap_verification.py
- tools/check_core_syntax_lean.py
- tools/check_core_syntax_partitioned.py
- tools/check_core_syntax_staged.py
- tools/check_dynamic_unsigned_step.py
- tools/check_guarded_slice_lean.py
- tools/check_initialization_frontiers.py
- tools/core_byte_facts_dag.py
- tools/core_byte_facts_diagnostic_sources.py
- tools/core_byte_facts_sources.py
- tools/core_byte_facts_verify.py
- tools/core_syntax_declaration_diagnostic_sources.py
- tools/core_syntax_diagnostic_capture.py
- tools/core_syntax_partition_diagnostic_sources.py
- tools/core_syntax_partition_sources.py
- tools/core_syntax_stage_sources.py
- tools/core_syntax_structured_sources.py
- tools/core_syntax_structured_stages.py
- tools/diagnose_core_byte_facts.py
- tools/evidence_checks.py
- tools/experimental_deferred_guard_proposer.py
- tools/extract_initialization_obligations.py
- tools/qualify_hia_initialization_prefix.py
- tools/qualify_hia_selected_formal.py
- tools/research_deferred_guard_model.py
