# HIA native rewrite: execution interruption checkpoint

This checkpoint preserves source text and precise work state after the local execution environment became unavailable. It is not the completed R15 evidence publication and does not certify an installed native replacement.

## Verified Git baseline

- Repository: TrillionniumFoundation/Hepta.
- Product main remains `5831f52fada45e076f8f68f198a15c0585e6104f`.
- Audited candidate remains `0ef9541b2fc12f4b01ab5078b05d0b304cfa90f5`.
- Latest complete evidence checkpoint before this interruption is R14, commit `bef1b176882a7c8c2bf50580b7c1958c0f60a188`, tree `afb7e540b81639a6a98b7d5c82e9f9944f859eaa`.
- R14 adds 29 files / 22,511,730 bytes. Its 3,327 blob entries were checked against the original and new expected SHA, mode and size.
- This checkpoint is added only to the recovery branch. No product default switch or legacy owner deletion is claimed.

The R13 audit covered all 2,798 tracked candidate files and 100,772,825 bytes. All 1,130 Python files parsed. The inventory included 156 package modules, 302 hosted tools, 65 HIA assembly sources and 12 HIA JSON sources. This is a complete static inventory, not evidence that every behavior is natively replaced.

## Text retained here

`manifest.json` identifies every text file, its exact Git blob identity and its provenance. Root fetched all twenty-one text blobs and independently recomputed their Git blob identities.

Two service-records authoring files were copied from complete tool readback performed before the interruption. Their content is retained, but byte comparison against the presently inaccessible original files is still required. The four CLI source drafts, the superseded CLI executor, the CLI notes, the service plan/notes, two service-record test drafts and the namespace constraints are new text written during the interruption. They have not been generated, compiled or executed as an installed CLI/service.

The first executor draft's static environment-pointer defect is retained under `superseded/`; later drafts and the earlier text manifest/notes are retained there too. The current executor is the fourth new source-only revision. Independent static review found private frame destination and terminal-view validation gaps, which were corrected in that source revision; no native test is claimed. The new CLI controller text is also explicitly a new revision of a draft whose original local apply_patch acknowledgement was initially missing. That operation later returned a write-failure acknowledgement (exit 1 after 682.2s); its separate receipt is retained without asserting whether a partial local file exists. The older CLI text manifest preserves its original observation. The filesystem-v2 authoring generator is also retained from its successful patch text; no native or VM test of that extension is claimed.

Python authoring files are development inputs. Their existence is not a claim that the final product is exclusively HIA. The proposed runtime semantics live in generated HIA; the mechanical ELF template and all remaining authoring/bootstrap dependencies still require a complete ownership and release assessment.

## Previously completed local work that is not in this commit

Five sealed local archives were ready or nearly ready for the intended R15 publication: CLI file handling, CLI pretty output, tool schema, namespace filesystem and the CLI compact Graph wire pair. The manifest records their exact observed sizes and SHA256 values. The first four had completed independent root member and expanded-payload readback. The compact-wire archive had agent readback; the root readback's terminal result was not observed.

Their bytes were not uploaded to this Git checkpoint. The interruption prevents a new local read; it does not prove that they were deleted. Do not replace the original archive bytes with reconstructed text or transfer their historical test claims to a new build.

Completed local observations included:

- CLI file handling: 36 public/path cases, 20 private controls and 8 lifecycle/error-order controls, including actual 8MiB reads, growing/truncated files, short reads, UTF-8/surrogateescape/NUL, directory/symlink/FIFO behavior and close after allocation failure.
- CLI pretty output: 249 layout cases, 9 actual metadata chains and 27 protocol cases; output above 8MiB was exercised. Original counterexamples remain in the local archive.
- CLI compact wire: 688 retained worker cases and 204 CLI cases, including a 9,437,220-byte compact result and a 9,437,230-byte pretty result. One aggregate driver failed on an incorrect private-fixture growth assumption; a separate corrected protocol panel passed. This is not an aggregate-pass substitution.
- Tool schema: all 26 roots / 232 distinct admitted catalog schemas were covered through completed and continuation panels. The first aggregate process exited 137 with unknown cause. A wire error-acknowledgement bug was fixed and 6,147 original semantic transcripts replayed against the actual revised wire image. Arbitrary external schema/regex and dynamic catalog loading remain open.
- Namespace filesystem: fourteen raw filesystem primitives and five actual process cases, with 78 HIA entries compared to complete VM buffers. Earlier private counterexamples and corrections are retained. This does not close the namespace coordinator or SQLite migration fence.

## Program inspection work interrupted before final-source qualification

A new HIA projection component implements inspection summaries, verified-program reports, exact function/block views, normalized Core objects and normalization reports. The component compiled with the existing B3 limits. Its 310 semantic cases over 28 programs and 102 private controls passed before the interruption.

A fixed ELF service then connected actual source admission, receipt validation, fresh hashing, decoding, Graph merge, projection and wire output. The first service build passed 310 worker cases; a later build using the new CLI wire passed 310 CLI cases. A valid exact-8MiB source produced an 8,389,414-byte CLI inspection JSON result successfully. The enclosing aggregate driver later exited 137; the cause is not established and no later worker result from that run is claimed.

Independent review requested stronger checks on the merge parent node, issued Graph leases and event/header/root agreement. A new query revision implemented those checks and compiled under unchanged limits. An authoring output-path mistake was preserved as a separate failed attempt; the old HIA source was restored to its original hash.

The final revised service was built, and a 620-case two-policy semantic panel plus the exact-8MiB worker check were launched. Their terminal results were not observed before execution access was lost. They remain unqualified. The successful earlier build's results cannot certify the revised build.

## Confirmed open semantic defect: candidate snapshot limits

A nine-case candidate-edit probe found three real differences before the interruption. For nested candidate values at depths 57, 58 and 119, the original implementation returned:

`E_HIA_LIMIT: caller-owned tree exceeds snapshot budget`

The candidate native path instead terminated through private ABI failure at role 59. This defect remains open. No fix or passing regression is included here.

The next probe was intended to distinguish queued-node limits from depth limits while preserving caller insertion order. It was launched but its result was not observed. A correct fix must reproduce the caller-owned bounded snapshot traversal before candidate canonical rendering, preserve the request's insertion order for diagnostic precedence, and validate any new private witness before publishing the exact public error. The existing complete-candidate byte-limit witness must remain separately checked.

## Namespace observations from the original source

The namespace source review here retains exact original Hepta and SQLite source identities. Root UID zero is a valid observation. A writer lease requires a successful real exclusive lock and must be tied to the issued filesystem context and actual lock object.

SQLite 3.46.1's default busy handler budgets requested sleep durations, not a monotonic wall-clock deadline. Its exact delay table and final clipped delay matter; Unix sleep does not restart the remainder after EINTR. A JavaScript model of the original table yields 109 sleep calls totalling 10,000ms under continuous contention. This is a static model, not a native runtime test.

A new flock-based LOCK file does not fence an already running SQLite WAL writer. The old WAL lock and in-process sibling bookkeeping must be addressed by a real migration/ownership protocol before legacy storage can be removed.

## Full product qualification remains HOLD

The last complete retained qualification of candidate `0ef9541b` ran on ROG. Its durable job is `1a1cab94f66-2564-82c`; the terminal status and complete logs were successfully re-read during the interruption. Twenty-seven earlier steps passed. The final 4,157-test regression reported 187 errors, one failure and 18 skips, returning 1 without timeout, cancellation or output truncation. The 188 errors/failure directly referenced three missing NDU binaries; the actor that removed them is unknown.

That older qualification is not a matching-source qualification of R13, R14 or the new local R15 work. No whole-product acceptance is claimed.

Still open are the installed CLI and final process/file handoff, complete worker business dispatch, service/journal integration, namespace lock issuance and durable migration, remaining build/proof/VM/evaluation/library/compiler ownership, patch/impact/assembly surfaces, exact diagnostic edges, the confirmed candidate snapshot defect, and a final cold/retained qualification with the required components present.

## Recovery procedure

1. Keep the R14 commit and all new text identities immutable.
2. Recover the interrupted filesystem when access is available, then compare every original source/archive to its recorded bytes, hashes and custody records before resuming publication.
3. If continuing in another configured host, restore only from verified Git archive parts and exact manifests. Record this as a new execution location.
4. Inspect unfinished process outputs before deciding whether to rerun. Preserve partial outputs and failed attempts.
5. Generate, compile and test new source drafts under the original resource limits. Retain exact source/image/ELF identities with each result.
6. Fix the confirmed semantic differences, connect all remaining native owners and run the matching-source release gates.
7. Remove legacy owners only after the native replacement and complete release gate are established. The user's authorization to finish and clean up remains in force; this interruption does not require re-authorization.

The user-requested goal remains the entire native HIA stack. This checkpoint makes interrupted work reviewable and recoverable without overstating completion.
