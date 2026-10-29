# Recovered round-six CI evidence for `9fa9e957`

This is a **newly assembled recovery** of retained GitHub Actions evidence for public source **`9fa9e957a9ebc7b34b4018fd4b83d863ebbc717b`**, tree **`debee7040ed2ffac2cbaf953c28c1e2ca3fc8407`**. All six workflows and eighteen jobs completed successfully on their first attempt. A fresh official API observation at **2026-10-29 14:58:02 UTC** reconfirmed their exact source and terminal state.

Automatic workspace maintenance removed an earlier, unpublished 397-file local package before its archive parts were uploaded. **That complete package has not been restored.** This package has a new explicit selection, index, archive identity and verification record. It combines original CI ZIP/member bytes recovered from GitHub with surviving response bytes and clearly labelled new recovery metadata. Old manifest/review files that were lost are not presented as recovered originals.

## Package identity

| Item | Value |
| --- | --- |
| Source commit | `9fa9e957a9ebc7b34b4018fd4b83d863ebbc717b` |
| Source tree | `debee7040ed2ffac2cbaf953c28c1e2ca3fc8407` |
| Selected raw files | **257** |
| Selected raw file bytes | **101,508,375** |
| Joined TAR/XZ bytes | **65,305,268** |
| Joined TAR/XZ SHA-256 | `33b1639a6a23f0086d187e9b72f7fdd913e163eab91164df090a631bd3092967` |
| Parts | **11**, each at most **6,291,456 bytes (6 MiB)** |
| Original public CI ZIPs | **16**, containing **5,087** indexed regular members |
| Original verified report members | **122**, totaling **6,420,254 bytes** |

[ARCHIVE.json](ARCHIVE.json) fixes the ordered part hashes and joined archive identity. [RAW-INDEX.json](RAW-INDEX.json) fixes every selected raw file and every original public ZIP member. [RECOVERY-SELECTION.json](RECOVERY-SELECTION.json) binds the four explicitly approved input manifests. [PACKAGE-SUMMARY.json](PACKAGE-SUMMARY.json) keeps execution, recovery and economic claims separate.

The raw selection is:

| Component | Files, including its explicit manifest/receipt records | Bytes |
| --- | ---: | ---: |
| metadata | 50 | 2,594,112 |
| host | 70 | 91,038,151 |
| integrated | 4 | 1,065,959 |
| verified | 133 | 6,810,153 |

The public files beside the archive parts are additional packaging metadata and a standalone verification reader. They are not extra tests and are not part of the raw-file denominator above.

## Verify or restore without executing archived programs

Download this directory with all `parts/` files. From this directory, run:

```sh
python3 RESTORE.py --verify-only
```

This hashes every part, verifies the joined XZ stream and all 257 outer TAR members, and checks that each member has the indexed path, size, mode and SHA-256. The recorded execution is [VERIFY_ONLY.json](VERIFY_ONLY.json); [ASSEMBLY-VERIFICATION.json](ASSEMBLY-VERIFICATION.json) binds the command, its successful exit and the unchanged source checkout. `--verify-only` does not expand the inner CI ZIPs; all 5,087 inner members were independently read, CRC-checked and hashed during assembly and are indexed for optional expansion.

To restore into a new directory, optionally including the original public CI extraction trees:

```sh
python3 RESTORE.py --output recovered-ci --expand-ci
```

Existing output paths, traversal, duplicate files, unexpected members and hash mismatches are refused. The reader only verifies and extracts data. It does not execute archived source, native binaries, test harnesses or retained audit scripts. Some retained audit scripts refer to producer-specific filesystem paths; this package does not claim they can be run unchanged from any directory.

The reader was retrieved from immutable public commit `999c63cae7a3143050a1ac71b66f5e040e489ab1` and its original SHA-256 was verified as `523c432662c68556316c7d866e72b46a75ffc7a6b019d1d9b948e85daf8a59e4`. Only its description and successful-output schema identify this new recovered package. Its verification/restoration logic is unchanged; [READER-PROVENANCE.json](READER-PROVENANCE.json) binds both identities. The directory's `.gitattributes` preserves all publication bytes with `* -text`.

## Actual source-bound CI results

| Workflow or cohort | Actual result | Original run |
| --- | --- | --- |
| Integrated qualification | All **8 gates** passed; **3,898 unique Python methods**, zero failures/errors/skips | [40871552682](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40871552682) |
| Rust resource crate within integrated | **84 tests**; **16 Cargo result sections**, including one empty Doc-tests section | [same integrated run](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40871552682) |
| Canonical matrix within integrated | **146/146** passed | [same integrated run](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40871552682) |
| C/ABI host matrix | **7** actual OS/compiler/architecture jobs passed | [40871552510](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40871552510) |
| Upstream C++ host matrix | **7** jobs passed; locked library versions **3.11.3** and **3.12.0**, each with **98 cases per host** | [40871552569](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40871552569) |
| HSIR/C migration | Passed; **167** selected unittest methods | [40871552546](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40871552546) |
| Source/application | **146** canonical selectors, **351** regressions and **449 selected scalar SMT obligations** | [40871563756](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40871563756) |
| Verified optimization/native NDU | **777 unique regression methods**, zero failures/errors/skips; **30** finite NDU/control episodes completed | [40871563884](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40871563884) |

These executions overlap. Full discovery, selected cohorts, canonical checks, host repetitions, local repair tests and data-review checks must **not** be added into one unique-test total. The original Rust producer's `test_binaries: 16` field is preserved; its output consists of fifteen `Running` sections plus one empty Doc-tests result, not sixteen independently observed executable binaries.

The integrated report preserves a clean before/after source at `9fa9e957` / `debee704`, **6,410 source paths** and **440 unchanged external input identities**. The recovered integrated audit independently matched all 6,410 raw-byte hashes, Git blob identities and modes against a fresh exact-source checkout. These inventories are identity evidence; this archive does not duplicate the entire source checkout. The verified cohort separately binds 2,270 source files while retaining its own untracked output/upstream directories, so it is not described as a globally clean worktree.

The generic Rust LLD repair has actual evidence: the same configured `rust-lld` binary, SHA-256 `5b224e53ad32986a5bf2e349addbe00c5ef37814a6a5584a9f2e3d03bb524306`, was invoked through a private GNU alias for its version probe and three full-LTO links. All succeeded. The masked-CPU raw control still received SIGILL, while six bound-IR and six C-reference executions returned the expected results. The source/application lane used a separate dedicated LLVM linker. Its success is not substituted for this integrated generic-driver execution.

Real macOS logs retain **20** ownership/guardian/stream methods: eight ownership, eleven guardian and one stream method. Conditional POSIX steps are not credited as Windows executions. Host evidence qualifies its declared C/ABI and C++ library-reuse routes, not arbitrary direct-LLVM HIA programs on every platform. Original Windows checkout bytes and frozen fixture bytes remain exactly as stored in their original artifacts.

## Public/private boundary and recovery provenance

The sixteen original public ZIPs are fourteen host artifacts, source/application artifact `12897305216`, and integrated artifact `12898192961`. Their exact official sizes and SHA-256 digests were rechecked. Every member has a safe canonical path, regular-file type, size and hash in the new index.

Verified artifact `12897077130` contains private NDU bridges. **Its original ZIP, all four private bridge executables, private source payloads, toolchains and transfer requests are excluded.** Only the explicitly approved 122 original report/input/log members are included, along with new recovery metadata. Public reports may retain private source paths, digests and build identity strings; these are metadata, not copied private source or executable payloads.

The metadata component separately retains surviving original observations at 12:48:37 and 12:50:53 UTC and a new 14:58:02 observation. All eighteen job-log response strings were collected without truncation by the collector. Every response retains its final runner cleanup marker. The connector exposes no independent content-length header; that limitation is recorded. Eight API bodies equal surviving originals byte for byte. Four log hashes independently match pre-pruning recorded hashes. No signed download URLs are included.

The earlier [published repair package](https://github.com/TrillionniumFoundation/Hepta/blob/bba01784239543cb3abe77b8affdef2b7b1c6c1a/evidence/hia_round6_repair_20261029/README.md) retains its original local source `0796550d` and **122** local repair methods. It is not relabelled as this remote CI. Earlier failures at `0f78511` retain their own source and provenance. Neither earlier local nor historical runs are added to this package's CI denominators.

## Economic and safety limits

The current finite NDU study has five arms with six episodes each. All six NDU choices were `stop`; calibrated identity and folded candidates produced identical native bytes. Recorded standalone six-episode costs were approximately **2.584036 s** for selected fixed, **2.563641 s** for light, and **29.730974 s** for NDU, including NDU's separately measured **26.704908 s** empty-target build. These are attributed standalone totals, not per-call delays, and summing the five arm totals repeats shared setup. This cohort has no separately labelled complete-DP arm. Neither incremental-value flag passed.

The adaptive and owned-state reports retain conservative or negative benefit conclusions. Preparation-only filecheck/queue/IRPGO inputs are not timing wins. Agent controls made zero model requests. Compiler and artifact-upload warnings remain in raw logs; zero failures/errors/skips in the named cohorts is not a global zero-warning claim.

All six broad research goals remain open. This package does not prove whole-language soundness, final-machine-code refinement, arbitrary C/C++ translation, universal Rust performance superiority, profitable general state replacement or global instruction optimality. NDU retains advisory authority only. Resource legality, functional preservation, native artifact identity and economic value have separate evidence and separate limits.

Recovery, byte audits, archive assembly and reader verification did not rerun project tests, compilers, archived programs or CI. This evidence directory is intended for a separate branch whose sole parent is the source commit above; source files are unchanged. Publication and PR merge state are controlled separately.
