# Round6 repair evidence — local 122-method qualification

The final focused repair run executed **122 unique methods with zero failures,
errors, skips or warnings**, in **30.428135234 seconds**, on local frozen commit
`0796550d67e71f3e5d7a1f2fb6db1f23db17b809`.
Its source tree is `debee7040ed2ffac2cbaf953c28c1e2ca3fc8407`.

[Published source `9fa9e957`](https://github.com/TrillionniumFoundation/Hepta/tree/9fa9e957a9ebc7b34b4018fd4b83d863ebbc717b)
has the same tree. The local observations retain their original `0796550` identity.
They are **not results of remote CI on `9fa9e957`**. This evidence publication is
prepared with the strict parent `9fa9e957a9ebc7b34b4018fd4b83d863ebbc717b`, adding only
`evidence/hia_round6_repair_20261029` to its source tree. Source PR
[#372](https://github.com/TrillionniumFoundation/Hepta/pull/372) and later CI outcomes
have independent state; this package does not certify a current CI outcome.

## Final source and denominator

The original `RUN.py`, `SELECTION.json`, final `PLAN.json`, `RESULT.json`, stdout
and stderr are retained unchanged. The plan binds **6,410 source paths**. Packaging
checked every recorded SHA-256 against its exact raw Git blob from the frozen
source tree: **4,744 unique blobs**, totaling **293,186,444 source bytes** were read
for verification, without importing or executing project code. The source corpus
itself is not duplicated into this evidence archive.

The public source identity is supported by the retained source publication,
commit, ref and tree-plan receipts. The `9fa9e957` Git commit object was not present
in the packager's local Git database; the local `0796550` tree and complete blob
inventory were independently checked. The final source review also retains its
13-path change review and the distinction between local evidence and remote CI.

| Final selection membership | Methods |
| --- | ---: |
| C importer guards | 47 |
| Compiler capture and ownership | 33 |
| Workflow shell/argv fixtures | 14 |
| Darwin guardian mechanism | 11 |
| Complete C++ AST stream and process ownership | 19 |
| Linker dispatch and feature-policy fixtures | 8 |
| Sum of memberships | 132 |
| Duplicate memberships | 10 |
| **Unique methods selected and executed** | **122** |

The overlap is recorded by exact selector in `SUMMARY.json`. Earlier stage counts,
the previous 171-method run, reviews, canonical safety selectors and CI jobs are
not added to 122. Full regression, actual native compiler/Rust qualification and
the complete canonical matrix were not executed by this final local focused run.

## Original failures remain failures

The public allowlist preserves the original failure reports and logs for source
`0f78511cde0985d3dba4436ef5bd1b4caee82364`, with original run/job and source bindings.
These denominators overlap and describe separate workflow observations.

| Original observation | Retained result |
| --- | --- |
| Verified workflow, run `40865793338`, job `123420129446` | 764 methods; 5 failures, 0 errors, 0 skips. Complete streams reaped the compiler before the shared owned-cleanup check. |
| Integrated full regression, run `40865726443`, job `123419903445` | 3,872 methods; 6 failures, 1 error, 0 skips. Original stream, linker-flavor and `/proc` observation failures are preserved. |
| Canonical safety matrix within the original integrated run | 146 methods; 1 failure. The configured generic `rust-lld` invocation failed before the intended masked-CPU LTO control. |
| Original macOS native/C++ host jobs `123419903193` and `123419902760` | Compiler-identity/setup capture failures remain failed. The original reports lack the underlying errno; no inferred errno is substituted. |

Apple platform-source analysis is retained only in `PLATFORM_EVIDENCE.json` as
URLs, commit/path identity, hashes and a bounded explanation. The exact loaded
kernel build and unrecorded original errno are not claimed proven. Apple source
files are excluded from the archive.

## Repair stages and their limits

The guardian records preserve separate direct and forced-route stages, the
original failed PIPE/early-EOF controls, source snapshots, handoffs and independent
reviews. Their 23-, 42-, 43- and 20-method observations overlap and use their own
intermediate source hashes. Linux execution of the guardian mechanism does not
establish actual macOS qualification.

The stream component retains the complete AST parser and original limits, restores
non-reaping ownership and the post-EOF deadline, and publishes a successful receipt
only after owned cleanup. Its 19 normal-route methods and 13 overlapping forced
guardian methods remain separate component observations. The local C++ project
harness recorded seven skips because Clang 20 was missing: **zero native methods
executed**, with qualification explicitly false.

The linker component contains two actual subprocess argv-dispatch/file-identity
fixtures and six existing nonnative feature-policy methods. They do not claim
native LLVM code generation, an actual LTO link or masked-CPU execution. The exact selected linker executable
and its ELF invocation remain subjects for current-source CI.

The process-observation fixture retains its original failure, pidfd repair and
atomic-ready-marker follow-up. The first local red attempt failed an earlier
numeric-PID assertion with `injections=[]`; it did **not** reproduce the original
CI ESRCH read. Each stage is the same existing method, not an additional method.
`FINAL_HANDOFF.json` binds the later fixture to local `0796550`.

## Retained bytes and exclusions

The archive contains **247 original files**, totaling **7,061,074 bytes** before
compression. `MANIFEST.json` and `RAW-INDEX.json` map original absolute paths to
archive members, with byte counts, SHA-256 hashes and component labels. Existing
receipts, timestamps, failure messages and source identities are unchanged.
Original nested path indexes remain present; the outer indexes locate their
retained files after the archive is moved. Archive metadata is normalized to
regular files with mode 0644 and uid/gid/mtime zero.
The package-local `.gitattributes` disables Git newline conversion for every
publication file, preserving the exact outer JSON, verifier and documentation
bytes on checkouts with `core.autocrlf=true` as well as the original tar archive.

The archive excludes private artifact ZIPs, all whole original ZIPs, private NDU
source/checkouts and bridge binaries, toolchains, Cargo targets, Git bundles,
Apple full sources, old large archive payloads and new `9fa9e957` CI artifacts.
Only the explicit historical failure report/log allowlist is retained. Temporary
download credentials and high-confidence secret patterns were checked before
packaging; package review is recorded separately from project qualification.

No NDU performance experiment was executed by this repair package, and it supplies
no new optimization benefit evidence. Historical negative results remain assigned
to their original studies. These observations do not prove whole-language safety,
arbitrary C++ migration safety, a global instruction optimum or universal Rust
performance superiority.

## Verify without executing the project

```sh
python3 RESTORE.py --verify-only
```

The standard-library-only verifier checks the compressed archive and each indexed
regular member, rejects unsafe paths, links, duplicate/unexpected members and
byte-budget violations, and checks the original focused source/selection/result
bindings. It extracts nothing, imports no project modules, runs no compiler or
project test, and performs no network operation. `VERIFY-ONLY.json` is a byte
verification receipt, not another project test run.

SHA and Git-object checks establish byte identity. They do not replace semantic
verification or establish producer authenticity beyond the published evidence
and its retained source bindings. Fresh exact-source native hosts, integrated and
Rust gates, canonical safety, migration, six-outcome applications and verified
optimization remain separate qualifications.
