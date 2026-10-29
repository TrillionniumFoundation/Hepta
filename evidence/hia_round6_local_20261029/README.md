# Round6 local validation evidence — immutable source tree

This package retains the local observations produced while integrating HIA contracts,
source/Rust execution, migration guards and bounded compiler capture. The final
focused run executed **171 unique methods with zero failures, errors, skips or
warnings** on local commit `dc7b451b61850e4fef3d692f873c5d037c46eab6`, tree `6f2fd62bab62eef2d6952fa488dc9076d648a2ab`.

[Source PR #372](https://github.com/TrillionniumFoundation/Hepta/pull/372) originally
published commit `0f78511cde0985d3dba4436ef5bd1b4caee82364` with the same tree. The local run was performed
on `dc7b451`, **not by remote CI on `0f78511`**. Later source repairs or CI outcomes
do not rewrite this package. The publication parent is strictly `0f78511` and only
this evidence prefix is added to its source tree.

## What the final run covers

The complete original `PLAN.json`, `RESULT.json`, stdout and stderr are retained.
The plan binds all **6,407 source paths**. Packaging additionally checked every
recorded SHA256 against the exact raw Git blob from the committed source tree;
no checkout normalization or working-file substitute was used.

| Final-run membership | Methods |
| --- | ---: |
| Semantic/Core/SMT/protocol | 87 |
| C importer guards | 47 |
| Compiler capture and ownership | 33 |
| Workflow shell/argv fixtures | 14 |
| Membership sum | 181 |
| Duplicate membership between importer and capture | 10 |
| **Unique methods actually selected and run** | **171** |

The 146 canonical safety selectors were resolved; their complete matrix was not
executed locally. Full Python discovery, actual Clang/Rust toolchain qualification,
native migration comparisons and remote CI are not certified by the 171 methods.
Earlier stage counts overlap and are never added to 171.

## Original failures, warnings and intermediate sources

| Original component | Retained observation and limit |
| --- | --- |
| Semantic 358 | Stage JSON contains two original six-method tool outputs. There was no separate raw-log file; none has been fabricated. |
| Semantic 360 | 70 + 17 methods on the uncommitted merge, with original logs and file hashes. |
| Importer checkpoint | Earlier 15-method run; original files and their existing checkpoint copies are retained without treating copies as another run. |
| Importer attempt 1 | 47 methods with one strict-AST diagnostic assertion failure; original failure retained. |
| Importer attempt 2 | 47 methods passed on its recorded earlier importer/capture bytes. |
| Capture before fix | Three red-control methods produced eight failure records, including subtests; exit code 1 retained. |
| Capture after fix | 33 methods returned success, with the original **ResourceWarning** retained. |
| Cleanup fixture follow-up | The callback ownership repair and exact new test hash are retained. Only the final 171 run is described as warning-free. |
| Earlier workflow validation | 14 shell/argv fixture methods; not real compiler qualification. |
| Discovery-only observation | 3,844 IDs discovered, two module-import errors from missing Rust, **no test execution**. |
| Rust preflight | No available filesystem space. Download, installation, dependency fetch and Cargo tests were not attempted; no native result is invented. |
| Two read-only reviews | Original baseline and integration records. Historical model/optimization observations keep their original sources and do not become local test counts. |

All raw payload bytes remain unchanged. `MANIFEST.json` maps original absolute
paths to archive members and records their byte counts and SHA256 hashes. Intermediate
handovers retain their original uncommitted/checkpoint source attribution.

## Current CI is a separate evidence scope

No old 701 CI bundle or current PR372 CI artifact is included. During preparation,
the parent reported that current-source CI had started, two macOS jobs had failed,
and other jobs were completing. Their original observations and any resulting
source repair remain separate. This package does not infer a terminal CI result
or convert an in-progress job into success.

Separate current-source qualification is still required for the eight integrated
gates, the canonical safety matrix, real migration, both seven-job host matrices,
the six-outcome application gates and verified optimization/native NDU gates.
Their future test counts must not be added to 171 as a single denominator.

## Verify retained bytes without executing the project

```sh
python3 RESTORE.py --verify-only
```

This standard-library-only verifier checks the compressed archive, every regular
member, and the original focused selector/source bindings. It extracts nothing,
runs no project program, invokes no compiler and performs no network operation.
The archive contains 86 original files totaling 1,635,509 bytes
before compression. Files have normalized archive metadata; their content bytes
are unchanged. `VERIFY-ONLY.json` is the packager's own byte-verification receipt,
not another test run.

Excluded material includes private NDU source/packages, NDU native binaries,
toolchains, Cargo targets, Git bundles and historical model-performance payloads.
No general safety theorem, global optimum or performance-superiority claim is
established by this local evidence package.
