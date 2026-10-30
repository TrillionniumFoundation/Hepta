# Independent review: native ABI binary retention, candidate 2f4891c

The bounded artifact-retention change passes independent production-source and
original-native-result review. The frozen candidate is
`2f4891ce7c5b92979ffb4c65575075367a1ecb15`, tree
`bc41b0509bd343821a985cae7f22bcb338897cef`, with public parent
`a6cfb7e00a1c08276d27459bdcc5628aa7622079`. This is a local candidate execution;
the review does not relabel it as an execution of a future public commit.

## Actual observations

| Population | Original result |
| --- | --- |
| Parent a6cf, actual Linux GCC matrix | Passed its original ABI checks, but zero of the four original binaries remained after temporary cleanup |
| Frozen 2f4891c, actual Linux GCC matrix | Two profiles, 181 foreign calls per profile, three specific type refusals, compiled wrong echo rejected with return code -6; all four binary originals retained |
| Frozen 2f4891c, actual Linux Clang matrix | The same original finite matrix and claims; two profiles, 181 foreign calls per profile, three specific type refusals, wrong echo return code -6; all four binary originals retained |
| Frozen protocol population | 25 distinct methods, exactly once, all ordinary PASS: 14 new artifact-custody controls and 11 existing driver/evidence controls |

The independent final readback completed **38,486 read-only conditions**. It
read the exact original 12 host command records per native matrix, including
the compiler probes, both actual build/run pairs, the three failing type
compilations and the compiled wrong-echo execution. It checked all eight
retained files across the two candidate matrices against their source-report
roles, names, original paths, sizes, SHA-256 values and actual modes. The
original temporary paths were gone; the retained copies still existed with
the expected bytes. The original parent result remains a successful finite
ABI execution with an unsatisfied binary-retention requirement.

No native matrix, compiler, frontend analyzer, checker or oracle was executed
by this final readback. The native matrices were executed by `root` and their
actual records were consumed by `review_resume`.

## Source and protocol review

The exact five-file source export matches the candidate's raw Git bytes and
modes. Applying its 48,187-byte patch in a separate index based on the public
parent independently reconstructs the declared tree. All original compiler
probe/type-control helpers and all original `validate_report` gates retain
their ASTs; the latter gains only the optional retention metadata check. The
old success-report fields, ABI schema, claims, matrix generator, Core source
and canonical safety contract remain unchanged.

The implementation retains the Rust object and the two drivers/wrong-control
binaries before temporary cleanup. It copies a driver before attempting its
execution, preserving already built evidence when a later command fails. The
copy and actual-file validation use bounded, nonempty regular-file reads,
ordinary modes, stable open-file identity, SHA-256 binding and exclusive
creation. Successful CLI qualification also verifies its own canonical
artifact directory. Explicit offline directory mapping remains available for
archive restoration, without rewriting original producer paths.

The new tests were authored and executed by `review_resume`; this authorship
is disclosed rather than treated as independent review of its own test code.
They use plainly labelled fake binary bytes and mocked compiler outcomes.
They do not establish Windows/MSVC execution or any other native result.

The initial development run executed 24 methods and exposed two real failures:
an existing success report could be replaced by the refusal from its occupied
artifact directory, and a concurrent output could be overwritten. Those
original FAIL logs and the initial test source remain intact. The production
fix now rejects an existing output before starting and creates the final JSON
exclusively. The workflow preserves its own setup placeholder under a separate
name before invoking the CLI and uploads both that placeholder and available
binary copies. A final directory-binding control was then added, producing
the frozen 25-method population. There was no redundant intermediate green
run.

The frozen protocol methods ran on 2026-10-30 at 17:14:40 UTC and had zero
errors, failures, skips, expected failures or unexpected successes. Their
Python/Git/test-runner provenance and source inventories agree before and
after. The executed sparse checkout materialized 1,426 of 7,700 tracked paths;
the other 6,274 paths are explicitly excluded from execution coverage. The
native candidates have the same materialized scope. The parent baseline had
1,425 materialized paths because the new test module was not yet present.

## Limits and artifact map

`review.json` and `input-manifest.json` bind the final review and original
inputs. `frozen25/` and the adjacent process/tool records retain the actual
protocol run. The initial dirty-source metadata was recorded immediately
after that development run; it is not a claim of a clean or fully qualified
intermediate commit. `audit_originals.py` performs only readback and Git source
verification, including the separate-index patch reconstruction.

The current change closes the demonstrated binary-custody gap for the two
actually executed Linux compiler matrices. Other hosts, arbitrary ABI
features, physical devices, whole-language soundness, backend refinement and
full release qualification are not inferred. The existing Python API still
has optional temporary behavior when no artifact directory is requested.
Python remains production authority; optimization policy remains `no_change`;
all 27 strict P0–P7 blockers remain open.
