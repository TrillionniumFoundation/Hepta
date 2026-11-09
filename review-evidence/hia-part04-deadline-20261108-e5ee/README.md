# Part04 deadline repair evidence

Baseline: `ffa64c93dd4c51190fda8c0f647481a31ffbcf07`.
The published candidate still needs its own exact-commit CI. This directory
records completed local source-snapshot qualification and retained original
evidence, not a production deployment.

`validation.json` identifies the eight tested implementation, test and workflow
files, the Python runtime and all 105 distinct regression methods. The final
suite passed 105/105 in 221.835 seconds with no failures, errors or skips. The
earlier 8/8 and 3/3 logs overlap these same methods.

`original-evidence.tar.xz` is 160,304 bytes, SHA-256
`7cd9e6b601002c35344ec776c37ae0f36304cfb967eeb838811b215f6de0723f`.
All 338 members, totaling 33,785,304 uncompressed bytes, were independently
read back from the archive and checked against `archive-manifest.json`.

Important retained paths inside the archive:

| Path | Meaning |
| --- | --- |
| `original-job-128881557778.log` | Complete decoded original GitHub failure log. The unique historical cause remains UNKNOWN because it lacks the subcase terminal receipt. |
| `original-run-42529899242-jobs.json` | Metadata for all 79 original workflow jobs. |
| `red-delayed-start.log` | Initial local reconstruction failed before running the fixture because one exact-source experiment directory was absent. It was restored from the pinned commit. |
| `red-delayed-start-v2/` | Original-source control that did **not** reproduce the failure: delayed first output, zero markers, clean timeout replay. |
| `red-delayed-cleanup/` | Original-source control that did **not** reproduce the failure: a 40 ms post-signal pause. |
| `red-cleanup-read-pause/` | Original-source failing assertion under 40 ms and one transient stderr-read EAGAIN; includes all retained source and capture files. |
| `green-cleanup-read-pause/` | Intermediate repair regression: ordinary timeout bypassed draining. This unsuccessful attempt is preserved. |
| `green-cleanup-read-pause-v2/` | Successful replay of the same controlled pause after the clock and normal-timeout transition repairs. |
| `red-production-late-wait/` | Original collector incorrectly completed after the actual wait return was observed beyond the cleanup deadline. |
| `green-production-late-wait/` | Same controlled late observation explicitly fails under the repaired collector. |
| `reproduce_*.py` | Exact scripts used for the controlled observations. Run from the corresponding source checkout, with a fresh output-directory argument. |
| `new-deadline-controls.log`, `relocation-timeout-controls.log` | Separate eight-control and three-control terminal results. |
| `affected-suites.log` | Complete final 105-method regression, including the formerly failing method and both full inverse integrations. |
| `workflow-validation.log` | YAML, shell, embedded Python and exact test-inventory validation. |
| `independent-static-review.json` | Scope and source hashes of the separate read-only review; it did not execute the tests. |

The child programs are deliberately inert Python substitutes. No Lean target,
formal theorem, model/provider interaction or native compiler qualification is
claimed by this experiment. The real PTY, read, signal, wait and filesystem
operations establish the stated finite observation controls only. Legacy v1
trace records remain untouched and retain only their original semantics.
