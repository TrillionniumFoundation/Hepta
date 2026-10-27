# Exact 44cb3257 full CI evidence

This bundle preserves the observed result of source commit
`44cb32576f0ee8b0d9f01aa5a4fa44ea0848c314`, tree
`b8cf0ef7d1a7b8a367308bbb28c4b0fcf0786157`. The provider job concluded
**failure**: the source qualification completed all 50 planned gates, with 49
passed and `task_io_composition` failed. The separately executed HIA qualification
completed all 15 planned gates and passed all 15. All three finite native
performance profiles reached their defined complete state and passed.

Archive verification establishes retained identities and the described data
checks. It does not turn the failed source qualification into a pass, repair the
tested source, establish whole-project completion, or extend finite qualification
to arbitrary programs, devices, or workloads.

## Provider and source identity

- [Run 40439677114](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40439677114)
- [Job 121976747689](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40439677114/job/121976747689)
- [Artifact 12706738924](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40439677114/artifacts/12706738924)
- Artifact name: `hepta-release-evidence-44cb32576f0ee8b0d9f01aa5a4fa44ea0848c314`
- Original provider ZIP: **76,483,441 bytes**, SHA-256
  `a7dbce62bc05e4405a389ff74e499958a713bd8f560d28c1b1dc5f76d31a1a53`.
- Compiler identity: `baa9c71bf65c590b23598635012989ac2f07242803b1a876b13a28eec2848bd7`.
- The full source snapshot and both HIA snapshots contain **923 paths** and are
  equal. Their canonical file-map SHA-256 is
  `333ccb45aa881e2574961014cf57a1a84e1f751cd9def3fa30e3df163ba09e1c`.
- At capture, all 923 file hashes were compared with blobs from this exact Git
  commit. The bundle retains the path-to-blob tree proof, 111 relevant source
  tree objects, and the literal bytes of **27 selected source files**. It does
  not duplicate all 923 source files. Offline replay verifies those 27 source
  byte identities and the captured Git commit/tree/path proof; hashes of other
  source bytes remain the recorded capture comparison.

`provider-observation.json` contains terminal job/artifact metadata.
`provider-observations/` retains the preceding observations and terminal capture.
Only public provider URLs are included. The complete provider-decoded job log is
retained as `job-121976747689.log`, encoded as UTF-8 without content editing:
**147,146 characters, 147,234 bytes, 1,407 lines**, SHA-256
`fd379a2379c755682203ee67d0471c8f8ab6baf0ffed4dc906fcb51b6ba77206`.

## Complete inventory and deduplication

The original ZIP contains **3,394 ordinary file members**. Each member was read,
hashed, and classified against the exact source Git tree:

| Classification | Files | Treatment |
|---|---:|---|
| Byte-identical tracked `artifacts/` | 89 | Retain inventory and Git identity; deduplicate bytes |
| Byte-identical tracked `evidence/` | 1,999 | Retain inventory and Git identity; deduplicate bytes |
| Added by this run under `artifacts/` | 1,306 | Preserve every original byte and file mode |
| Changed tracked files | 0 | None observed |

All **1,306 new files, 180,840,083 bytes**, are retained, including **176 ELF
files, 110,401,880 bytes**. Selection is based on exact Git blob identity, not a
short list of report names or an assumption that old evidence can be skipped.
The ZIP classification proof includes 168 tree objects. It represents the
source tree's complete `artifacts/` and `evidence/` subtrees, which contain 2,089
tracked blobs; one of those tracked paths is absent from this provider ZIP.

`run-artifacts.tar.xz.b64.part01` through `part03` encode one archive produced by
one xz compression operation using preset 6, a 64 MiB dictionary, and one thread.
Each ASCII part is at most 3,500,000 bytes. The USTAR container preserves member
bytes and modes and normalizes only tar timestamps and owners.

| Layer | Bytes | SHA-256 |
|---|---:|---|
| Selected member contents | 180,840,083 | Per-member identities in `run-artifacts.manifest.json` |
| USTAR container | 181,790,720 | `19052719eacaee93659b189f07dd81d202296730682a8b99f6ae56dee4b91ec3` |
| xz stream | 7,205,652 | `5d6f4b25ac0bc151eaffcefcdcc82745fcf210edc40e5cb59a2010354b5b442b` |
| Combined base64 parts | 9,607,537 | `730d38d6f1c2012076d396b0c4bb52529eac4153893639aa62014d817c78735d` |

The original provider ZIP's identity and complete inventory are retained; the
ZIP container itself is not duplicated in this directory. Supplying that ZIP to
the verifier additionally checks all 3,394 original members, including the
deduplicated ones, against the captured bytes, modes, and Git identities.

## Qualification and the retained failure

| Original report | Planned / completed / passed | Unit terminal result |
|---|---|---|
| `artifacts/candidate/release-validation.json` | 50 / 50 / 49 | 2,111 tests in 499.201 s; OK; 0 skips, failures, errors |
| `artifacts/hia-unified/qualification.json` | 15 / 15 / 15 | 2,111 tests in 480.177 s; OK; 0 skips, failures, errors |

The 50 full-source log links and 43 full-source evidence links, plus the 30 HIA
stream links and 14 HIA evidence links, all match their recorded hashes and
applicable byte counts: **137 linked files** in total.

`task_io_composition` exited 1. Its report is `status=failed`, `ok=false`, with
`ValueError: one or more planned cases failed`. Of its ten planned cases, the
`positive` controls case failed and the other nine cases reported passed,
including the expected negative-control outcomes. The positive case's trials
0 and 1 exited 0; trial **2**, the third recorded trial, exited **-6**. Its
original stderr records an assertion in generated `positive.rs:1337:20`, with
`left: 1` and `right: 0`. The retained source at that line checks
`hepta_task_io_fd_open(fd) == 0` after shutdown.

The complete report and failed gate log have convenient byte-identical copies
under `originals/artifacts/candidate/`. Every file from
`artifacts/candidate/task_io_composition.files/`, including generated sources,
native binaries, and individual process streams, remains in the archive. This
bundle records the failure and does not infer its root cause or incorporate a
later repair into the tested result.

The strict namespace gate passed. `supplemental-review.json` recomputes all ten
recorded predicates from the retained probe data and exact source constants.
Host-side path observations contain six `present` and two `unobservable`
entries (`host_credentials_path` and `proc_init_root_escape`, errno 13); the two
unobservable paths are preserved as such and are not converted to absent paths.
All ten checks are passed, and the original report is `qualified=true`.

## Three complete finite performance profiles

All values below are recomputed from this run's raw samples. Each kernel/backend
cell contains seven samples. Paired ratios mean LLVM elapsed divided by baseline
elapsed within each group, followed by the median over the seven groups.

| Profile | Samples | Geomean versus generated Rust | Geomean versus handwritten Rust | Maximum relative MAD |
|---|---:|---:|---:|---:|
| Scalar | 42 | 0.9988553957650554 | Not a baseline | 0.0027197595990484215 (`branch_accumulate/llvm`) |
| Owned | 63 | 0.9501784644298715 | 0.7808616315269213 | 0.007928961816134556 (`two_stage/rust`) |
| Standalone HIA | 63 | 0.9422534743732750 | 0.9446819665018608 | 0.0038959803347708524 (`two_stage/llvm`) |

| Profile / kernel | Median paired ratio versus generated Rust | Versus handwritten Rust |
|---|---:|---:|
| Scalar / `signed_walk` | 0.9999810897847171 | Not a baseline |
| Scalar / `unsigned_walk` | 1.0024652852394043 | Not a baseline |
| Scalar / `branch_accumulate` | 0.9941381278115574 | Not a baseline |
| Owned / `full_lifecycle` | 0.9981053482076180 | 0.9989851083333363 |
| Owned / `constructor_error` | 0.8505886747943866 | 0.8521801623285251 |
| Owned / `two_stage` | 1.0104610333150341 | 0.5592832553754067 |
| HIA / `full_lifecycle` | 0.9980645245482859 | 1.0003690397959990 |
| HIA / `constructor_error` | 0.8387058496826376 | 0.8379108422397042 |
| HIA / `two_stage` | 0.9993898888344191 | 1.0057703360233563 |

All three reports have `phase=complete`, `status=passed`, `ok=true`, and empty
quality/performance failure lists. The independent data review checks the exact
168-row schedule, per-cell median/MAD/minimum/maximum, paired ratios, geomeans,
native-call denominators, and the frozen protocol parsed from retained source
AST constants. Owned rotates backends using group plus kernel position; HIA
uses group plus the original kernel index.

The frozen limits are per-kernel paired median <= 1.2, geomean <= 1.1, relative
MAD <= 0.05, and every sample >= 0.05 seconds. Owned/HIA additionally limit each
sample to 30 seconds; scalar has no such maximum in its protocol. No sample is
excluded and no threshold is adjusted. The profiles preserve their distinct
allocation semantics and scope; the figures are not a cross-profile speedup
claim or evidence of universal superiority over Rust.

### Process evidence, correctness, and binary retention

| Evidence | Scalar | Owned | HIA |
|---|---:|---:|---:|
| Timing rows | 42 | 63 | 63 |
| External `process_observations` | 42 | 63 | No such array; telemetry is in 63 timing rows |
| Linux before/after raw-text hashes | 252 | 378 | Not this observer format |
| Complete command/exit/stdout/stderr receipts | 0 | 70 | 71 |
| Individual stdout/stderr hashes checked | 0 | 140 | 142 |
| Finite correctness cases per backend | 186 | 196 | 196 |
| Reported native correctness calls | 372 | 784 | 588 |

All external observer snapshots and deltas are observed, without unavailable or
reset counters. Their command, sample identity, clock interval and Linux text
hashes are checked. Owned and HIA timing rows are bound to their recorded
driver/library identities and execution output. The HIA scheduling summary is
recomputed from its 63 rows: CPU/wall minimum 0.9923694403467092, median
0.9984367281837858, maximum 0.9986337510640247; 10,044 involuntary context
switches; zero voluntary switches, minor faults and major faults. These counters
do not establish exclusive CPU access or a cause for a timing difference.

Scalar and owned retain their formula cases and qualification assertions, not
individual actual native outputs for every correctness case. Owned additionally
retains four backend observation digests. The data review reconstructs those
formula domains and digests. HIA retains all 588 actual observations and the
588 JSON stdout lines; both are compared with independently evaluated formulas.
Owned/HIA timing checksums are recomputed using integer digest arithmetic. Their
positive resource controls record 7 allocations, 7 frees, 0 live allocations and
1 refusal, exit 0; missing-free controls record 7, 0, 7 and 1, exit 1.

The HIA `performance-artifacts/` directory retains 16 exact files totaling
7,821,997 bytes, plus a 7,026-byte retention manifest. All sixteen hashes and
path mappings, including four timed binaries and four control/object identities,
match. Retention manifest SHA-256:
`7338c72ee42709dd1e0c53ed5f89721cf9f07e1a15da0448de3060344e1ab717`.
The complete provider inventory contains no matching bytes for scalar's six
declared binary/object identities. Of owned's twelve identities, only its
handwritten Rust library has matching retained bytes, in the HIA artifact
directory; the other eleven are absent. Thus this archive preserves all
provider-supplied files, but does not claim all three profiles supplied every
measured binary.

## Known standalone C caller limitations in the tested source

The selected source captures preserve two unfixed qualification defects:

- `examples/cpp/composed_migration/harness.c` calls `composed_case` in its C
  build without a preceding C return prototype. The `uint64_t` prototype exists
  only in the C++ branch.
- `examples/cpp/owned_migration/harness.c` has the same issue for `owned_case`.

Finite passing receipts from these standalone C callers do not establish
full-width C return ABI correctness. This statement does not change either
original gate outcome or attribute the task-I/O failure to these defects.
`supplemental-review.json` records exact source identities and every matching
diagnostic location. Scanning all stderr strings in **55 first-level candidate
and HIA JSON reports** finds **9 warnings for `composed_case` and 1 warning for
`owned_case`**, zero matching errors. These ten occurrences are counted from this
run's actual JSON strings; copies in text logs are not counted again.

## Portable verification

Run from this directory with a Python standard-library environment:

```sh
PYTHONDONTWRITEBYTECODE=1 python verify_bundle.py
PYTHONDONTWRITEBYTECODE=1 python verify_bundle.py --original-zip /path/to/12706738924.zip
```

Both modes read and decompress bounded data in memory. They do not extract or
execute archived programs, invoke a compiler or production qualifier, import the
production evaluators, access the network, or measure performance. The optional
ZIP mode additionally verifies the original ZIP digest and every original ZIP
member. The checked summaries are stored as `verification.json` and
`verification-original-zip.json`; `MANIFEST.json` seals them with the other
sidecars. `review.json` and `supplemental-review.json` are recomputed and compared
on every verification.

The capture and verification helpers are retained for inspection. Capture used
only immutable Git reads, original-file reads, data arithmetic, one authorized
compression pass, and writes to this new evidence bundle and its temporary
capture directory. No native execution or performance sampling was repeated.
