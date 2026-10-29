# Hepta finite continuation components — 2026-10-29

This archive preserves component executions, independent review, original
failures and publication inputs with their own source identities. It does not
turn those executions into a complete qualification of public source
[`699de39a8e92e0f083df316ecc5333fb3ecf8571`](https://github.com/TrillionniumFoundation/Hepta/commit/699de39a8e92e0f083df316ecc5333fb3ecf8571).
The full integrated and safety qualifications of that exact public commit are
recorded separately by the parent continuation.

Python remains production authority, the optimization policy is `no_change`,
and the broad P0–P7 obligations are not all closed.

## Independent source scopes

| Retained directory or record | Original source and scope |
| --- | --- |
| `core-next-evidence-efb2fea/` | `efb2fea1de2855b2669593660d787b98fc966aa6`: explicit v3 policy on the existing Rust Machine, with 88 Rust tests, 91 legacy Python tests, 8 v3 methods, 825 bound observations and 43 raw refusals. |
| `core-next-strict-result-52653db/` | `52653dbc182ff400c95f7cda771800e9961c3c83`: strict qualification-result handling, 4 regressions and a fresh execution of the same 8-method v3 profile. The 825 observations and 43 refusals overlap the earlier component. The same retained Rust binary is explicitly bound. |
| `v3-peer-review-efb2fea/` | Independent review of the original `efb2fea` component: 242 actual native bound comparisons, programs, process journal, initial invalid SSA fixture and its correction. |
| `ci-repair-20261029/` | Original hosted failure on `1669ddc`; local LLD repair on `9da1d4b`; native observation-window repair and complete preparation on `e25b2eb`. The original scopes and intermediate failures remain distinct. |
| `integration-static-review-20261029/` | Read-only review at local source `44602dc` with 94 resolved selectors at that point. Resolution and static review are not test execution; this record predates the final 95-selector source. |
| `source-publication-699de39.json` | The exact source publication receipt: local `421ae80` and public `699de39` share tree `592b6114f659fb18b13ad3fa5ed5e213ecdb92b5`. |
| `final-control-tests-95.log` | A pre-publication focused run of **23** methods. The filename's `95` is not the number of executed methods, and this log is not a complete gate run on the public commit. |

These groups overlap. Their counts must not be summed into independent tasks,
distinct generated programs, productivity gains or a whole-language proof.
Original bundles, actual native binaries, collector/review source, manifests,
stdout/stderr and rejection records are retained.

## Hosted CI snapshot on public `699de39`

The included official run/job snapshot was observed on **2026-10-29 at
11:15:39 UTC (07:15:39 America/New_York)**. All 19 job records identify the
same exact public source commit.

| Workflow | Official run | Snapshot result |
| --- | --- | --- |
| C ABI host matrix | [40862645159](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40862645159) | Seven of seven declared hosts completed successfully. |
| C++ upstream host matrix | [40862645199](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40862645199) | Seven of seven declared hosts completed successfully. |
| Source/application, push | [40862645202](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40862645202) | Completed successfully. |
| Source/application, PR | [40862658213](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40862658213) | Completed successfully. |
| NDU integration, push | [40862645459](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40862645459) | In progress. |
| NDU integration, PR | [40862658216](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40862658216) | In progress. |
| Full release | [40862645318](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40862645318) | In progress. |

This snapshot includes official metadata, not downloads or content inspection
of the new hosted artifacts. It does not assert that all CI passed. Later
observations belong in a separate supplement, preserving this timestamp.

## Original CI failure and finite repairs

The historical [run 40799429611](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40799429611)
on `1669ddc` remains failed. Its release candidate and integrated suites each
ran 3,614 tests with one failure; its standalone unified suite ran 3,614 tests
with two failures. All had zero errors/skips. The selected original logs and
reports are included unchanged.

The generic LLD version/driver handling failure is repaired using an explicit
version flavor and a temporary ELF invocation name for the same selected
executable. Hash and path checks run before and after use, including cleanup
on exceptions. Actual substitution attacks reject. The native test-window
repair preserves exact SIGSYS requirements for forbidden forks and the
separate 200 ms timeout control. It changes no production deadline or seccomp
policy. The historical CI's exact delay point remains unknown.

The CI repair component has 37 distinct successful test methods across its
source-bound runs. The repeated generic/ELF driver profiles are not distinct
method counts. The complete actual prepare-only application run on `e25b2eb`
passed 768 differential calls across eight arms, 48 resource cases, four
maintenance cases and two whole applications. Its samples are empty and its
status is `prepared_not_measured`.

## Retention and validation

`retention.json` lists each member's size, SHA-256, Git blob identity and mode.
Every archived member is read back and compared against that inventory, and
every selected input is checked again after creation. `archive-receipt.json`
is stored alongside the archive to identify its complete bytes.

The CI component is included strictly from its existing `PUBLIC_FILES.json`
allowlist plus the allowlist itself. Private signed download transport metadata
is excluded and is not read by the collector.

Only one nested duplicate container is omitted:
`v3-peer-review-efb2fea/peer-review-efb2fea.tar.gz`. Its original complete hash
and size are retained. Every raw member is included byte-for-byte and mapped
in the exclusion record. This does not claim that the old gzip container bytes
are embedded in the new archive.

The original failed hosted artifact
[`12868778348`](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40799429611/artifacts/12868778348)
is an external official reference: 337,379,434 bytes with SHA-256
`77e2f532ddd607c812607d0d9c3b3494496f22dd84a5dcbd0ec29f39c22c772f`.
Its complete download was verified earlier; the new archive retains selected
original records and does not pretend to embed that complete ZIP.

Ten credential patterns are checked across every selected file and the decoded
Git objects from every retained source bundle. `credential-scan.json` and
`bundle-object-scan.json` state the actual coverage. The collector performs no
native execution, compilation, language admission or new test qualification.

If the compressed archive exceeds the single-blob limit, the receipt specifies
ordered raw parts. Concatenating those parts by index reconstructs the exact
archive, verified by complete size and SHA-256; no archive bytes are omitted.
