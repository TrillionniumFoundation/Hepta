# Native release selector integration: development observations

The release selector was ported from immutable source
`5d5424a31caa33283a562defba9cb6b187deb99c` onto
`34963d4f0a80acd7e59b15db2bbdbb42f5f76fa3` and integrated into the distinct
`selfhost-core-linux-x86_64-v68-native-source-build-release-selection` profile.
The two HIA programs retain their exact original bytes. Current paths use
`.hepta`; the authoring and build drivers also resolve direct CLI imports from
outside the checkout. The native policy, adapter instructions, package and state
formats, rejection behavior and resource budgets are unchanged.

**The development test run failed four required fault controls.** There are
21 passing controls and four failures, with no skips or expected failures.
This is not a completed cold qualification or whole-product native approval.

| Controls | Observed result |
| --- | --- |
| Independent HIA VM, packer bytes and policy review | 7 passed |
| Actual native installer and selector kernel tests | 6 passed |
| Independent actual kernel review | 8 passed |
| Actual `strace` fault injection | 4 failed: environment denied `ptrace` |
| Source contract, language inventory, CI, source suffix and CLI entry controls | 37 passed |

The last group exercised all 43 declared public builders with absolute-path
`--help`, Python `-I`, an unrelated working directory and no `PYTHONPATH`.
The Core-only source check observed 92 HIA sources and 155 production Python
modules. The current source contract binds 670 files; its cold input map also
contains the generated contract itself. The development runner compared that
complete map before and after the 25 selector tests and observed no change.

Each native test class built a fresh B0/B1/B2 development compiler and checked
that B1 and B2 bytes were equal. The actual installer and selector ELFs were
packed from the resulting native images. Successful controls exercised real
installed releases, CAS and rollback, contention, corrupt and impossible state,
lock-file attacks, a broken receipt pipe, and actual SIGKILL after publication
with a blocked receipt. These actions were confined to newly created test roots.
They did not migrate an ordinary worker or modify a slot/lease ledger.

The four failed tests actually invoked `/usr/bin/strace`. The environment
refused `PTRACE_TRACEME` and `PTRACE_SETOPTIONS` with `Operation not permitted`.
The failures establish no successful fsync, EINTR or strace-mediated crash
injection. They remain unchanged and mandatory in the native CI step and the
current qualification-v4 runner. Independent broken-pipe and process-death
tests passed without ptrace, but do not replace those four obligations.

## Retained records

- [Development result](development-result.json): exact 25-test result,
  original failure tracebacks, profile and complete source identities.
- [Development log](development-tests.log): all passing and failing test names.
- [Integration source log](integration-source-tests.log): 37 passing controls.
- [Source scope](source-scope.json): actual source-format and package counts.
- [Summary and native identities](summary.json): B1/B2 comparisons, ELF
  inspections, image/input/receipt hashes and explicit qualification limits.
- [Import record](import.json): original and suffix-adapted bytes before the
  two direct-entry import guards were added.
- [Kernel observations](ReleaseSelectionKernelTests.observations.json),
  [fault observations](ReleaseSelectionFaultTests.observations.json) and
  [independent review observations](ReleaseSelectionReviewKernelTests.observations.json)
  preserve the original class receipts byte for byte.

Large native binaries and temporary release trees are not committed. Their
identities are recorded in the summary. The source files and original test
drivers are sufficient to rebuild fresh development artifacts; a reproduced
run must retain its own source and environment observations.

## Reproduction

From this checkout, choose a new private output directory:

```sh
env -u HEPTA_HIA_RELEASE_SELECTION_COLD_REPORT \
  HEPTA_HIA_RELEASE_SELECTION_OBSERVATIONS=/new/private/selector-development \
  python -B -m unittest -v \
  tests.test_hia_release_selection.ReleaseSelectionSourceTests \
  tests.test_hia_release_selection_review.ReleaseSelectionReviewPolicyTests \
  tests.test_hia_release_selection.ReleaseSelectionKernelTests \
  tests.test_hia_release_selection.ReleaseSelectionFaultTests \
  tests.test_hia_release_selection_review.ReleaseSelectionReviewKernelTests
```

This explicit development route does not relax the production builder. The
builder requires the completed cold report for the exact current source and
compiler before creating output, then rechecks source, compiler, report and
consumed images before publishing. A later merge must be qualified as its own
source identity; these observations do not transfer to changed input bytes.
