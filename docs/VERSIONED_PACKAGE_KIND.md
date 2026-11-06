# Package-kind diagnostics in versioned package contexts

This bounded composition stacks on #739
`10b8d29da50ea26ef3d26fb4219750915654d101` and carries the one-line kind guard
from #687 `537eb4ff1e41b79d7a84f8fa2a961a6c44b6012b`. It does not merge either
pull request. The original documents remain historical records of their own
sources and qualifications.

## Production change and compatibility

The only production change requires `kind` to be a string before testing
membership in the allowed `bin`/`lib` set. The resolver already moved this
manifest parsing into `read_package`; the original guard transfers there
without changing its diagnostic text, order, phase or path attribution.
An array/table kind therefore raises `E_PACKAGE_SCHEMA`, rather than escaping
as Python `TypeError`.

Every explicitly listed version candidate is read before candidate selection.
The repair does not ignore a malformed lower, higher or out-of-range candidate,
silently fall back to an older version, or change the resolver's graph search.
Schema rejection precedes lock verification and module-context checking.
Restoring the original valid manifest preserves selection and restores the
existing `E_MODULE_PACKAGE_CONTEXT` rejection for a conflicting import.
Failed lock refresh leaves the previous lock byte-identical. Valid version
changes still require explicit refresh and lock review remains
`compatibility: not_assessed`.

## Original-source obligations

Of 177 parent files, 173 remain byte-identical, including every existing
workflow, test, oracle, inventory, compiler backend and the 65-method runner.
The four adapted files are `hepta/packages.py`, the two source manifests and
`tools/qualify_versioned_package_context.py`. The last adds only a two-line
call to an independent provenance check before its original input checks.
Its 83 method identities and execution logic do not change.

Both original manifests and the complete parent blob inventory are archived
and hard-pinned. The new verifier requires the exact inverse guard and exact
inverse two-line runner insertion to recover their original blobs. Current
manifests must equal their archived originals with only named identity slots
changed and the new verifier pin added. All other parent files retain their
original blobs. The original 10-method schema test and scope document retain
their exact #687 blobs. New qualification inputs are separately pinned.

This preserves the original checks rather than overwriting hashes without
retaining provenance. Both the original 83-method runner and the new focused
runner require this verification. The original 65-method runner continues
checking all its existing component identities against the adapted manifest.

## Focused checks and hosted qualification

Run with Python assertions enabled:

```sh
python -B tools/qualify_package_kind_context.py
CC=gcc HEPTA_PACKAGE_TEST_BACKEND=c python -B tools/qualify_versioned_package_context.py
```

The first command requires the original 10 schema methods and four new
version/context/lock intersections, with identical planned, started, finished
and passed lists, no skips/failures/errors/xfails/xpasses, and unchanged source.
These 14 methods do not compile or execute Hepta programs. They include 22
actual CLI subprocesses: 14 original schema checks, six versioned schema
refusals and two frontend-only recoveries.

The unchanged scoped C execution logic retains 83 methods and its two scoped
oracles. The separate inherited 65-method workflow and all original workflows
remain intact. A new single-host Python 3.13 workflow runs the 14 focused
methods on an exact-head isolated source snapshot and retains identities and
logs even on failure. Uploaded logs or queued jobs are not passes; verify
completed results for the published head separately.

Native Rust context parity, omitted cycle-specific methods, complete original
suites and the other original graph oracles are outside the local scoped
qualification. Frontend Rust emission is not native Rust execution.
P01/P11/P12 remain PARTIAL. No soundness, performance, production, merge,
release or deployment claim is added.
