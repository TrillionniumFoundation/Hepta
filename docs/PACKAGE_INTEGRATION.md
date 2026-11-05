# Offline package selection and lock review integration

This draft composes two bounded P12 increments at their exact source heads:

- Local resolver [#690](https://github.com/TrillionniumFoundation/Hepta/pull/690),
  `1819615983e6241c92efa53e73992312add850a2`.
- Lock comparison [#691](https://github.com/TrillionniumFoundation/Hepta/pull/691),
  `ff260748c05e30f696e701b5b485b3b7dd24ef6e`.
- Shared main base: `125d11c5454835a7df1dc51915fc49901fbede5b`.

Both production changes are preserved byte-for-byte: `packages.py` and
`package_resolution.py` from #690, `cli.py` and `lock_diff.py` from #691. Their
focused suites, independent oracles and workflows are also unchanged. The
checked-in `tests/package_integration_components.json` binds those retained
files by Git blob and SHA-256. Shared documentation incorporates both contracts.
No other open research branch is composed.

## Workflow and compatibility boundary

1. Create a lock with `python -m hepta lock path/to/app` and save a copy.
2. Intentionally change a candidate requirement, local package version, selected
   source, or fixed dependency. A previously valid lock may now be stale.
3. Explicitly refresh using `python -m hepta lock path/to/app`. Unsatisfiable or
   malformed reached declarations reject and leave the previous lock unchanged.
4. Compare saved and refreshed locks with
   `python -m hepta lock-diff before.lock path/to/app/Hepta.lock --check`.
5. Validate or execute the refreshed project with `--locked` using the chosen
   supported backend. Lock review itself never compiles or executes source.

The wire format stays `hepta.lock.v1`. The existing checked-in fixed-path example
lock verifies and regenerates byte-identically. Fixed paths can retain several
versions of one package name; candidate identity unification remains separate.
If a fixed edge and candidate edge select the same directory, their package
record is shared. A candidate selected at a different path appears as a package
removal/addition and an edge retarget, even if its version string is unchanged.

Changes to a requirement or candidate ordering can change a manifest hash without
changing the selected graph. Unselected candidate **source bytes** remain outside
the lock until selected. Candidate metadata is still read as required by the
resolver. If a new winning candidate changes the selected graph, the old lock is
stale. Comparison of saved locks needs no package directories at all.

Every successful report still says `compatibility: "not_assessed"`. These checks
establish finite wire-format/command interoperability, not source, API, ABI,
behavioral or deployment compatibility. In particular, the native fixture
intentionally changes its observable exit from 7 to 9 after an upgrade. A valid
lock or a readable diff does not make that behavioral change acceptable.

## Reproducible qualification

Run from the repository root with a real GCC-compatible compiler:

```sh
PYTHONDONTWRITEBYTECODE=1 python -B tools/qualify_package_integration.py
```

To require actual pinned Rust 1.90.0 instead, set
`HEPTA_PACKAGE_TEST_BACKEND=rust`. Missing compilers fail rather than skip.
The gate refuses Python `-O`, since the independent oracles use assertions.

The strict inventory is **65 unique methods**: 27 resolver, 17 comparison,
12 integration and nine unchanged legacy package controls. Planned, started,
finished and passed identities must match exactly, with no failures, errors,
skips, expected failures or unexpected successes. The gate verifies retained
component bytes and hashes the source tree before and after all checks.

The new public CLI workflows cover upgrades, transitive backtracking/shared
edges, selected-source edits, unchanged selections with changed requirements,
unselected-source behavior, failed refresh/recovery, malformed declarations,
equal-version retargeting, mixed fixed/candidate identities, offline comparison,
layout-preserving relocation and the original checked-in lock. Four actual
native executions per gate observe exit codes 7, 9, 7 and 7, with empty output.
Their receipts include the actual compiler identity, generated-source and
artifact hashes, compilation flags and locked snapshot hash.

All three independent oracles run against the same combined source:

- The unchanged resolver oracle: 500 three-identity graphs, including 149
  satisfiable and 351 unsatisfiable graphs with fixed paths and candidate cycles.
- The unchanged lock-reader oracle: 1,000 graph-admission fixtures.
- A separately authored composition oracle: 326 finite acyclic graph states,
  250 satisfiable and 76 unsatisfiable, with 249 forward/reverse transition pairs
  and 748 complete delta comparisons. It independently exhausts candidate
  assignments, builds expected selected snapshots from manifest/source hashes,
  and derives complete differences without production resolver/range/diff
  helpers. It includes 20 backtracking states and 62 distinct fixed-A1/candidate-A2
  states, plus unchanged-path version and source-only changes. Unsatisfiable
  writes must preserve the existing lock. It is not a general solver proof.

Local qualification passes all 65 methods and all three oracles on Python
3.12.14 and 3.13.5 with actual GCC 14.2.0. Native Rust, ARM and Python 3.11 were
not run locally. The read-only exact-head hosted workflow requires Python
3.11/3.13, Linux x86-64/ARM64 and C/Rust lanes, retaining each complete log.
Hosted qualification must be read for the exact integration commit; component
CI results do not qualify this composition.

## Remaining scope

This is an integration draft, not a merge or a claim that P12 is closed. It adds
no production logic beyond the two exact inputs. Registry resolution, general
SemVer ranges, migration automation, compatibility analysis, signatures,
production standard library and ecosystem qualification remain open. Full
project, release, formal and performance gates were not run. The finite native
fixtures establish selection behavior only, not whole-compiler correctness,
filesystem atomicity, concurrency safety or a security boundary.

## Initial hosted toolchain-selection failure

The first integration head `282586c2d63ea5911c22cd228cd462109e3f8e79`
retains its original [run 41995147650](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41995147650).
All four C lanes passed. Rust jobs
[127136406800](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41995147650/job/127136406800),
[127136407150](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41995147650/job/127136407150)
and [127136407151](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41995147650/job/127136407151)
installed/defaulted Rust 1.90.0 successfully, then rejected at the unchanged
`toolchain_info(find_rustc())` preflight with `E_TOOLCHAIN_IDENTITY`, before any
suite method or oracle. These are failed qualification attempts, not test passes.

Selecting a rustup default does not supply a direct compiler path to Hepta:
`find_rustc` resolves symlinks, while rustup's command-name-dispatched `rustc`
shim can point to the rustup executable. The workflow now obtains the actual
compiler with `rustup which --toolchain 1.90.0 rustc`, checks that it is executable,
prints its complete `-vV` identity and exports that path as `RUSTC` for the gate
and every child CLI invocation. It also records the original PATH/shim paths.
No compiler production file, component bytes, test, oracle, inventory or gate
acceptance rule changes. The strict 1.90.0 identity requirement remains intact.
The original failed run is preserved; a fresh exact-head matrix must qualify
this correction before hosted Rust success is claimed.
