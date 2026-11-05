# Isolated installed-compiler qualification

This draft advances the finite P11/P12 installed-tool qualification boundary.
It is stacked only on [#710](https://github.com/TrillionniumFoundation/Hepta/pull/710),
exact `0594a85f2f1e05ef50a61bf9c5a18ae191499502`, and changes no compiler,
packaging configuration, source library, existing test or inherited gate.

[#677](https://github.com/TrillionniumFoundation/Hepta/pull/677) checks the old
main source archive's test inputs and wheel member bytes, deliberately without
installation, imports or native execution. It is not composed here. This new
check actually installs and executes #710's compiler, comparing direct-wheel
and source-distribution-rebuilt-wheel routes. It does not claim that this
branch's source archive includes a runnable development/test suite. That
separate source-distribution composition remains open.

## What is installed and what is copied

The existing `hepta-language` 0.2.0 wheel installs only 16 `hepta/*.py` runtime
files and its distribution metadata. All 21 wheel members, including RECORD,
are checked; direct and rebuilt member bytes must match exactly. ZIP container
bytes/timestamps need not match. Existing packaging metadata stays unchanged.

The four Hepta libraries and typed packet/text packages are **separately copied
source fixtures**, not wheel contents, bundled standard-library resources or
published library releases. They retain the original public local-dependency
layout. Both fixture trees are relocated before any compiler execution; original
checked-in locks must still validate without regeneration. The initial checked-in
entry program remains byte-identical for the CLI tests. Later oracle generation
and explicit relocking affect disposable fixture copies only.

`tools/installed_compiler_components.json` binds all compiler Python sources,
pyproject metadata and selected fixture files to exact #710 bytes. The runner
snapshots the complete supplied source tree, not only expected packaging inputs.
A clean full-source copy builds the direct wheel; another builds the sdist, whose
unpacked contents build the second wheel. No dependency resolution is invoked.
Owned temporary build-source copies are removed before installed execution.
The original checkout itself is neither removed nor made inaccessible. Isolation
is established by interpreter flags, separate environments, import origins and
payload checks, not by a filesystem sandbox claim.

## Executed checks

Each wheel is installed offline into a separate fresh virtual environment with
system-site-packages disabled. A preinstalled trusted host pip targets that
environment with `--no-index --no-deps --no-compile`; it does not fetch an installer
or a build backend. The host setuptools and pip versions are recorded separately
from the selected target Python version. Application dependencies remain empty.

- Absolute console-script and `python -I -B -m hepta` entrypoints both report the
  expected version and run the relocated, locked seven-module native example.
- Console `build` produces an independently executed native artifact. Reports
  identify the compiler bytes, real compiler executable, version, target, flags
  and artifacts. There is no frontend-only success substitution.
- A source-library edit produces `E_LOCK_STALE` and preserves the lock bytes.
  Restoring that source restores successful build/run without rewriting the lock.
- A separate installed-only probe builds 21 independently expected packet cases:
  16 success cases (empty, duplicates, Unicode boundaries and seeded sequences)
  and all five typed errors. Every backing input/scratch/scalar element is checked,
  including prefixes, suffixes, error payloads and success range fields.
- The oracle executes at O0/O3. C requires nonrecovering UBSan. Two separately
  compiled wrong-expected-scalar-count controls per wheel must actually abort.
  These controls prove detection of a wrong observation, not fault injection into
  production compiler code. Native Rust uses the existing panic-abort contract.
- Per interpreter/backend lane: two installations, **14 native program runs**
  (10 expected successes, four expected wrong-output aborts). The 21-case corpus
  runs four times successfully across wheel routes and optimization levels.
  Compilation/probing subprocesses are retained but not counted as program runs.

The import check requires the exact venv `site-packages/hepta` location, complete
runtime-file hashes and distribution entrypoint identity. Its independent
compiler hash must match the public build report. Ambient Python/pip overrides
are scrubbed and the working directory contains a deliberately failing `hepta`
package. A non-isolated module invocation must hit that sentinel; the qualified
isolated module and console invocations must not. This is a tested ordinary
installation configuration, not resistance to a malicious Python runtime,
installer, `.pth` file, interpreter standard library or host operating system.

Eight packaging/import controls run: four in-memory wheel validation refusals
(missing runtime module, changed runtime bytes, missing entrypoint, invalid
RECORD), two active cwd-import sentinels, and two actual missing-installed-module
refusals. The latter temporarily park one file in each owned venv, require the
installed-byte verifier to reject it, then restore it before native checks.
Those byte checks are not represented as execution of a broken compiler.
Two stale-lock refusals and four native wrong-output aborts are separate controls.
All commands, outcomes and native receipt hashes are retained in the JSON report.

## Reproduction and scope

Use a preinstalled setuptools >=68, pip with `--python` support and the selected
native compiler. This command neither downloads build dependencies nor publishes
anything:

```sh
PYTHONDONTWRITEBYTECODE=1 python -B tools/qualify_installed_compiler.py > /tmp/installed-c.json
# A different target interpreter can be qualified with the same host builder:
python -B tools/qualify_installed_compiler.py --target-python /usr/bin/python3.13 > /tmp/installed-c313.json
# Requires an actual pinned Rust 1.90.0 compiler, otherwise refuses:
python -B tools/qualify_installed_compiler.py --backend rust --rustc /absolute/path/to/rustc > /tmp/installed-rust.json
```

The runner refuses optimized Python, unavailable selected compilers, changed
parent components, inventory drift and incomplete native outcomes. It checks all
source bytes before/after; it never discovers or executes the broad project test
suite. The read-only workflow checks the exact PR head on Linux x86-64/AArch64,
Python 3.11/3.13, and C/Rust. Hosted outcomes qualify only their exact source and
actual platform. A queued job is not a pass.

Locally, Python 3.12/3.13 C qualification is the available scope. Rust, ARM and
Python 3.11 are not local claims. The full language, wider platforms, registry,
release signing, automatic library bundling, complete development sdist,
performance and production-standard-library obligations remain open. Native raw
pointer caller obligations and other parent limitations are unchanged.

The repository still has no distribution-license grant established by this
check. Wheels/sdists are temporary local test products and are not uploaded,
published or released. No new dependency, license or legal permission is added.
Draft only; no merge, deployment or activation. P11/P12 remain PARTIAL and
`whole_project_blockers_closed` remains false.
