# Source distribution contents

The Python wheel installs only `hepta` and its existing command-line entrypoint.
The source distribution also carries the checked-in inputs needed by its shipped
tests and existing Makefile commands. These development files do not become
installed runtime packages.

`MANIFEST.in` explicitly includes the helper scripts, Hepta/C/Rust examples,
example package manifests and lock, benchmark source fixtures, formal source and
toolchain locks, and the original `experiments/agent_eval` fixture inputs. The
evaluator's manifest-listed files retain their original bytes and hashes.
Its README explains that its reference solutions are already public repository
inputs, not secrets from readers of the complete repository.

Generated evidence, artifacts, bytecode caches, toolchains, unrelated experiments
and archived research results are not part of this source-distribution contract.
Including source for a native, formal or evaluator command does not execute it
or establish that it passes. Compiler installation remains a separate action.

## Artifact-only regression

From a Git checkout, with the declared setuptools build backend already installed
and any new distribution inputs added to the Git index:

```sh
python -B tools/check_distribution.py
```

The check copies the complete tracked working tree into temporary directories,
adds exclusion sentinels, and uses the installed PEP 517 backend. It does not
resolve dependencies, install a package, import project modules or tests, run
test bodies, invoke native compilers, launch models or studies, or upload files.
It checks:

- The independently enumerated source/fixture inputs are present byte-for-byte.
- Deliberately placed evidence/cache/unrelated-source sentinels are absent.
- A wheel rebuilt from the sdist has the same members and bytes as direct wheels
  built with and without the manifest, including entrypoint metadata.
- Omitting helpers, benchmark sources or an evaluator fixture causes rejection
  for that specific missing input. Including generated evidence or other real
  tracked documentation outside this contract also rejects.
- Original source and frozen fixture bytes remain unchanged.

The output reports packaging results only. It is not a project test-suite pass,
native/formal/performance qualification, release certificate, or permission to
run any frozen study. Existing test and release gates are unchanged.

## Distribution permission remains unspecified

The inspected repository has no `LICENSE`, `COPYING` or `NOTICE` file and its
project metadata declares no distribution license. This change does not assign
a license or claim that public source is freely redistributable. No third-party
implementation, toolchain binary or package archive is added. Maintainers must
resolve distribution permissions before publishing a release or package.
