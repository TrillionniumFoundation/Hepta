# Intelligent assembly closure CI

The new `.github/workflows/hepta-intelligent-assembly-closure.yml` is an additional
gate for the current semantics, callback implementation migration, call expansion,
chained guarded proofs, and finite planning work. The existing verified-optimization
workflow remains unchanged.

## Required core job

Pull requests check out the exact `pull_request.head.sha`; manual runs check out
the selected workflow commit. Both jobs verify that commit, record its tree, and
reject changes to tracked source. They use Python 3.12, the project's pinned
`z3-solver==4.13.4.0`, and the existing signed LLVM 20 installation profile.
Clang's actual patch version and executable identities appear in the evidence;
the apt installation pins the major version, not a permanently fixed package build.

The core job runs these declared suites and fails on every skipped or expected-failure
test, incomplete test run, ordinary failure, or error:

- `test_hia_semantics_contract`, `test_hia_call_expansion`, and
  `test_cpp_callback_project`, including their actual native tests.
- `test_hia_planning.FiniteCompressionTests` and the two non-native graph classes
  `FiniteGraphTests` and `CompilerGraphBoundaryTests`.

It then retains a full callback qualifier run and feeds that run's
`three_weight/standalone.core.json` directly into the call-expansion qualifier.
This covers actual Clang capture, separate original C++ and HIA executions,
independent value/resource observations, callback rejection and cancellation,
allocator high-water measurements, proof/receipt binding, and the registered
native trap cases. A missing compiler, solver, result, or callback-error observation
fails the job.

The callback qualifier records both C++ `-O3` and `-O3 -flto` baselines. CI uses
50,000 benchmark calls and three repetitions to keep this gate small; it retains
the complete correctness and failure-path corpus. No speed ratio, net-benefit
sign, or claim of superiority is a pass condition. The callback integration unit
test also runs its own independently created qualification directory.

## Optional original native NDU job

Dispatch the workflow with `run_native_ndu: true` to require the native job after
the core job. An ordinary pull-request run does **not** qualify native NDU; its
`SCOPE.json` records `native_ndu: not_qualified`. The disabled job is not evidence
that any native test passed.

The native job uses the existing source pin
`c4a1bbed3a39beba43a6abf1a18b6f75c5725c21` in
`TrillionniumFoundation/hepta-private-ci`, Rust 1.95.0, and
`tools/build_hia_ndu_bridge.py`. It builds the original crates in a new target
directory and admits their actual source/tool/binary identity. The optional
repository secret `HEPTA_NDU_READ_TOKEN` can supply read access to the private
source; otherwise checkout uses the workflow token. Lack of access or a failed
build fails a requested native job. There is no substitute evaluator or
`continue-on-error` path.

The native job runs the complete planning and graph test modules with zero skips,
then both one-shot and stream compression qualifications. Their saved results must
say `native.status: executed`, contain native differential cases, and account for
the original build within the declared controller cost scope. Merely producing a
model-only result with `native.status: blocked` cannot pass.

Finally it runs the compiler graph's unchanged registered protocol with all six
original controls plus `ndu-compact` and `q32-dp`. Correct outputs, completed
episodes, the existing absolute budgets, and complete declared cost accounting
are required. Relative timing remains descriptive. The authority stays
`DENY_ALL`; an NDU recommendation does not issue a safety certificate.

## Evidence and local reproduction

Artifacts are uploaded on success and failure. The core artifact includes the
source commit/tree, scope, solver and tool versions, declared test inventory,
test log, callback reports and actual binaries, and the call-expansion reports.
The native artifact additionally includes its original build manifest and bridge
binary. Failed or partial reports must retain their status when cited.

With the same dependencies installed, reproduce the retained core qualification
using fresh output directories:

```bash
python tools/qualify_cpp_callback_project.py \
  --workdir artifacts/local-closure/cpp-callback \
  --clang /usr/bin/clang-20 --clangxx /usr/bin/clang++-20 \
  --cc gcc --iterations 50000 --repeats 3
python tools/qualify_hia_call_expansion.py \
  --output artifacts/local-closure/call-expansion \
  --clang /usr/bin/clang-20 \
  --component-core artifacts/local-closure/cpp-callback/three_weight/standalone.core.json
```

The CI script supplies the strict no-skip unit runner. Ordinary `unittest` success
alone is insufficient when optional dependency checks can skip native tests.
These finite qualifications and checked transformation rules do not establish
whole-language soundness, backend refinement, unrestricted C++ coverage, or
unrestricted global optimality.
