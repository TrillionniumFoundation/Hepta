# Native deadline fixture repair

The historical 69-test qualification retains one failure: evaluation was
correctly refused as `context/E_HIA_BUDGET` before entering its reference
runner. The test slept until about 100 ms before the context deadline *before*
dispatch. Input validation, source-identity hashing, context I/O and scheduling
could consume that window. The retained log does not isolate their individual
costs. It is not evidence of a restarted production budget.

The test now dispatches while its original context is live. A test-only barrier
calls the real `_required_claims`, then waits inside the admitted evaluation
until the same original deadline-minus-100ms point. The real reference runner
must be called, start its disposable child, return `budget_exceeded`, and
confirm termination. The candidate's native mode must remain unstarted.

Clock instrumentation records and returns the actual `time.time_ns()` values.
The timeout passed to the reference runner must equal the original retained
context deadline minus the last real clock observation, using the production
integer-millisecond formula exactly. There is no clock substitution, new
budget, tolerance constant or production-code change.

The total budget remains 3000 ms and the native budget remains 1000 ms. The
old boundary of 0.75 seconds after dispatch at deadline-minus-0.100 seconds is
expressed as the same absolute `sampled_at + 3.0s + 0.650s` upper bound. The
production runner's cleanup behavior is unchanged.

A separate new test waits past the same retained creation-time deadline and
requires a context budget refusal with zero reference/native runner calls,
the original context timestamp, zero native budget consumption and no native
owner. That refusal cannot satisfy the reference-loop test.

## Source and results

- Base: `9ba2a6202277e3d3418d3a8205450973174eb812` (PR #824).
- Tested code commit: `7cd5ea219d74ebf9d3b2253f29718cc36e8221fb`.
- Tested code tree: `ccf4ed1977ecc4c988dc16e02d9e3c29375491cd`.
- Only `tests/test_hia_agent_native_tools.py` changes. The Hepta production
  package, support contract, online service and default release lock do not.

All three modules from the historical campaign passed **70 tests**, zero
failures/errors/skips, in 47.027 seconds. Inventory reconciliation retains all
69 original test identities and adds only the expired-admission test. This is
a new local qualification on the stated source; the historical 68/69 result
is not relabelled or removed.

The focused pair passed. An additional raw replay records one real reference
runner and one underlying process-owner call, with no native-mode calls:
`timeout_ms=99`, `wall_ns=102319521`, `returncode=-9`, `started=true`,
`termination_confirmed=true`, `status=budget_exceeded`. These fields establish
the disposable reference-process path and termination, not a separate trace
of exactly how many guest VM instructions executed before termination.

An in-memory fault that grants a fresh 3000ms reference budget fails the new
exact timeout assertion. The original historical failure, the first fixture
repair attempt (which hit the VM's separate step limit), this deliberate fault
failure, and the successful results are all retained in `raw-evidence.zip`.
The archive's `FILES.json`, CRC and each member's size/SHA256 were checked.

## Reproduction

```sh
python -B -m unittest tests.test_hia_agent_native_tools tests.test_hia_agent_native_machine_validation tests.test_hia_agent_native_proof_contract -v
python -B review-evidence/hia-native-deadline-test-20261109-5e86/replay.py --output /new/replay-directory
python -B tools/generate_hia_selfhost_contract.py --check
```

The replay needs the same Linux x86-64 native tools, jsonschema and pinned Z3
dependencies as those modules. It records actual outcomes and does not change
the installed runtime configuration. This test repair does not close general
compiler, ABI/FFI/ISA, provider-cost or economic-benefit obligations; overall
six-track acceptance remains **HOLD**.
