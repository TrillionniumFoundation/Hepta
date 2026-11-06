# Native NDU values inside feedback search

This is a bounded research profile. It connects the original pinned NDU scalar
recursive utility and candidate evaluation APIs to every live search backup.
It does not change the compiler, the compiler's qualified source inventory, or
production authority. All advice and receipts retain `DENY_ALL`.

The implementation is split between the [Rust adapter](../rust/hia-ndu-value/src/main.rs),
the [Python transport](../experiments/hia_ndu_feedback_20261106/native.py), the
[finite feedback model](../experiments/hia_ndu_feedback_20261106/model.py), and the
[actual cache workload](../experiments/hia_ndu_feedback_20261106/workload.py).
The [upstream manifest](../rust/hia-ndu-value/upstream.json) pins commit
`8e52e1187f47f6d4edc8d942fc7cb7eca4bc447d`. A source digest is an identity claim;
it is not a license grant, proof of environmental truth, or execution permit.

## Mathematical and experimental scope

For each candidate, the native adapter evaluates one original recursive utility
event with the caller's modeled continuation as its terminal value. In raw Q32
integers, the backup is

\[
V(a)=i_a+\operatorname{roundEven}\!\left(\frac{d_a c_a}{2^{32}}\right).
\]

Here `instant_q32` is \(i_a\), `terminal_q32` is \(c_a\), and `discount_q32` is
\(d_a\). The underlying scalar kernel is affine, subject to the declared fixed
point rounding. The adapter rejects clipping rather than treating projected
values as exact results. A separate call to the original
`evaluate_candidates_with_policy` applies hard feasibility, resource and risk
ceilings, then selects the full Pareto frontier on its single maximizing utility
axis. With zero tolerance this is the complete set of eligible scalar maximizers.
The returned `chosen_id` is the lexicographically first member of that set.

The caller owns the model. In this study it updates a posterior over a hidden
demand regime using only the current observation, enumerates possible next
observations, and computes an external conditional downside adjustment. For
continuation values \(v_j\) with probabilities \(p_j\), the model uses

\[
\mu=\sum_j p_jv_j,\qquad
C=\operatorname{roundEven}\left(\mu-\lambda\sum_jp_j\max(0,\mu-v_j)\right).
\]

The caller passes this \(C\) as `terminal_q32`; it converts its resource-dependent
price into the actual immediate numerical utility before calling NDU. The
`preference_digest` binds that numerical request to its declared preference
state. Changing the digest alone cannot change the scalar utility. The request's
`risk_q32` is a separate hard eligibility metric; it must not be confused with
the model's conditional-risk coefficient or charged again without an explicit
objective change.

These distinctions matter when interpreting the comparison:

- Native values are consumed while search is selecting each node's action.
  A completed ordinary plan is not subsequently rescored and labeled NDU.
- Every candidate at that node, including infeasible candidates and abstention,
  reaches native evaluation. Hard-infeasible transitions do not generate future
  child states, but their candidates and rejection receipts are retained.
- With identical forecasts, candidate space, objective, tie rule and arithmetic,
  the independent ordinary controller and native NDU are expected to agree.
  Agreement establishes integration and numerical consistency, not an additional
  planning advantage unique to NDU.
- Unit discount and linear known costs deliberately remain a degeneration
  control. Splitting a total into several events does not create adaptation value.

This profile does not implement a learned FBSDE, a parameter gradient, a learned
preference estimator, or an optimizer of NDU parameters. Neither a recursively
computed value nor a process named \(Z\) establishes a parameter gradient. Such
claims would require an explicit differentiable objective or a justified gradient
estimator and a separate evaluation. The external finite conditional-risk model
does not turn this adapter's affine kernel into that solver.

## Python API and abstention contract

```python
from hashlib import sha256
from experiments.hia_ndu_feedback_20261106.native import NativeValueBackend, Q32

def digest(text):
    return sha256(text.encode()).hexdigest()

with NativeValueBackend(
    executable_path,
    build_receipt_path,
    log=new_raw_jsonl_path,
    timeout=10.0,
) as backend:
    result = backend.evaluate(
        [
            {"id": "abstain", "instant_q32": -30 * Q32,
             "terminal_q32": 0, "discount_q32": Q32},
            {"id": "serve", "instant_q32": 8 * Q32,
             "terminal_q32": 5 * Q32, "discount_q32": 15 * Q32 // 16,
             "feasible": True, "resource_q32": 2 * Q32, "risk_q32": 0},
        ],
        state_digest=digest("observed state"),
        preference_digest=digest("declared numerical preference"),
        objective_digest=digest("registered objective and units"),
        generation=1,
        resource_budget_q32=3 * Q32,
        risk_ceiling_q32=Q32,
    )
    chosen = result["chosen_id"]
```

The original candidate evaluator **requires an eligible candidate named exactly
`abstain`**. Its utility need not be zero. The backend neither invents this action
nor silently renames another action. In the finite feedback model, abstention
terminates the episode, makes no workload dispatch, and incurs the registered
remaining-request loss. The ordinary controller, independent oracle and native
arms all include that same outcome. An over-budget direct dispatch must not be
presented as feasible abstention.

`id`, `instant_q32`, `terminal_q32` and `discount_q32` are required. The Python
wrapper defaults `feasible` to `True`, and `resource_q32` and `risk_q32` to zero.
It rejects unexpected candidate fields. The wire protocol contains every field
explicitly. Names are unique, contain 1–64 ASCII letters, digits, hyphens,
underscores or periods, and each batch contains 1–32 candidates.

Instantaneous utility, terminal utility and the resulting scalar utility are
bounded by `±1_000_000 * Q32`. Resource use and its budget lie in
`[0, 1_000_000 * Q32]`; discount, risk and its ceiling lie in `[0, Q32]`.
Booleans are not accepted as integer inputs. No normalization is applied by the
adapter. All numerical utilities must use the same declared units. The generation
is a positive integer at most `2**32 - 1`; state, preference and objective
digests are nonzero lowercase SHA-256 hex strings.

`objective_digest` has a fixed research default for API compatibility; a study
should supply its actual frozen objective identity. The default resource ceiling
is `1_000_000 * Q32`, and the default risk ceiling is `Q32`. Resource-limited
experiments must supply their real ceiling instead of relying on that default.

The response includes:

| Field | Meaning |
| --- | --- |
| `values_q32`, `values` | The same complete candidate-to-value mapping; `values` is the Python API alias. |
| `eligible` | Hard feasibility and both numerical ceilings. |
| `winners`, `chosen_id` | All eligible ties, sorted; deterministic first winner. |
| `rejected` | Ineligible identities with original native rejection reasons. |
| `path_receipts`, `evaluation_digest` | Original recursive and candidate-evaluation evidence digests. |
| `sequence`, `request_sha256`, identity digests | The exact request/response binding. |
| `native` | `True` only on the verified native transport response. |
| `native_evaluation_ns`, `outer_call_ns` | Nested diagnostic timing scopes described below. |

## Transport, provenance and failures

The build receipt must identify the pinned original source and record unchanged
original non-manifest inputs, unchanged staged build inputs and the exact current
adapter file inventory. Before execution, the Python wrapper checks that receipt
and the executable hash, seals the executable object, and launches that object.
The native hello frame must match the expected profile and bounds.

The stream uses bounded newline-delimited JSON, a 65,536-byte frame limit,
monotonically increasing sequences starting at one, and a bounded session of at
most one million requests. The wrapper verifies the raw request SHA-256,
generation, objective/state/preference identities, source pin, authority fields,
candidate inventory and native entry points. It independently recomputes Q32
values and eligibility after native evaluation. That calculation detects a bad
response; it never substitutes an answer after a native failure.

Raw hello, request/response frames, their hashes, successful validation, failure
and process close are written to the caller's new JSONL file. Malformed input,
native refusal, identity mismatch, an unexpected extra frame, timeout or numerical
disagreement terminates the session. Close records process return code, forced
kill status, reaping and bounded stderr. A normal successful session must exit
zero without a forced kill. Deliberate negative tests retain their expected
nonzero exit evidence; that evidence is not a successful planning result.

The wrapper does not authenticate external observations. A compromised caller
can submit a self-consistent but false model. Exact arithmetic, pinned code and
matching digests do not establish predictive calibration or goal correctness.

## Cost boundaries

The layers below are nested. They must not be added together as though they were
independent costs.

| Measurement | Included scope and practical limit |
| --- | --- |
| `native_evaluation_ns` | Request parsing, construction of original utility paths, recursive evaluation, candidate evaluation and receipt construction up to the timer sample. Excludes response serialization and pipe output. |
| `wire_roundtrip_ns` in the raw exchange log | Request pipe write through receipt of the native response frame. Includes native work and native output serialization; excludes Python response validation and the subsequent log write. |
| `outer_call_ns` and `total_call_ns` | Successful call entry through input checks, request serialization, exchange, raw exchange log flush, response checks and independent numerical verification. The final `validated` record is written after the timer sample. Failed attempts have separate `attempt_wall_ns` records and are not in `total_call_ns`. |
| `startup_ns` | Receipt/adapter/binary checks, executable sealing, process launch and hello validation. The hello record's final write follows the timer sample. |
| `close_ns` | Close, wait/kill/reap and stderr inspection up to the timer sample. The final close record and log-file close follow it. |
| Caller wall around the complete decision or episode | Required for net value: includes the model, forecasts, search, all native calls, validation, logging and failure handling that actually occurred. Include process startup and shutdown according to the declared session boundary. |
| `build_cost` in the build receipt | Original-source extraction, staging, Cargo work and subsequent source/tool/binary validation. Its explicit scope excludes Python imports, caller startup and the final receipt write. Cache state is retained; it is not a fully cold-machine measurement. |
| CI `preparation.json` | Outer acquisition/toolchain/source-verification and both adapter builds, including failed commands and their wall/CPU costs. Python/runner setup and the final receipt write are excluded. A supplied local checkout/toolchain has unknown earlier acquisition cost. |

An economic comparison must also charge workload preparation, loading, warming,
retention, retirement, actual dispatch, output validation, adoption, unsuccessful
work and any training or calibration used by that arm. Forecasts may be trained
on separate inputs, but final future measurements must not be fed to the planner
before it chooses. The workload wrapper returns measured wall cost only after
the selected commands complete. Kernel-only timing is not net benefit.

## Build, CI and evidence publication

[The builder](../tools/build_hia_ndu_value_bridge.py) delegates to the existing
isolated original-source builder. It reads the three pinned upstream crate trees
from Git objects, verifies blob identities, copies original non-manifest bytes,
and creates isolated production manifests. That manifest isolation is explicit;
the claim is unchanged original Rust and non-manifest inputs, not an untouched
monorepo workspace. The lockfile, toolchain, adapter inventory, original input
hashes, build command, costs and binary hash are retained in the build receipt.

```bash
RUSTC=/absolute/rust-1.95.0/bin/rustc \
  CARGO_TARGET_DIR=/absolute/private/value-target \
  python -B tools/build_hia_ndu_value_bridge.py \
  --upstream /absolute/private/pinned-git-checkout \
  --output /absolute/private/new-value-build \
  --cargo /absolute/rust-1.95.0/bin/cargo
```

The [dedicated workflow](../.github/workflows/hia-ndu-feedback.yml) uses one job
with read-only repository permission and no added secret. It runs these gates:

1. Check out `github.event.pull_request.head.sha` for a pull request and
   `github.sha` for a manual dispatch. Both source snapshots require an explicit
   `--expected-head` from that event identity and compare it to the actual
   checked-out `HEAD`. Freeze every tracked source hash and the worktree status.
   The final snapshot must retain the same expected identity as the first.
   Artifact names use the observed checkout SHA. A clean, unchanged synthetic
   merge does not satisfy an exact PR-head requirement, even when its tree is
   byte-identical. Temporary Git-fixture controls verify rejection of wrong
   heads, same-tree merge commits and a changed expected head between snapshots.
2. Run the engine, workload boundary, campaign, mechanism-coverage, forecast-price,
   exact-arithmetic, source-closure, dynamic-cache and preparation-bound tests.
   Empty inventories, import failures, test failures, errors, expected failures
   and skips cannot produce a pass.
3. Install Rust/Cargo 1.95.0, anonymously fetch the exact upstream pin using the
   repository's existing Git-fetch pattern, and build separate value and workload
   adapters outside the checkout.
4. Run every native backend test with zero skips, including 3,000 randomized
   native differential requests. Run native wiring reversals, the expected linear
   degeneration, and finite-model decisions checked against the ordinary
   same-objective controller and independent oracle.
5. Execute a small real native cache episode. Its observed workload wall cost is
   fed back only after execution; output checks, chosen/executed action identities
   and balanced close receipts must pass. Its forecast costs are declared smoke
   inputs, not calibrated performance evidence, so it makes no speedup claim.
6. Recheck identical clean source even when a preceding step failed, then stage a
   closed allowlist of evidence files for upload.

The [CI harness](../experiments/hia_ndu_feedback_20261106/ci.py) retains private
upstream trees, build outputs, executables and raw compiler streams under
`runner.temp`. Compiler diagnostics can include private source lines, so they are
not uploaded. Uploaded artifacts contain only explicitly named structured build
receipts, command exit/cost/stream-hash records, test logs, source inventories and
research request/response JSONL. No source-tree glob, private fixture JSON or
derived executable enters the upload staging directory.

If the pinned upstream cannot be fetched with existing access, preparation fails
and records the upstream access gate as `OPEN`. The workflow does not introduce a
token, widen permissions, skip native tests, replace the evaluator, or claim that
the hosted CI passed. Local success with already supplied pinned Git objects is
separate evidence and does not establish hosted fetch availability.

The workflow validates this finite research profile. It does not replace the
production compiler gates, establish out-of-distribution calibration, demonstrate
an FBSDE learning mechanism, or prove positive net value.
