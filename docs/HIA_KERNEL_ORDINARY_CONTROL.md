# Independent native ordinary control for the full kernel comparison

This is the independent same-objective arm. It implements ordinary finite-horizon
path evaluation in a separate Rust executable with no Hepta or NDU dependencies.
It does not invoke the NDU executable, consume NDU advice, or construct native
PreferenceState digests. Its purpose is to keep language and compiler differences
out of a claim about the NDU framework.

The complete experiment remains owned by the kernel comparison driver. An
arithmetic qualification pass is not a kernel performance result. Only actual
qualified complete images and real guest calibration/held-out observations may
enter the measured campaign.

## Build identity and timing

The builder reads the actual frozen native NDU build receipt and requires equal
full cargo/rustc version strings and the same RUSTFLAGS,
CARGO_ENCODED_RUSTFLAGS and CARGO_BUILD_TARGET. The registered toolchain is Rust
1.95.0. Both executables use the ordinary Cargo release profile; this control does
not add custom LTO, target CPU or optimization settings.

The control has its own new target directory. Dependency resolution is
--locked --offline, Cargo uses one build job, and the resulting package graph is
recorded and checked to contain no Hepta crates or Git dependencies. The source,
compiler executables, build commands/logs, dependency lock, output binary and
actual build wall/CPU cost are bound in the build receipt.

For planning, use identical cold process launch or identical persistent stream
mode for the paired arms. Save both complete serialized requests and responses.
Charge actual external process wall time, including startup, input/output and
serialization. service_before_output_ns covers parsing, validation and evaluation
up to constructing the response, and is supplementary: it excludes final JSON
serialization and flushing in both implementations. Synthetic test durations
must not be used as kernel performance observations.

## Interface

One-shot invocation reads one JSON value from standard input and writes one
JSON line to standard output. Errors write a reason to standard error and exit
with code 2. --identity returns the independent profile. --stream has the same
framing limits as the native NDU adapter: 1 MiB per frame, 256 requests, a hello
line, one response or refusal per newline-terminated input.

The outer schema is hepta.hia.kernel-ordinary-control.request.v1:

    {
      "schema": "hepta.hia.kernel-ordinary-control.request.v1",
      "request": { "...": "complete hepta.hia.kernel-ndu.request.v1 fields" },
      "previous_weights": null
    }

The embedded request is the same supplied image/path/objective/observation shape
as the NDU adapter. Its preference.previous_state must always be null. A non-null
native state is rejected. preference.genesis_values always retains the registered
initial values. On the first call previous_weights is null; on later calls it is
this arm's own previous response.preference.weights:

    [{"axis": "latency", "value_q32": 3221225472},
     {"axis": "memory", "value_q32": 1073741824}]

All Q32 fields are signed 64-bit JSON integers. The comparison driver binds the
previous ordinary response to the next ordinary request and never copies an NDU
state or response into this control. The control validates all axis dimensions
and bounds. It accepts the embedded request as a raw JSON value only to retain
the exact input bytes for hashing; it parses every field into explicit typed
structures and rejects unknown fields. There is no opaque program or evaluation
payload.

The response schema is hepta.hia.kernel-ordinary-control.response.v1. It includes:

* input_sha256 for the complete outer bytes and request_sha256 for the exact
  embedded request bytes (canonical serialization by the driver gives the same
  request hash as a standalone canonical request).
* Objective, snapshot, action-registry and generation bindings.
* preference.initial_weights, target, effective_target, weights and eta_q32.
  Weights are arrays of axis/value_q32 objects, sorted by axis.
* preference.iterations with iteration, residual_raw, projection_count and the
  complete values after each step. termination includes iterations,
  terminal_residual_raw, maximum_residual_raw and projection_count.
* Every paths entry, including all weighted terms, phase cost, instantaneous
  utility, backward values_q32, feasibility and explicit rejection reasons.
* The exact maximizing pareto_candidate_ids and selected_first_image_id.
* service_before_output_ns and explicit independent-implementation declarations.

It creates no native state/evaluation digest, safety certificate, workload
measurement, image verification, compilation or production activation.

## Independently implemented calculation

For Q = 2^32, multiply(a,b) computes a*b with an i128 intermediate and divides
its signed magnitude by Q, rounding to nearest with halfway values rounded to an
even integer. No floating point is used.

Dynamic preference updates use registered eta = Q/4. Each update is

    next[k] = current[k] + multiply(target[k] - current[k], eta)

All initial/target weights are in [-Q,Q]. Convex damping needs no projection;
any out-of-range result is refused. The stopping residual is the maximum
absolute coordinate difference and must be at most 4096 raw units, including
the initial zero-iteration case. At most 64 iterations are allowed. Fixed
preference retains the current ordinary weights and performs no update.

For every supplied phase:

    instant = sum(multiply(weight[k], component[k])) - phase_cost

For every full image path, backward recursion is:

    U[H] = registered_terminal_utility
    U[t] = instant[t] + multiply(discount[t], U[t+1])

Instant and recursively computed utilities must remain within
[-1000000*Q,1000000*Q]. Overflow and any need for clipping are refused.

Exactly three distinct image recipes (native adapter slots O2/O3/Os), all
3^H paths for H in [1,4], and one zero-effect search abstain are required. The
experiment explicitly maps O2 to the original per-translation-unit flag recipe;
it must not claim that every function of that image is optimized with O2.
Original/O3/Os images each have an independent complete HIA import and rebuild,
including their own generated kallsyms/compressed assembly data.

A candidate is feasible only if it is verified and within the registered
resource budget and risk ceiling. Uncertainty is preserved and bounded, as in
the registered scalar NDU objective; it is not silently added as a different
penalty. The frontier consists of every feasible candidate with the exact
maximum U[0], with zero tolerance. A first image is selected only if the entire
frontier excludes abstain and shares that image. Otherwise the driver retains
the registered baseline image and still executes the mandatory guest task.
Search abstention never skips work.

## Qualification and limits

The independent Python harness replays every preference step, weighted term,
recursive value, hard gate, frontier and selected first image. It also executes
the unchanged frozen native NDU binary as an external test reference, carrying
native and ordinary state independently. Production control has no such call.

Fixtures cover all four horizons, dynamic preference reversal, signed/halfway
rounding, zero/one discounts, residual-boundary stopping, multiple optimal paths,
abstention, resource/risk/verification exclusion, strict malformed/unknown field
refusals, frame bounds and stream recovery. Every fixture is explicitly
synthetic. Raw requests, stdout, stderr, actual wall/service durations and binary
identities are retained.

A measured comparison must separately charge full kernel builds, calibration,
planner preparation and actual planning. Stock and the static HIA baseline do
not incur unnecessary search costs. Report same-objective arithmetic parity
separately from overhead or correctness differences, and use held-out workload
observations only after actions are frozen. Do not infer framework superiority
from the implementation language of Python auditing or ordinary greedy/MPC
arms.
