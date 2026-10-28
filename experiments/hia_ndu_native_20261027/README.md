# Frozen continuation experiment

This protocol is committed before its qualification runs. It investigates one
registered fill-loop candidate and retains one old swap control. It is separate
from the historical strict Rust comparison and the 35-gate qualification.

## Fixed design

Run exactly two fill-loop searches, followed by one swap control. Each search
uses 31 paired samples, 10,000 repetitions of its complete fixed corpus per
backend/sample, alternating baseline-first and candidate-first. Each fill
corpus contains 16 rows: sizes 1, 32, 512 and 4096 crossed with byte values 0,
7, 173 and 255. Probe positions and XOR masks are fixed in the committed case
file. The swap corpus retains the existing 20 rows. Negative cases run through
semantic validation outside native timing.

The unchanged defaults require MAD at most 5%, a positive paired median saving
above three saving MADs and a 2% relative margin, a maximum 60-second search
admission cost, a two-second decision reserve, at most 16 MiB live Core byte
storage and 64 MiB native artifact size. The projected workload horizon is
100,000,000 calls. Both native sides use the same compiler and flags. Native
artifact equality forces no-change under measurement policy v2.

No samples are dropped; no failing, slow or inconclusive round is replaced.
Actual search errors and timeouts remain results. There is no repeat-until-pass
rule. Compiler optimizations are not disabled to manufacture an advantage.
Known agent-owned compilation/test workloads are stopped before these runs;
the shared container is not an exclusive or physically identified dot host.

Each search carries an additional 120-second cooperative deadline. A synchronous
context-local deadline is checked during tool polling and at qualification
phase boundaries. It does not install an asynchronous signal or interrupt
arbitrary Python code. Its exception passes through the existing subprocess
capture owner, which cleans up its own child process group and retains
available partial output. The report records the deadline mechanism and expiry,
including expiry discovered when leaving its scope. The enclosing runner does
not force-kill that owner or launch the next round after expiry, an interruption,
a missing final report, or a report that disagrees with the frozen protocol.
Such a run is an incomplete protocol, never a completed pass. Pure Python work
between checks and an unresponsive host can delay observation of expiry; this
is not a hard real-time bound. Normal compiler/native/evaluator process timeouts
remain independently bounded.

The runner checks the actual report's six objective fields, the decision reserve,
deadline metadata, sample and iteration counts, actual case inventory, calls per
sample, total timed calls and artifact-identity policy. Counts are recomputed
from the actual case files: each fill search requests 9,920,000 timed native
calls and the swap control requests 12,400,000, across both backends. A claimed
successful measurement must contain all 31 paired samples and its assessment.
The recorded protocol also contains the unchanged live-storage and artifact
limits, so a later default change cannot silently alter this experiment.

A consistent final `failed_closed_no_change` report remains an ordinary paid
attempt, with its diagnostics and partial observations retained, and the runner
continues the precommitted sequence. That attempt is never counted as a
successful completed measurement: the protocol summary's `ok` remains false.
Attempt completion, measurement completion and protocol consistency are recorded
separately. Deadline expiry and incomplete or inconsistent reports stop the
sequence even if a producer otherwise claims success or supplies a zero exit
code. No replacement round is launched.

The driver checks each native case result and times the actual allocate,
exclusive-borrow, fill/read and cleanup function. The enclosing runner also
records the complete CLI wall time and child CPU usage. Those costs do not
include creating the optimizer, model inference, toolchain installation,
building the NDU evaluator, energy, or long-term maintenance.

This kernel was constructed to exercise the registered rule. It is not a
randomly selected or independently profiled industrial hot function. A passing
run is scoped candidate evidence, not P4 completion, a universal Rust comparison,
formal safety, a global optimum or production activation.

## Reproduction

After committing the complete implementation and protocol, run with the native
Linux Python and an already built, pinned NDU bridge:

```sh
/usr/bin/python3 experiments/hia_ndu_native_20261027/run_frozen.py \
  --clang /absolute/path/to/clang-20 \
  --bridge /absolute/path/to/hia-ndu-bridge \
  --bridge-sha256 ACTUAL_EXECUTABLE_SHA256 \
  --output-directory /new/path/outside/the/checkout
```

The runner refuses a dirty Git worktree, creates a new output directory, records
all tracked source hashes and tool identities before/after, saves the fixed
commands before execution, retains individual stdout/stderr and reports, and
records the final source equality separately from each search decision. It
does not wait for remote CI or activate selected code.

The independent Rust/Python ledger controls and actual native lifecycle tests
run separately against the same frozen source before this timing window. They
are not injected into the measured CLI or relabelled as a third timed backend.
