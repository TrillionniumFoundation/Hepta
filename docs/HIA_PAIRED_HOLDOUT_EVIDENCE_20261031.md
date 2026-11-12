# HIA P5/P6 — exact paired cost evidence (research / DENY_ALL)

## Scope and dependency

This additive feature is based on the real Linux ELF observer in HIA #456
(which itself inherits the complete four-arm arithmetic gate in #455).
It does **not** change HIA Core, the independent Rust verifier, the LLVM emitter,
C/C++ migration, original NDU algorithms, artifact admission or production
execution permissions.

It addresses a concrete scientific error: a positive *aggregate* NDU saving
can be driven by one or two unusually large task wins while the same controller
loses on most registered tasks. Such a result is not evidence of robust
task-level improvement. The existing full-cost gate already refuses missing
costs, incomplete arms, wrong outputs, ABI/candidate-bank mismatches, unknown
costs, and violations of absolute, relative, RSS and p99 thresholds. This
supplement neither bypasses nor weakens that gate.

## Protocol and exact arithmetic

Input is the existing strict `hepta.hia.full-cost-comparison.v1` immutable
JSON wire (at most 256 KiB). `assess_paired_holdout(raw)` first calls the
original `assess_full_cost(raw)` and refuses every original rejection.

For every registered task `i`, four comparable strategies must have a
complete result. For control `c` (baseline, fixed, DP) against NDU:

```text
cost(i, arm) = execution_ns + controller_ns + failed_attempt_ns
one_time(arm) = sum(all 11 required one_time_ns fields)
delta_scaled(i, c) =
    N * (cost(i, c) - cost(i, ndu))
    + one_time(c) - one_time(ndu)
```

`N` is the registered task count, 8–128. This models **equal allocation of
each one-time cost across registered tasks only**, not independent per-task
attribution. Multiplying by N keeps the calculation exact in integers, so
nanosecond remainders cannot change a win/loss. The sum of the N scaled
deltas is exactly N times the original total saving against that control.

A strict positive delta is one task win, negative is a loss and zero is a tie.
The number of non-tied tasks `m` is at least eight. The exact one-sided sign
tail is:

```text
P = sum(comb(m, k) for k in wins..m) / (2 ** m)
```

There are three preregistered controls. To accept *conditional task-level
support*, the result must be strictly positive against every control,
at least eight non-tied task pairs must remain in each comparison, and

```text
20 * 3 * sum(comb(m, k) for k in wins..m) <= 2 ** m
```

This is an exact, distribution-free sign-test calculation **conditional on
independent task units**, with a conservative Bonferroni familywise alpha of
0.05 across the three tested controls. The independence, held-out nature and
representativeness assumptions are NOT established by the wire. Shared trials
and control arms need no spurious assumption of arm independence. Repeated
measurements of the *same* task must not be counted as independent task units.

`paired_evidence_supported` requires **both** the original
`economic_scope_positive` and all three paired thresholds. It does not
grant production deployment, generalization, statistical confidence in
future p99, or compiler equivalence. Per-control signed task counts,
worst task regression, exact rational p and original full-cost verdict remain
in the report. No loss, tie, unknown cost or negative report is trimmed.

## Reproduce (synthetic controls)

```sh
python -B -m unittest tests.test_hia_paired_holdout -v
python -B -m unittest tests.test_hia_full_cost_gate -v
python -B tools/qualify_hia_paired_holdout.py \
  --input /path/to/four-arm-registered-comparison.json \
  --output /new/output.json --require-paired
```

Without `--require-paired`, negative economic or statistical results are
retained and the tool returns zero on a valid comparison. With this flag,
valid-but-negative evidence still publishes and returns nonzero. Malformed
or incomplete inputs refuse without publishing. Input requires a regular,
no-follow file; output is a complete fsynced temporary file atomically linked
into a previously absent final pathname, never overwritten.

Targeted regressions cover: 8/8 all-task wins; strong aggregate win with
2/8 task wins; 7/8 wins failing the three-way corrected threshold; ties
reducing effective sample size; expensive preparation overturning apparent
wins; unknown human cost; unordered observations joined by trial identity;
forged/missing control evidence; and exact 128-task integer tails. The
real native observer's ELF tests remain separately required, not replaced.

## What this does NOT prove

The source Core and native ELF may not be semantically equivalent; both
observer identity and external costs remain self-asserted. Tests currently
use synthetic costs for the paired component and real C11 echo executables
for the preceding native observer. Task independence and randomization are
not proven, and execution latency contains process launch/polling overhead.
The sign test measures a task-level *win-frequency direction*, not the mean
effect size or a future latency guarantee. Cost allocation is a declared
diagnostic convention, not a theorem about optimal amortization.

All output contains:

```text
authority: DENY_ALL
safety_certificate: false
production_activation_allowed: false
```

All P0–P7 production blockers remain **OPEN**. To close P5/P6 still requires
registered, externally verifiable **real HIA/Rust/Clang/NDU workload** results,
independent build/proof/controller/switch and human cost attribution,
matched information and search budgets, and frozen unseen holdout outcomes.
P0–P4 and P7 retain their independent semantic, resource, ABI, migration,
runtime fault-recovery and Agent qualification gates.

## Real ELF raw-receipt replay

The additive `hepta.hia_native_paired_replay.replay_native_paired(raw)`
accepts the **entire** immutable, bounded Linux observer report (up to 8 MiB),
not merely its summary. It refuses incomplete, failed or escalated-authority
reports. It replays the original complete full-cost verdict from the
embedded canonical JSON input, checks the frozen ELF digests and the charged
freezing cost, then **independently recomputes** per-trial totals, actual direct
process sample count, maximum RSS and nearest-rank p99 directly from all
interleaved `wait4` sample receipts.

The replay enforces exact registered trial/arm sets and uniform 2–128
repetitions, bound at most 4,096 direct-child samples. It refuses a
misreported sample result, stderr, exit/crash/timeout, invalid repetition,
missing/duplicated sample, uncharged ELF freeze, mutated summary, wrong
full-cost verdict or altered permission flag. The independently recomputed
summary must equal the upstream arithmetic input exactly before the paired
sign comparison is reported.

```sh
python -B -m unittest tests.test_hia_native_paired_replay -v
```

This is **structural evidence consistency, not independent metrology**.
The registered output oracle, build graph, historical one-time costs,
external work, physical hardware identity, task independence and compiler
refinement remain unverified. The real ELF regression corpus is deliberately
small C echo programs, not HIA-vs-Rust-vs-Clang-vs-original-NDU production
workloads. No real P5/P6 positive scientific result is claimed.
