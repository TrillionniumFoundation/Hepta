# Captured stb remainder with matched compiler policies

This is a separate locally frozen experiment. Earlier CRC, narrowed-reduction
and agent qualification outcomes retain their identities and negative results.
The workload is the unchanged, pinned `stb_divide` 0.94 `stb_mod_eucl` body;
the demand sequence is prospective research input, not a production trace.

The full component goes through the existing C capture and migration frontend.
Its conditional helper produces an actual Core call. A new, separate bounded
scalar-call validator directly encodes the original caller/callee closure and
compares it with the proposed flat Core, including the first trap code and call
position. It does not invoke the inlining producer. The legacy scalar validator
continues to reject calls. The new profile admits at most 16 functions, a total
of 32 blocks/512 operations, and 32 symbolic call expansions per side; recursion,
memory, resource effects, unknown callees and unknown SMT results do not pass.

The captured baseline has 8 blocks/13 operations after explicit i32/u32 bit
casts and checked inlining. The candidate bank contains baseline, divisor-8,
divisor-10 and combined divisor-8/10 guarded versions. All retain generic
fallback. The combined candidate has 26 blocks/43 operations, below the
unchanged execution-profile limit. Every actual bank build independently
repeats scalar equivalence, selected LLVM validation and 64 native/VM edge
controls. These checks do not prove the C frontend, whole compiler, ISA or
machine code. C denominator-zero and INT_MIN/-1 inputs remain undefined source
inputs; HIA compares its own specified traps separately.

The existing finite executor adds an explicit opt-in `map_repeat` profile.
Unlike state folding, every call receives the original full-width input and
fixed divisor. The native child really executes each repetition. Input storage
remains bounded to 65,536 u32 values, repetitions to 4,096 and actual calls to
16,777,216 per trace. The 5-second wall, 3-second CPU, 256-MiB address-space,
output, image, plan and ownership bounds remain in force. Legacy fold wire
records and default opt-in behavior are unchanged. Reference checksums use
exact modular composition, with literal-loop controls in tests; that common
reference saving is never assigned to NDU.

All four policies receive the full bank and the same complete public input and
calibration information. Fixed precommits a per-divisor dispatch table over the
whole trace, including the dual-guard candidate. Greedy updates current-request
estimates from its own completed observations. Light DP solves the next at most
three requests. The original pinned native NDU stream evaluates the identical
at-most-64 paths, then executes only the first action. No host DP supplies NDU's
answer. After policy execution, the same-model audit distinguishes choosing the
same finite optimum from an independent planning advantage.

Fifteen semantic reference entries are prewarmed under the same existing
256-entry/1-MiB limits. They contain only expected values; every plan receives a
new nonce and every native request runs. The four policies share this declared
warm cache rule. A fresh baseline-only bank and its separately built cache give
the unoptimized cold-cost control. Source, proof, compiler, reference, native,
controller, cleanup and failed-attempt costs are retained. Common costs are
charged once per standalone arm. The pinned NDU build's original actual cost
is shown separately; no new cold build is claimed.

`qualification` uses 24 actual calls per candidate. It is correctness evidence
and does not run the economic campaign. `study` freshly repeats all preparation
before the registered 24 calibration deliveries and 160 policy/control
deliveries: **3,087,007,744 actual kernel calls**. It retains failed or slow
observations, stops on an incomplete gate and never retries a sample. The
protocol allows no result-driven budget, input, candidate or arm changes.

```sh
python tools/qualify_hia_stb_ndu.py --stage qualification \
  --output /absolute/new-qualification --expected-head FULL_COMMIT \
  --clang /absolute/clang20 --identity /absolute/stream/identity.json

python tools/qualify_hia_stb_ndu.py --stage study \
  --output /absolute/new-study --expected-head FULL_COMMIT \
  --clang /absolute/clang20 --identity /absolute/stream/identity.json
```

Run the study only in the coordinated heavy-task window, with the actual Linux
PID/proc namespace required by sealed execution. Capture the whole outer
process stdout/stderr and wall time in a separate receipt. Any observed finite
cost advantage is descriptive; this host does not establish statistical,
universal, global-optimality or production-demand claims. Authority remains
`DENY_ALL`; serialized receipts cannot publish or execute another artifact.
