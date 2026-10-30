# Fixed-polynomial parallel CRC byte proposals

This separate lane targets `checksum_byte` in the existing Filecheck application.
Filecheck is a small application written in this repository, not a migrated
third-party CRC library. The original C body, legacy CRC proposals, historical
CRC protocols, failed studies and negative results remain unchanged.

The previous stb study did not demonstrate a kernel benefit. On both retained
runs, the fixed policy selected baseline 20 times and `guard_8_10` 12 times;
the dual guard was selected for divisor eight. In the completed run, fixed
kernel time was 1,625,897,335 ns versus baseline 1,625,070,807 ns. Its lower
delivery time came from costs outside the timed kernel. Removing preparation
cost cannot turn that observation into evidence of a faster algorithm or a
profitable persistent deployment. This lane therefore changes the actual CRC
calculation instead of projecting a profitable lifetime for stb.

## Proposal and proof boundary

For a fixed polynomial `p`, let `F_p` denote exactly eight unsigned right-shift
and conditional-XOR steps. The proposal uses the binary linear relation

```
F_p(x) = (x >> 8) XOR XOR(i=0..7, bit_i(x) ? F_p(1 << i) : 0).
```

The proposer computes eight basis constants and emits independent bit tests,
constant contributions and a balanced XOR tree. It does not add tables, memory
accesses, foreign instructions, calls, or a new Core dialect. Exact equality
guards admit the IEEE or Castagnoli polynomial; every other 32-bit polynomial
uses a renamed but otherwise unchanged original eight-step body.

The original captured C-to-Core function remains the source of the existing
bounded bridge. The generator is untrusted and its basis computation does not
replace either side's original semantics in the independent validator. Every
candidate requires a fresh all-input scalar translation check, including first
trap observations, and a fresh check of the actual emitted LLVM. Unknown or
timeout does not admit a candidate. The existing finite context retains its
32-block/512-operation bounds and the stricter existing 128-operation selected-
LLVM bound, native limits, sealed byte identities, one-use
traces, cleanup obligations and reference-cache limits.

## Complete candidate pool

| Candidate | Implementation |
| --- | --- |
| `baseline` | Unchanged generic eight-step kernel |
| `ieee_guard` | Unchanged legacy constant-polynomial specialization |
| `castagnoli_guard` | Unchanged legacy constant-polynomial specialization |
| `linear_ieee` | Parallel IEEE body with original generic fallback |
| `linear_castagnoli` | Parallel Castagnoli body with original generic fallback |
| `linear_dual` | Two guards supply basis constants to one shared parallel body; one original fallback |

Fixed policies have the complete pool, including the dual candidate. A later
controller experiment may not withhold it to create an artificial advantage.
If a fixed version solves the workload, this is a candidate-generation result;
it is not evidence of incremental NDU value. An exact dynamic program is still
optimal within its supplied finite additive model. A native NDU implementation
cannot improve that same model's exact optimum.

## Correctness qualification

`tools/qualify_hia_crc_linear.py` accepts an exact clean source commit and a new
external output directory. It captures the actual two C translation units,
repeats the existing 48-case original-C/captured-VM/oracle comparison, and builds
all six images through fresh translation, emitted-LLVM and native gates. Each
image receives 64 differential cases, including both target polynomials,
arbitrary fallback polynomials and unsigned boundaries. A real owned context
then executes 18 requests and 162 byte-update calls, exercising both target
polynomials and a non-target polynomial in every image.

The output retains canonical proposals, proof receipts, actual LLVM/native
artifacts, symbol-only disassembly, raw context events, source/tool identities,
all preparation and execution costs, failures and cleanup status. The complete
300-second admission deadline includes final identity checks and the first
result write. The qualification timers are not a speed comparison.

The first real qualification on `2f7052c669353d1dd0fb3480923a63f165ae821d`
was rejected: a duplicated dual fast body had 148 operations and exceeded the
unchanged 128-operation selected-LLVM limit. The first five images had already
completed their 64 native differential cases; all acquired cost and the failed
result remain retained. The revised dual shares its pure linear structure and
passes basis constants as block arguments, reducing it to 105 operations. The
checker limit and the complete six-candidate pool are unchanged. This is a
candidate representation fix followed by fresh qualification, not an omitted
failed trial or a relaxation of admission.

Code differences, functional equivalence and successful native qualification
do not establish performance. An economic comparison needs a separate source-
frozen protocol, matched data and work, every necessary preparation and identity
cost, and the full fixed candidate pool. Neither production demand, whole-file
speedup, best-available CRC, hardware-CRC superiority, general C refinement nor
machine-code refinement is claimed by this proposal lane.

## Separate frozen economic comparison

`experiments/hia_crc_linear_20261030/PROTOCOL.json` and
`tools/qualify_hia_crc_linear_economics.py` retain the v3 input domain, seeds,
two phases, two trials, three polynomial workloads, 16 requests of 256 bytes,
and 300-second budget. The eight arms are fresh-child baseline, all six
coalesced fixed candidates, and fixed known-polynomial dispatch to the two
linear single-polynomial candidates. This gives 96 observations, 276 contexts,
1,536 delivered requests and 393,216 actual byte-update calls. The complete six
candidate pool remains the strong fixed baseline; no NDU arm is invented for
this already statically expressible task.

The cold charge is the complete observed study interval minus the sum of all
full arm intervals. Every other measured preparation, verification, lookup,
cleanup, identity and evidence cost stays charged. The dispatch cold comparison
is the minimum host time over all six fixed versions minus the maximum dispatch
host time minus this complete shared charge. The inner result requires a real
outer execution receipt before a complete-cost acceptance claim; startup,
final rewrite and shutdown are not silently zero.

Each new candidate also reports its kernel and complete-host differences from
the strongest legacy fixed controls, including all negative/fallback results.
The native kernel timer covers the driver loop, calls and rolling evidence
checksum; per-call differences are not isolated instruction latency. Positive
kernel differences can produce conditional break-even call counts using the
observed three-image preparation component or the full shared charge. Those
ratios are hypotheses about future work, not measured net profit or demand.
