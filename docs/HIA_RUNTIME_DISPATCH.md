# HIA interpreter dispatch preparation

The canonical HIA interpreter previously constructed a six-element string set
at every non-constant instruction to recognize checked and wrapping integer
addition, subtraction and multiplication. This change creates the same fixed
set once as a `frozenset`. Every call still re-verifies the supplied program;
opcode/version admission, arithmetic, trap order, VM fuel, ownership, loans,
allocation and execution receipts are unchanged. No verification cache or
trusted producer receipt is introduced.

## Observed wall time

After a five-pair exploratory pilot, the final four cases, eleven paired rounds,
two warmups per arm and alternating arm/case order were registered in
`benchmarks/hia_runtime_dispatch/PROTOCOL.json` before the retained run.
The complete original runtime from #564 commit
`ab1c1a50b77a0d9f2da14a86b418f60985fbfe28` is retained and SHA-256 checked.
Both arms use the same canonical Core bytes and unchanged current verifier.

The timer includes the entire `execute_program` call: mandatory admission,
interpretation and report generation. Loading input bytes and importing the
implementations are outside the timer. Every invocation must produce exactly
the same complete report, including scalar result, step count and resource
ledger. No samples are trimmed or pooled across workloads.

Observed Linux x86-64, CPython 3.12.14 medians in milliseconds:

| Fixed case | Original | Candidate | Reduction |
| --- | ---: | ---: | ---: |
| 10,000-iteration scalar loop | 132.560 | 107.919 | 18.59% |
| Same loop through a Core call | 128.532 | 100.838 | 21.55% |
| 1,000-iteration borrowed-memory loop | 61.275 | 50.250 | 17.99% |
| Empty-loop admission control | 25.161 | 25.754 | -2.36% |

All 88 timed observations and four complete reports are retained under
`evidence/hia_runtime_dispatch/registered/`, together with the exact protocol,
Core bytes, implementation hashes and machine/Python description. The empty
control's regression is retained: there is no claim that every input improves.
These shared-cloud wall-clock observations are not isolated CPU-cycle data or
a future speed guarantee. They do not establish faster native machine code,
compiler emission, NDU full-lifecycle value or Agent productivity.

An independent repeat of the same registered 88-observation protocol is
retained separately in `evidence/hia_runtime_dispatch/independent-review/`.
It observed 19.54%, 12.70% and 21.52% median reductions for the scalar, call and
borrowed-memory cases respectively; the empty control changed by +0.015%.
Complete reports again matched. Neither repeat replaces the other, and the
first run's empty-control slowdown remains part of the result.

## Reproduce and correctness controls

```sh
python tools/measure_hia_runtime_dispatch.py --output /new/runtime-dispatch-run
python -m unittest tests.test_hia_runtime_dispatch tests.test_hia_program -v
```

The output directory must be new. The retained source is a measurement baseline,
not an alternate production runtime. The independent arithmetic matrix covers
all six operations, all ten integer types, boundary inputs, wrapping outputs,
checked overflow and exact execution-step counts. Both complete composition
and no-skip native regression gates explicitly include the new controls.
Existing resource, returned-loan, recursive-chain, bulk-operation and evaluator
budget tests continue to check the surrounding semantics.

This is a scoped Python implementation optimization. Full language soundness,
native refinement and P0–P7 qualification remain open; `DENY_ALL` remains.
