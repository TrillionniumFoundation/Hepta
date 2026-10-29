# Selected safety checks on the unified next source

The executions recorded here used clean local commit
`ccd423bc9ee22888fec5d23f993978f2c0f51b57`, tree
`26695834a49be88dae42a41a2954954f721c7066`.
Public PR #360 source `e629d92d82752244edf11c3ae5a0c477a64e9252`
has that exact tree. The two commit identities remain distinct: these local
executions are not relabelled as executions under the public commit name.

## Results

| Check | Observed outcome |
| --- | --- |
| Fixed scalar lowering matrix | 449 / 449 verified; zero unknown, zero refuted positive obligations |
| Actual-LLVM mutation controls | Four refuted with counterexamples; unreviewed `nsw` refused by the closed parser |
| Related regression methods | 61 / 61 passed; zero skips |
| Actual unsigned cursor helper | Independent arithmetic specification verified for all 192 input bits |
| Actual signed cursor helper | Independent arithmetic specification verified for all 192 input bits |
| Source stability | Recorded sources and clean local HEAD unchanged during the matrix |

The matrix took 27.910024552 seconds; the regression group took 12.813
seconds. These are operational observations on a shared execution host, not
comparative hardware performance measurements or evidence of execution on
the user's physical dot machine.

Each scalar matrix row is one concrete Core/LLVM lowering shape with an
all-input SMT obligation. The count is **not** a count of runtime input
samples and does not quantify over every program expressible in the profile.
The 61 methods overlap functionality covered elsewhere and are not added to
other regression counts as disjoint coverage.

The actual migration Core bound by both cursor reports is
`1044e28ea68a18d6a0681cff9cd5f835e26e91c9a669dab01256b9592f64ca51`.
The separate 66-bit specification requires returning the mathematical sum
`offset + index` exactly when `0 <= offset + index < extent`, and aborting
otherwise. There are no input preconditions. This covers `INT64_MIN`, large
unsigned offsets, empty extents and corrected one-past cursors. The reports
also retain the actual Core-to-emitted-LLVM obligations for those helpers.
Their math solver times were 0.524538420 and 2.449741610 seconds respectively.

## Evidence layout

`REGISTRATION.json` was written before the matrix's first observation and
contains its fixed inventory and source hashes. `obligations-*.jsonl` retain
every successful row, including Core/LLVM/query/checker/solver identities.
`QUALIFICATION.json` retains the aggregate and all five negative outcomes.
The negative LLVM and SMT inputs are in `negative_controls/`.
`CURSOR_UNSIGNED.json` and `CURSOR_SIGNED.json` retain the complete cursor SMT
queries and nested lowering results. `SOURCE.json` records the interpreter
and host scope; `TESTS.log` is the actual complete regression output.

The full matrix raw directory contains 1,827 retained files, including every
Core program, emitted LLVM body, query and per-obligation report. Its manifest
identity is in `SUMMARY.json`; every retained member hash was checked before
this compact projection was created. Full raw files accompany the overall
delivery attachment. The compact JSONL rows are unchanged result objects,
with the SMT text retained in the raw files under the recorded query hashes.

## Preserved failed attempt

The earlier source `b68f8ac2866262294f18b379282396af581bb3cc` attempted a
matrix fixture with a unit-valued native input. The existing native export
guard correctly refused it after 439 completed obligations. That attempt
did not complete qualification. `FAILED_RUN_01.json` and its original log
preserve the failure, its partial progress and exact source identity.
The later fixture constructs unit values internally. Native input eligibility
was not weakened, and the partial run does not contribute to the 449 total.

## Remaining boundaries

The Core scalar encoder, closed LLVM parser and pinned Z3 remain trusted.
The result does not prove their correspondence to the complete language or
the full LLVM specification. C ABI wrappers, LLVM optimization and final
machine code, allocator validity, pointer provenance, general concurrency,
resource cleanup and universal process-memory bounds are outside these
selected proofs. All such universal claims remain unproved. The checker
cannot publish native artifacts or import external proof receipts.
