# Finite chain flow and allocator-failure qualification

The four allocator runs recorded below belong to the exact `233bf7bc...` and
`90ca756f...` compiler images, before the independent high-SSA block-parameter
review found a separate compiler rejection defect. Their original outcomes
remain finite allocator observations and are retained unchanged in the archive.
The later parameter fix requires its own fresh complete qualification, including
the allocator cases on its new B3/M3 images. The word "final" in the historical
run names below identifies that allocator study's frozen runs; it does not
qualify the later integrated source or the entire pre-fix compiler profile.

The v13 witness set exercises dynamic `chain` ownership across control flow,
calls, moves and head loans. A separate native witness makes one ordinary
allocator call return `NULL` and records every successful allocation and
non-null free. These are finite compiler and runtime observations under the
declared ELF/libc profile. They do not prove whole-language soundness, general
machine refinement, arbitrary ELF loading, or economic value.

## Source interfaces and scope

- `tools/hia_selfhost_chain_flow_cases.py::cases()`: 13 ordinary Core inputs.
- `refusals()`: 75 inputs, including 19 general-Core-valid inputs outside
  the successor profile and 56 canonically invalid inputs.
- `profile_refusal_ids()`: the exact 19 names for which the general Core
  checker must accept while the bounded successor must refuse.
- `allocation_failure_cases()`: six explicit allocation-failure inputs.
- `tools/qualify_hia_selfhost_chain_flow.py::qualify(directory, compiler)`:
  these six inputs plus one 5,000-node destruction control, each checked by
  the Core VM, the supplied native successor compiler and the independent
  direct machine backend.

The ordinary flow/refusal fixtures are aggregated by
`tools/qualify_hia_selfhost_chain_elf.py`. The allocator qualifier has its own
scope and report; running it alone does not claim that all flow refusals ran.
Both qualifiers accept the fixed three-buffer entry ABI, an empty input,
eight output bytes initially `a5`, and an empty workspace for the compiled
test program. Each native successor compiles the actual HIA input into its
own ELF object bytes and allocator relocation records.

The positive flow set includes empty/nonempty pop, all three push/pop results,
four owner moves, shared sibling head loans, a nested head loan transferred
through permuted block parameters, a live head loan around a loop, an owner
created in a later source block, both arms of a fresh-chain join, two-level
calls, two distinct chains passed in reversed order, self-tail calls, and the
highest admitted SSA result numbers.

The refusal set checks consumed inputs, duplicate owner transfers, missing
loan graph parents/children, incompatible incoming loan parents, consuming
operations with a live head or payload loan, head-loan alias conflicts,
chain values used as ordinary byte owners/views, exact opcode arguments,
result arity/types, unexpected attributes and duplicate outputs. Out-of-range
SSA values, flat-profile chain parameters even in dormant functions, and a
general-Core-valid multi-result call remain explicit profile exclusions.
They are not mislabeled as invalid Core.

## Explicit failure inputs

The failure index counts actual nonempty allocator attempts. The VM's
`allocation_fail_at` is passed explicitly with ample fixed step/heap budgets;
an evaluator budget stop cannot satisfy an expected allocation failure.

| Input | Selected attempt | Expected attempts | Successful allocations / frees | Observable requirement |
|---|---:|---:|---:|---|
| Empty chain, nonempty payload, node failure then retry | 2 | 3 | 2 / 2 | Failed push returns the original payload and empty chain; retry/pop succeeds. |
| Existing chain, new payload, node failure then retry | 4 | 5 | 4 / 4 | Both the old head and new payload survive the failed push; retry preserves the tail. |
| Empty chain, zero-byte payload, node failure then retry | 1 | 2 | 1 / 1 | Zero-byte payload creation makes no allocator call; the empty payload remains transferable. |
| Optional payload failure followed by successful push | 1 | 2 | 1 / 1 | Failed `buffer.try_new` returns an empty owner and false; it can be pushed and popped. |
| Required payload failure | 1 | 1 | 0 / 0 | The specified allocation trap occurs. |
| Required payload failure after a prior output write | 1 | 1 | 0 / 0 | The allocation trap retains the already performed write. |
| 5,000-node ordinary destruction control | None | 10,000 | 10,000 / 10,000 | Iterative chain drop releases every payload and node; no live allocation remains. |

For each nontrapping input, returned scalar flags, output bytes, all ownership
results, and live-state conservation are checked. For trapping inputs, the HIA
successor uses its specified `UD2` path and the direct reference uses its abort
path; the child termination codes and retained output/counters are checked
separately. The witness does not intercept signals or claim automatic cleanup
after a trap.

## Native allocator witness

`tools/hia_selfhost_chain_allocator_witness.c` is compiled as one small host C
object and linked into each explicitly named test program with ordinary
`ld --wrap=calloc --wrap=malloc --wrap=free`. It calls real libc for successful
allocations and valid frees. Exactly the selected allocation attempt returns
`NULL`; no global interposition, service installation or host configuration
change is involved.

The successor uses `calloc` for node storage. The independent direct backend
uses `malloc` for node storage. The qualifier checks that each node-failure
case actually reaches the appropriate allocator. It does not accept a failure
receipt from an unused wrapper.

The shared observation records contain logical allocation identities instead
of pointer addresses, allocation sizes, the selected failure and matched frees.
An independent Python pass replays the event records and checks them against
the counters. Duplicate/unmatched frees, an unexpected libc failure, a zero-size
allocator call, or exhausted tracking/event capacity make qualification fail.
There are 16,384 live tracking slots and 32,768 event slots; the 5,000-node
control uses 10,000 live allocations and 20,000 allocation/free events.

Normal return requires zero native live allocations and bytes. The separate
Core VM observation additionally requires no live owned capabilities, chains,
or local loans. A zero-byte logical owner is not counted as a physical heap
allocation. The event `frees` counter counts successful non-null releases,
rather than logical owner-drop operations.

The disposable child imports no HIA compiler modules. It uses the ordinary
system linker/loader for these own fixtures, fixed resource limits, and shared
output/counter files so an expected trap leaves inspectable observations.
This work neither changes the production loader nor exercises hostile loader
inputs.

## Local results and retained history

Two compiler identities were independently checked:

| Compiler | SHA256 | Final cases | Final native invocations | Recorded qualifier interval |
|---|---|---:|---:|---:|
| B3 | `233bf7bcdde5102beba1791c2922f1b8a994c0ccb3a2e83f2bcbc9bb0c802a1e` | 7 / 7 | 14 / 14 | 1.506900284 s |
| M3 | `90ca756f9697b5e37514377ce5e7436f18e6be24846002a6f24acc79583a39cb` | 7 / 7 | 14 / 14 | 1.487355460 s |

The same fixed allocator inputs also passed one development run for each
compiler. All four runs are retained, including deliberate trap terminations,
their exact inputs, objects, linked libraries, requests, stdout/stderr, compiler
receipts, source snapshots and raw allocation/free event files. There was no
failed qualification run or retry hidden by this result. Development runs are
not substituted for final-source results.

Final runs snapshot 13 named source files before the recorded qualification
interval and verify that they remain unchanged when writing the report.
The frozen source bytes are retained in each run. Earlier development sources
were separately preserved and checked against the hashes originally recorded
by their reports.

The recorded interval includes the host C witness build, successor compilation
of fixture inputs, ordinary linking, VM/direct references, and native calls.
It excludes interpreter startup, source snapshot preparation, prior
B0/B1/B2/B3 and M1/M2/M3 construction, and authoring. It is not a complete
engineering or economic cost measure. The shared host was not reserved for
performance comparison; these are correctness witnesses.

## Invocation

Run against each exact compiler in a fresh output directory:

```sh
PYTHONDONTWRITEBYTECODE=1 python -B tools/qualify_hia_selfhost_chain_flow.py \
  --compiler /absolute/path/B3.image.bin \
  --output /absolute/new/output-directory
```

The qualifier writes `qualification.json` even on a detected failure and
retains per-command logs. It refuses to reuse an existing output directory.
The complete local evidence is under
`review-evidence/hia-chain-flow-20261108-5e6c/`; `summary.json` identifies all
four runs and the content-addressed `originals.tar.xz` archive.
`originals-manifest.json` enumerates every original file by size and SHA256.

## Claims to preserve in aggregate reports

`python_parser_or_codegen_after_B0 = true` and
`host_reference_codegen_after_B0 = true`: host oracles do run after B0.
`python_parser_or_codegen_in_successor_compilation = false`: the successor
itself translates the HIA input. The C witness also makes
`external_assembler_after_B0 = true`, with scope limited to the host allocator
qualification witness; no external assembler participates in successor
compilation. Ordinary linking, libc, the operating system and hardware remain
trusted. General multi-result call/return ABI and general machine correctness
are not established by this finite suite.

