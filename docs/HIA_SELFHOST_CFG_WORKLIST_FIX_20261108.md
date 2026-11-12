# Selfhost v13 CFG worklist correction — 2026-11-08

This correction preserves the v13 input profile and public ABI. It replaces
repeated whole-module resource-graph discovery with a bounded per-function
worklist. It also includes the separately reviewed three-file runtime correction
for observing externally supplied buffer roots. The historical alloc-node
qualification for source `6e9b171d…` and its 1,131 checks remains a separate
record; those results are not reassigned to this compiler.

The frozen compiler source is
`b6062d03a72079de32b5a3ebbebb66d575297b9b89b1625f5a6b42cba9432168`.
The fresh B0 native qualification has passed all **1,183 checks**, the source
suite has passed **39 tests**, fresh cold replay has passed **10 checks** with a
second complete **1,183-check** native run, and the language matrix has passed
all **910 checks**. These are local qualification results, not a claim
that a future integration commit has passed CI, been merged or been deployed.

## Baseline and exact subject

The integration baseline is commit
`d6431f233619e1339cec5532741d9303ecfcf150`, tree
`3179505c5632492f90871628288702d2d8f88561`, whose compiler source is the alloc-node
fix `6e9b171db3b078919e3a37c40e3b097136ac3221f0e19b872da42eb765193de1`.
The baseline commit was a checkpoint; it was not evidence of successful CI or
online deployment.

PR 808 review comment 4507258706 described a legal 256-block function ordered
as `b0` through `b255`, with edges `b0 → b255 → … → b1`. The review did not supply
source bytes. The retained inputs below are explicitly independent
reconstructions of that topology, not claimed byte copies of an unavailable
attachment.

| Retained input | Bytes | SHA-256 | Original B3 / M3 observation |
|---|---:|---|---|
| Scalar result, no local loan | 6,878 | `5d26b74b3609f213e5205e22a68ad9b284ff4643fcf2fc8b60c439d85dd3b555` | Returned after 9.675 / 9.770 seconds of native execution |
| External root and local read loan transferred through every block | 15,398 | `2e42fb643c05d95ff9860d1f9d967f3214c0fa58b7266746b615b6a20f804ede` | Both children exited with `SIGKILL(-9)` under the unchanged ten-second CPU limit |

Both inputs were accepted by the independent general Core checker. The second
ends its local loan at `b1`. The original compiler images were the actual
alloc-node-fixed B3
`0c15464be69d656d825a654e45e1929fd583de7aa92ce88aba4822932462b26a`
and M3
`03898791a30b8f1c2fdd059291142bf1bb49a824d3b80befab81f850452af4f5`.
The two scalar runs did not get killed on this host. The evidence preserves that
distinction rather than converting the review's reported outcome into an
unobserved local result. The killed runs' shared output buffers remained
unchanged.

## Algorithm and resource invariants

The initial phase-zero traversal still checks the entire source in its original
order, including grammar, SSA uniqueness, instruction and Core-node limits,
signatures, and type restrictions. Each block record temporarily stores its
source token offset in the word later used for the generated machine offset.
The existing known-graph bit remains separate from the block's checked marker.

The first incoming edge that discovers a block's capability graph places that
block on the function's queue. Discovery is monotonic: a later edge must match
all sixteen packed root/parent entries and cannot replace them. The queue has
256 entries, the existing per-function block limit. It uses bytes 926480 through
928527 of the already required 1 MiB workspace. The enqueue bound is checked
before a queue write, and each function resets its queue head and tail.

At the end of the function, each queued target is checked against the current
function's actual block range before its stored offset is read. Blocks already
checked with a known incoming graph are skipped. An unchecked target is replayed
from its own offset exactly once; that replay can discover more targets.
After the queue drains, any unchecked block is unreachable and is rejected.
This handles reverse order and cycles without restarting the module parser for
each newly discovered graph. Incoming edges discovered after their target was
checked still undergo the same exact graph comparison.

Before a queued replay, the compiler clears only the SSA type entries tagged
with that block. Its ordinary `define` operation retains the original strict
duplicate-definition rejection. The initial traversal has already rejected
global SSA reuse, and the replay sees the same immutable input bytes. This
selective clear prevents capability scans from seeing definitions belonging to
future instructions in the block. Recreated parameter and instruction
definitions initialize their capabilities in execution order.

The replay saves and restores the global block, function-local block,
instruction, Core-node, relocation and external-import counts, plus the source
cursor. A repeated validation visit does not charge the original source twice.
Phase zero does not write output bytes or materialize relocations. Call-graph
edges and the shared chain-destructor demand flag remain monotonic. The
existing high-SSA error short circuits remain in place.

There is no increase in the source, output, workspace, function, block, SSA,
instruction, node, relocation, child CPU or child wall limits. The public entry
remains `f0(readbuf,mutbuf,mutbuf) -> u32`. No v14 authoring CFG compression or
multi-result ABI extension is included in this correction.

## Retained development failure

The first worklist development version kept already parsed definitions while
replaying a block. Independent reasoning identified that future instruction
capabilities could therefore appear live too early. A new **455-byte**, valid
general-Core witness reproduced an incorrect `INVALID` result on that
development image:

- Input SHA-256:
  `13346fbc7217cdce1c449a0b1d38de6f1ccfcf6eeb6db2a6cddc88365889b2fb`.
- Development compiler source:
  `603b7c6de8d3a9355eab8d6280c10ee58b30f58061e3c2c583a9dad2670bd1e9`.
- Development B3:
  `eb15a4331a31ce1c3e7accdeec302807087a7ebd17ef68c13a6e57c1de5bfa8b`.

The witness creates a second shared loan, closes both shared loans, then creates
and closes a mutable loan. Clearing the selected block's type entries before
replay corrects this behavior. The original failing input and receipt, the old
compiler bytes, the exact generator identity, and both development chains are
retained. The final compiler replays the same 455 bytes successfully. The
development failure is not attributed to the published baseline or hidden by
the final result.

## Frozen source and actual native results

The final assembly contains **85 functions, 1,498 blocks and 5,842
instructions**, with maximum SSA index **1,912**, in **442,704 bytes**. The
generator SHA-256 is
`49a52ccaa04f1bb12fd34c59077041f29e2d777dc907e18d5ac9142d11372713`.
The complete source manifest contains **250 paths** and was checked unchanged
after the main qualification.

The three integrated runtime source identities are:

| File | SHA-256 |
|---|---|
| `hepta/hia_agent_buffers.py` | `52d33e7ae3cc441233e44f20f0330e8d502b1e1f5f59606a511689cd1dd79114` |
| `hepta/hia_program_runtime.py` | `ce39be78627f253447f1d4e4b3272ba6689c594c31b22e3be204b1fcfea2ca56` |
| `hepta/hia_opcodes.py` | `114d68e72dfc3f5d8ae6dcfeb2a311be7ab1514437bd9b0be4a89bc4678e50ec` |

The new CFG suite contains twelve successful independent Core VM witnesses and
fourteen independently rejected Core inputs. It includes the unchanged review
subjects, six 256-block functions at the 1,536 total-block boundary, mutable
borrows, delayed matching and inconsistent root/parent joins, loop backedges,
owned buffers, chains, undefined or duplicate SSA, unreachable targets, and the
development failure. Both original and mutated native compilers execute the
suite, adding 52 checks. Successful compilation receipts must also report the
independently counted exact Core-node total.

| Qualification | Final observation |
|---|---|
| Source, contract, language-source, owned-flow and chain tests | 39 / 39 PASS |
| Fresh B0 main qualification | 1,183 / 1,183 PASS |
| Fresh source-only cold replay | 10 / 10 PASS; nested 1,183 / 1,183 PASS |
| Language coverage / refusal matrix | 910 / 910 PASS |
| Read-only assertions over the actual main report | 4 / 4 PASS |
| Independent narrow static worklist review | PASS; no additional native run |

The fresh main run produced:

- B1 = B2 = B3:
  `cb7cde17ace8aedce7b599c56790e816f9ccb92e3e7fe68bea8bb071c9287515`.
- M1:
  `5af46ec8c3438dc9cd1a72eb995d51793c19c788e097eef1d8176cf1f38c2dec`.
- M2 = M3:
  `0889a2bd0dd37d25dfa2be323d3e0a9d993ca3b37e56ab3c486f04b6e2639ffc`.

The cold run completed in 142.770 seconds under the original 180-second total
wall limit, with isolated Python, no inherited seed/successor artifacts, no
inherited home or Python cache, and no bytecode cache created. The language
matrix completed in 66.123 seconds. Main, cold, the cold nested run and language
qualification match all 250 source-manifest entries; every original and mutated
generation also matches across all three independent native builds.

On that fresh main run, original / mutated compiler execution took
0.118 / 0.092 seconds for the retained scalar reverse input,
0.695 / 0.706 seconds for the retained local-loan input, and
3.959 / 4.156 seconds for the 1,536-block six-function witness. All used the
unchanged ten-second CPU limit and 1 MiB compiler workspace. These observed
times establish the retained regressions on this host; they are not a general
throughput, cost or all-input termination claim.

## Scope and evidence

The qualification distinguishes successor compilation from host-side reference
checks. No Python parser/code generator or external assembler participates in
successor compilation. Independent host reference generation, ordinary ELF
linking, and compilation of the separate allocator witness remain explicitly
reported trust dependencies. The six existing provenance fields retain their
precise values and are covered by the actual report assertions.

The result remains the documented bounded v13 profile: 40 flat-output operations
and all 50 inventory operations in the explicit ELF profile. General
multi-result call/return signatures, returned resources and loans, arbitrary
Core syntax, full ISA/loading behavior, and general compiler refinement are
not established by this correction. No global safety claim or promotion of
historical independent qualification to a future root commit is made.

Evidence is stored under
`review-evidence/hia-selfhost-cfg-worklist-20261108-5e6c/`. The original review
reproductions, the development failure, the independent static review, final
source freeze, raw request/receipt/stdout/stderr/output files, and generated
images are retained separately. Archive indexes record each member's byte count
and SHA-256; every indexed file is read back before an expanded working copy is
removed. The final evidence manifest supplies each archive's actual Git blob
and digest.
