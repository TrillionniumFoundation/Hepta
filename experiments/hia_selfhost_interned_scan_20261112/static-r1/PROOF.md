# Five scans bounded by the current function's interned SSA count

## Candidate and present result

This is an isolated compiler authoring candidate. It changes five scan bounds in
`tools/generate_hia_selfhost.py` from the reserved capacity, 2048, to one local
snapshot of the already maintained count at workspace word 480. The scan bodies,
visit order, early returns and failure helpers are unchanged.

The baseline is the exact generator in commit
`9704596acc4470bd0042838586602e26bac7b3d1`:
81,991 bytes, SHA-256
`d9ede90b8b1d71674bd9f3d7c992f20bd5de7caef39e447bc112eaca7be77f32`,
Git blob `08455f39278c4d428ea312137887c53d964d4466`.
The complete candidate is 82,193 bytes, SHA-256
`9337d6704e47c4257b8b3723c0676809e1ba31914d6cfa6b13e07f2789b03ec2`,
Git blob `19876107428018182d8dd0bf99eee65167489ded`.

The preexecution checkpoint is
`6ba590ab9ddb4f455b4a94b13c8165efbb414226`, tree
`7a8f49442434b03bab0b6a0ce2ceafa28c96a719`. It adds the candidate and its static
reader under an experiment prefix; no product path or profile was changed.
The prior 4,555 leaves were checked unchanged.

A single CPython 3.12.14 static run has now parsed 25 Python files, parsed the
five isolated authoring functions, compared their loop-body ASTs and reversed
the patch to recover the complete baseline byte for byte. It imported no
project module, generated no HIA, ran no Core program and executed no native
compiler or test method. The exact command, reader source, stdout, stderr and
`STATIC-OBSERVATIONS.json` are retained. These observations establish the
mechanical extent of the patch. The argument below is a source-level
invariance argument, not a completed compiler-refinement proof.

The current recovered v78 source was independently read at
`d0e110e19f9433baaf202a0f605671c7205b4cff`, tree
`6381daf9beb11d873d4608c26facc0b9e5bc747f`. Its generator and the other inspected
compiler authoring fragments equal the 970 inputs. The only two differences in
the inspected file set are the names qualification label's `-flat-build`
custody correction and its new source test. Neither changes the interner.
The historical eight-module inventory has 110 methods; the current v78
inventory has all 110 plus that one test, hence 111. Both inventories are
retained separately.

## Why this is a useful bounded change

The completed cost audit at
`7c48cac08cd31b62f26854b6ca881c853e33d9c7`
paired 4,897 native invocation records across 35 complete phases. Its comparison
binds unchanged input, compiler image, output and result observations.
The sum of native observer clock intervals increased by 46.941401849 seconds;
the parallel phase-wall sums increased by 53.280155276 seconds. These are
overlapping sums, not critical-path durations or process CPU measurements.
The same-byte reverse-1,536-block cases make the compiler's internal work a
concrete optimization target. The audit does not identify why the host serviced
the same native code at different rates.

The fixed worklist already avoids reparsing an entire module for every reverse
edge. The name interner already uses a 2,048-slot exact-name hash table. This
candidate keeps both algorithms. It removes scans of SSA slots that have never
been allocated in the current function.

For a complete scan with `N = get(w, 480)`, the changed loop visits N slots
instead of 2,048. It adds one eight-byte count read. At N = 2,048 the scan still
visits every slot; there is no promised speedup at that boundary. For R queued
replays, the clear-loop work changes from `R * 2048` visits to
`sum(N_before_each_clear)`. This is an algorithmic count, not a measured
native speedup. No runtime or cold-budget claim is made for this ungenerated
candidate.

## Source and workspace facts used by the argument

All source identities are in `INPUT-PINS.json`. The corresponding source was
read without project imports. The relevant source definitions are:

| Definition | Exact baseline location | Role |
|---|---|---|
| `compile` | generator, line 55 | Admits the existing workspace/input/output sizes and runs the existing passes |
| `parse_function` | generator, line 139 | Resets the function-local count and clears all 2,048 type/hash slots |
| `read_value_name` | names authoring fragment, line 107 | Allocates dense indices or returns an existing exact-name index |
| `expect` | generator | Routes SSA names to `read_value_name` |
| `define` | generator, line 714 | Performs the unchanged SSA/type/duplicate checks before writing a type |
| `variable` | generator, line 732 | Preserves block ownership, defined-type and live-capability checks |
| `loan_live` | generator, line 1468 | Requires matching block tag, a resource type and the live bit |
| `fail` | generator, line 1144 | Writes the first code/offset only when word 40 is zero |

The compiler still admits a workspace of at least 1 MiB before using any of
these tables. The relevant eight-byte word/table ranges are disjoint:

| Storage | Half-open byte interval | Entry layout |
|---|---|---|
| Count word | [480, 488) | Unsigned count |
| SSA table | [536576, 569344) | 2,048 entries: type, defining-block tag |
| Argument vector's first 16 words | [569344, 569472) | SSA indices |
| Capability table | [875776, 924928) | 2,048 entries: root, parent-plus-one, live |
| Replay queue | [926480, 928528) | 256 block indices |
| Exact-name hash table | [955152, 1004304) | 2,048 entries of 24 bytes |

The complete scratch layout, including the block-name table ending at 1010448,
is unchanged. `scan_limit` is an authoring local, not a new workspace field.
Its generated SSA/stack cost still requires actual generation and cap checks.

### Count initialization and monotonicity

At each `parse_function`, in every pass, the original code writes
`put(w, 480, 0)`. It then iterates over **all 2,048 slots**, clearing each
name-record length and each SSA type word. That full clear is unchanged. It
does not rely on prior workspace contents or on the previous function having
used fewer names.

Within that function, the only explicit writer to word 480 in the inspected
authoring source is the new-name branch of `read_value_name`:

1. It obtains the current count N.
2. It refuses N >= 2,048 with the existing error 37.
3. It writes the new exact-name record and assigns index N.
4. It stores N + 1 in word 480.

An existing name returns its recorded index without changing the count.
References and definitions use the same interner, so a name may be registered
before it is defined. This makes N an upper bound on allocated identities, not
a count of live capabilities or of currently defined values. Within a
function, N is monotonic and stays in [0, 2048]. The next function resets it.

The original 2,048-probe loop, `slot = (slot + 1) & 2047`, exact-byte equality
check and N >= 2,048 refusal are all unchanged. No alternate interner, smaller
capacity, short identifier domain or special reverse-case path was added.

### Why the unused tail has no active type on an error-free path

After the full clear, all type words are zero. The only nonzero type writer is
`define(w, v, t)`; it retains its v >= 2,048, type-range and duplicate checks.

The inspected definition callers are `parse_params`, `instruction`,
`call_results` and `owned_define_outputs`. The value index comes from
`expect(..., 256)` through the exact-name interner, directly or through the
existing output staging words. Thus, while the first-error word is zero,
every successful definition has an index below the current N. A forward
reference can enlarge N but does not create a nonzero type by itself.

Consequently, at an error-free scan entry:

- Every index i in [N, 2048) has type zero.
- Its block tag and capability words may retain old bytes; the argument does
  not assume those words were cleared.
- `loan_live(w, i)` is false because `resource_type(0)` is false, even if a
  stale tag or live bit happens to match.
- The graph clear's possible store of zero to that type word is idempotent.

The graph clear only writes zero types. It cannot create a type outside the
dense prefix. The full per-function clear, name capacity checks and all
definition callers remain present.

## Loop-by-loop read, write and count-stability review

The following table covers the changed **inner loop**. Code around that loop
is unchanged. All retained indices are visited in their original increasing
order, so the first violating active slot has the same priority.

| Loop | Reads reachable from the loop body | Writes/early return | Why N cannot change inside this loop |
|---|---|---|---|
| `check_graph` | Defining-block tag at VBASE + 16*i + 8; local bid | If tag matches, type at VBASE + 16*i := 0; local i increments | Body calls only `get` and `put`; the only store is in the SSA table, disjoint from word 480 |
| `loan_access` | Current block word 88, SSA tag/type, capability live and parent | Matching live child returns `fail(62)`; otherwise local i increments | `loan_live` and `get` only read; `fail` can write 40/104, never 480 |
| `loan_borrow` | Same live predicate; capability root; the existing parent chain; type for the mutable-loan rule | Same error 62 or local increments | `loan_ancestor` only follows existing parent words with its original 2,048 depth bound; none of these helpers registers a name |
| `loan_transfer` | Active-loan/owner counters 280/352; live predicate; capability parent; SSA owner type; original n argument slots | `loan_argument` may call `fail(62)`; no graph/capability stores occur inside this first scan | Helpers read existing argument/capability/type words and possibly 40/104; interning is absent |
| `owner_free` | Local owner index v; live predicate; capability root | Same error 62 or local increments | The body only reads and calls the sticky error helper |

The count read occurs after each existing early-return guard:

- `loan_access` and `loan_borrow` still return before scanning when either
  word 264 or 280 is zero.
- `loan_borrow` retains its existing root read before the new count read.
- `loan_transfer` still returns when word 264 is zero. Its original
  `(get(w, 280) != 0 or get(w, 352) != 0)` condition stays in the same
  short-circuit position after the index bound.
- `owner_free` retains the original `owner_type(variable(w, v))` check,
  including any first error it produces, before the existing word-264 guard.

The graph loop initializes the new local to zero before the outer worklist.
It refreshes the local **inside each unchecked-block branch**, immediately
before the inner clear. It does not cache N across `parse_block`, across
queue iterations, across functions or across passes. Although unchanged
replay input normally has already registered its names, the proof does not
need a count snapshot to survive a parser call.

The queue bounds, target-range checks, per-function block count, global
instruction/node/relocation/import counters, cursor restoration and final
unreachable-block check are byte-identical. In particular, this patch keeps
the original protection against a future instruction's stale capability
during replay.

## Error paths and first-error ordering

The error-free invariant must not be applied to every intermediate error
state. A malformed name can make `read_value_name` return zero after setting
word 40, and a parser path can still reach `define(w, 0, t)\). A sentinel
2,048 from an absent output is rejected by the unchanged definition guard.
It is therefore incorrect to claim that every nonzero type is below N
without also describing the first-error state.

The graph clear is entered only while word 40 is zero. Its body contains no
error-producing operation or name registration, so the error-free tail
argument applies to that entire clear.

For the other four scans, consider both cases:

1. **Word 40 is zero at entry.** The unused tail has type zero. None of its
   predicates can identify a live capability, so no omitted iteration can
   create the first error. A violation among [0, N) is examined at exactly the
   same index and returns the same error. The earliest code/offset is
   preserved.
2. **Word 40 is already nonzero.** The omitted scan work consists of reads,
   local iteration and calls to the sticky `fail`. Its code and offset
   writes are disabled. No omitted loop body updates a live bit, root, parent,
   argument slot, graph row, queue or count. The three immediate-return
   helpers return zero in either path. `loan_transfer` continues into the
   same later packing/graph code with the same workspace and original
   code/offset; its remaining writes are not removed.

The actual malformed-index boundary was inspected rather than assuming
arbitrary invalid indices are harmless. A failed SSA-name read returns zero.
When N is nonzero, zero remains inside the retained prefix. When N is zero,
an out-of-prefix definition can affect slot zero, and that definition
initializes its resource record if it is a resource. An ancestor test on this
same zero argument finds the candidate immediately. The definition guard
prevents a sentinel 2,048 type write. Successful input retains the original
bounded argument and parent invariants; reads performed for retained prefix
indices are unchanged.

This is a reachable-state argument for the existing compiler entry and its
borrowed-buffer semantics. It adds no support claim for arbitrary calls to
private helper functions with invented workspace tables, or for concurrent
foreign memory mutation. It does not delete an input or weaken an existing
entry check. The original malformed, undefined, duplicate, wrong-type and
resource-refusal suites are explicitly required by the validation plan.

## Bounds that stay intact

The exact inverse-byte comparison proves that every source byte outside the
five controlled functions is unchanged. Each old loop body also has an equal
AST after isolating its predicate. The following protections are specifically
checked or pinned:

- 2,048-entry full type/hash clearing at every function entry.
- 2,048 allocated SSA identities, 2,048 name probes and the hash-table mask.
- Definition and variable-index guards at 2,048.
- The ancestor traversal's 2,048 depth cap.
- 256 blocks and queue entries per function; 1,536 blocks in total.
- 128 functions, 8,192 instructions, 262,144 Core nodes and 12,000 relocation
  slots, including the existing derived relocation bound.
- Sixteen parameters/arguments and the packed root/parent checks.
- Existing 1 MiB input/output admission and required workspace.
- Original ten-second child CPU limit and twenty-second child wall limit.
- Cold qualification's 180 seconds, cleanup's three seconds, two fresh oracle
  workers and all 38 phases.
- The separate three/five-second caller budgets and full retained/controller
  limits of 5,400/10,800 seconds.

No profile identifier, contract, coverage file, generated HIA assembly,
observer protocol, archive scheme, case list or test assertion is changed by
this static checkpoint.

## What remains to be demonstrated

The next source-controlled operation must generate the actual candidate HIA
with the unchanged authoring entry point, validate and round-trip it through
the original Core checker, and measure every original per-function and
whole-program cap. The new local can change generated SSA/block parameters;
the static source argument does not certify those generated counts.

The original source tests and whole relevant native suites must then execute
under their existing guards, with every fixed ID and subcase retained. The
candidate must create its own fresh B0/B1/B2/B3 and M1/M2/M3 evidence. Earlier
970, bde or v78 passes cannot qualify it. Baseline and candidate measurements
must retain all samples, complete outputs, first-error code/offset, untouched
output on refusal, and original CPU/wall limits. No test can replace the
complete 38-phase cold run or the separately required full retained gate.

`VALIDATION-PLAN.json` identifies the original method inventories, historical
reverse witnesses, fresh generation chain and evidence requirements. It is an
unexecuted checklist, not a launch request. The profile, final integrated
source/tree, runtime, new evidence root and unique request are intentionally
not assigned here. Root owns those integration choices.

## Evidence references

- `INPUT-PINS.json`: exact 970 source closure inspected for this argument.
- `EXACT-DIFF.patch`: actual unified diff from the pinned complete sources.
- `static_scan_check.py` and `STATIC-OBSERVATIONS.json`: actual Python AST and
  inverse-byte check; no product execution.
- `ORIGINAL-TEST-INVENTORY.json`: all 110 historical methods.
- `CURRENT-V78-READBACK.json`: exact current source comparison and all 111
  current methods, including the names custody regression.
- `INDEPENDENT-REVIEW.json`: peer's narrow static review of the same baseline
  and candidate, separately scoped from generation and native correctness.
- Cost evidence:
  `7c48cac08cd31b62f26854b6ca881c853e33d9c7`,
  `experiments/hia_970_ci_original_custody_20261112/cold-cost-comparison-r1/`.
