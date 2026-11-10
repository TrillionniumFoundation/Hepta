# Initialization coverage across deferred CFG frontiers

> Historical finite Core/native observations; removed harnesses are not
> delivered product entry points or current-source qualification.

This is isolated proof research on the exact candidate Core from draft #592,
source 954ee966547a233c691c27bde7d0a3b44d38edf8. It does not modify production
initialization checking or LLVM emission and does not disable zero initialization.
All observations retain DENY_ALL, with no native, quota or performance authority.

## Observed prerequisite, not a speed result

The reviewed compile-only run 41621254692 changed the empty path as intended
but changed both nonempty allocator relocations from malloc to calloc. The
existing checker accepts two complete-fill witnesses for each reference and
zero for each deferred candidate. Its reason is
`read_not_dominated_by_complete_same_root_fill`. This is a conservative proof
boundary, not evidence of an actual uninitialized read or measured slowdown.
The original compiler comparisons and VM quota counterexample remain
unchanged. No timing campaign is started here.

## Exact structural mismatch

The actual deferred linear and affine programs preserve one allocation root and
the original requested extent. Their shared prefix passes the same root through
block parameters; the observed rejection is not root ambiguity.

1. Each selected fill body has two incoming edges: its selected loop header and
   the first frontier guard. The current checker requires the body predecessor
   set to contain only the header.
2. Each selected header is entered only from its body. The current zero-index
   initialization rule expects a non-body incoming edge into the header. Here
   the initial i=0 traversal instead enters the body and stores before visiting
   the selected header for the first time.
3. Each selected read body also has an alternate second-frontier incoming edge.
   Ordinary CFG dominance therefore cannot establish that its own selected
   fill-completion block dominates every read. Any claim that this alternate
   edge is infeasible requires an actual path-condition proof, not deletion
   of an inconvenient CFG predecessor.

Relaxing the predecessor, entry-index or dominance checks alone is unsafe.
A new checker would need to recover the relevant facts from the actual verified
Core operands, operations and edges, rather than trust proposer names or a saved
report. No such production checker is implemented by this research.

## Required conditional invariant

For a dynamic allocation instance A of extent N, let k denote an established
written prefix [0,k). The useful invariant is not just that a loop exists:

- Every region entrance must establish the SAME root A and extent N, and
  0 <= k <= N. A fresh root starts with no program-written prefix (k=0), even
  though ordinary Core still initializes its bytes to zero.
- Every successful advancing step must write exactly A[k] before advancing to
  k+1, under a true k<N check. The arithmetic must not wrap on that path.
  Additional pure operations can trap; a trapped execution does not establish
  the next-state invariant or authorize later reads.
- Every backedge and phi operand must preserve root, extent and the established
  prefix. A body entrance that bypasses the header needs its own proven range
  condition and prefix, not an assumed loop invariant.
- A read of A[j] needs j<k (and ordinary Core bounds/lifetime validity). A
  complete-fill witness establishes k=N; an alternate incoming edge needs
  equivalent facts or a checked proof of infeasibility.
- Different dynamic allocations, ownership transfers, allocation failure,
  repeated allocation sites, calls, escaping buffers, ambiguous phi roots and
  unsupported control flow remain fail-closed. A static allocation name alone
  cannot transfer initialization to a later dynamic allocation instance.
- Whole-language resource and backend correctness are not implied by this
  scalar prefix argument. Costs, quota, timeouts and allocator behavior are
  separate observations; the existing 20-versus-17-step distinction remains.

## Real finite positive and negative controls

`retired harness research-initialization-writes` observes the ordinary VM without
changing its zero-initializing allocator or load/store implementation. It tracks
successful program stores by dynamic owner identity and index, and records
whether each successful load has such a prior store. Missing program writes
are counterexamples to a complete-overwrite claim, not unsafe Core reads.
The observer is a single-process research instrument, not a concurrent runtime
feature, a universal proof or an admission path.

`retired harness test-initialization-write-observer` regenerates the actual deferred
Core from the repository fixtures and asserts both hashes equal the real CI
inputs. Thirty positive cases cover both workloads, n=0/1/2/4/17, and three
seeds including uint32 max. Every observed read follows an explicit store. These bounded positive cases
exercise the production-threshold fast branch only; they do not establish the
huge-threshold slow branch or universal coverage.
It also compares ordinary VM results/resources directly with uninstrumented VM.
A separately labelled threshold=0 variant exercises small slow-clone inputs in
30 additional finite cases; it is not the original CI Core or proof of its
huge-threshold slow behavior. Allocation refusal and VM budgets retain their
ordinary outcomes.

Core-valid negative controls preserve zero initialization and demonstrate:

- Removing stores leaves every observed read dependent on initialized zeros.
- Repeatedly storing index zero does not cover later indices.
- Starting at one leaves index zero unwritten.
- Advancing by two leaves odd indices unwritten.
- Replacing the shared fill predicate skips the required writes.
- Shortening the fill extent leaves its final index unwritten.
- Stores to another owner do not cover a load from this owner.
- Replacing only a fill-extent phi operand by zero preserves CFG/root/opcodes
  but skips all required writes, demonstrating why graph coverage alone fails.

These are deliberately wrong programs whose Core typing and ownership remain
valid. Their observations show why weakening the coverage conditions is not
justified. The existing production coverage checker continues to reject them.
No target code is compiled or executed by these tests.

## Reproduce and next review boundary

Use the existing pinned solver environment; no new installation is required:

```sh
python -B -m unittest tests.test_initialization_write_observer -v
```

Before proposing any new coverage algorithm, independently review the actual
Core-to-invariant correspondence, all incoming paths and phi operands, loop
entry/backedge cases, roots, trap/failure paths and arithmetic bounds. Finite
positive observations and scalar lemmas cannot replace that bridge. A future
experiment must not force malloc, bypass calloc or alter production gates just
to obtain an attractive benchmark.

## Concrete candidate proof rule for independent review

A possible generic extension has two separate obligations. Neither is currently
used to authorize zero elision:

1. **Local completion certificates.** A counted-store loop may have seed edges
   into either its header or its body. Every external seed edge, considered
   individually, must provide index zero, the exact allocation extent and the
   same root. Direct-body seeds also need the appropriate range/bounds fact.
   Every other header/body entrance must be the verified loop edge, and the
   store at the induction index must precede its unit increment. The actual
   body phi has origins {zero, step}; requiring that entire phi to be zero is
   wrong, but accepting it merely because its set contains zero is unsound.
   Separately, the false edge of an exact unsigned `0 < N` comparison proves
   an empty interval N=0, which is trivially fully covered for that same extent.
2. **Global path coverage.** For each root and load, a set of semantically
   certified completion EDGES can cover all entry-to-load paths even when no
   single completion block dominates the load. A graph test can check that
   removing those edges from a temporary analysis graph makes the load
   unreachable. This does not delete any edge from actual Core and is sound
   only if each completion certificate is valid for the same dynamic root.

For the actual candidate names, the completion-edge set is
shared_3→shared_4, fast_0→fast_2, slow_0→slow_2 (each name has the `dg_` prefix).
The first edge is the empty-interval case; the others complete the chosen fill
loop. The second frontier is actually infeasible: reaching shared_4 from the
initial shared fill header requires NOT(0<N), while entering its read body
requires 0<N with the same N and reset zero index. These are contradictory.
Allocation failure returns separately and does not manufacture a completion.

The graph cut alone is not a semantic proof. For example, the wrong-predicate
mutant keeps the same CFG edge inventory while allowing uncovered reads.
Likewise, changing a seed, step, store index or extent can invalidate a local
certificate without changing graph connectivity. All such controls must reject
before a future checker considers zero elision. The production checker remains
unchanged, conservative and responsible for emission.

## Experimental checker implementation, not emission authority

`tools/check_initialization_frontiers.py` reverifies actual canonical Core and
uses the existing closed-profile scalar/root-origin domain. It imports neither
the deferred proposer nor the observer. It reconstructs every incoming edge
including separate branch arms from the same predecessor, checks each seed's
zero index and exact extent, same-root store, store-before-unit-step and exact
extent backedge, and constructs completion-edge certificates. For every load
it independently runs the edge-cut reachability test for that same root.
Unknown operations, ambiguous origins, repeated allocation sites, unsupported
shapes, analysis-budget exhaustion and uncovered read paths are rejected.
Source identity change or unexpected checking failure is unknown and also
never authorizes emission. A saved report is not a checker input or capability.

For a direct-body seed the implementation permits the range fact to come from
the successful ordinary checked store itself. With i=0, a normal successful
store implies 0<N; if N=0 it traps before the increment/completion path. This
uses existing Core bounds/trap semantics, not a claim about unchecked native
stores or a license to skip checks. The independent review must assess this
conditional normal-completion argument as well as header-based bounds.

The checker may return `status=checked` only as an experimental structural
finding. It ALWAYS returns `initialization_elision_authorized=false` and all
DENY_ALL/native/production/performance/quota restrictions. No code calls it
from production initialization coverage or LLVM emission. The 20-versus-17
VM quota counterexample and the actual calloc relocations remain untouched.

This implementation is not a second independent language semantics. It shares
the trusted Core verifier and existing origin-domain utilities, and its prefix
argument is not machine-checked whole-language or backend refinement. The
finite observer tests provide counterexamples and positive observations, not
proof that this Python bridge is universally correct.

## Conditional solver obligations and Python-only lane

`tools/prove_initialization_prefix_conditions.py` checks six abstract UNSAT
obligations and four SAT counterexamples with the existing Z3 4.15.4 pin and a
1-second per-obligation limit. They cover the empty prefix, successful store
extension, unsigned unit-step no-wrap, normal direct-body seed completion,
normal loop exit, and unsigned empty-extent edge. The countermodels illustrate
stride-two, nonzero seed, short extent and a different root.

These premises are MANUALLY stated scalar/array conditions. The script does
not extract them from Core, prove the Python checker correct, prove resource
semantics, or validate LLVM. `actual_core_bridge_proved=false` is permanent.
Missing/wrong-version/failed/unknown solver results cannot produce checked
status. The source hash and solver version are recorded, not represented as a
complete solver binary/OS lock. Full SMT2 is retained in the returned result
so the exact obligations can be inspected.

A permanent counterexample now changes stored byte values while preserving
complete writes: the initialization checker still returns checked while the
ordinary VM output changes. This is correct for its narrow coverage property
and explicitly demonstrates why checked is NOT output-equivalence authority.

The dedicated `hia-initialization-frontier-research.yml` job is exact-HEAD,
read-only, hosted Ubuntu, five minutes overall, and 180 seconds for tests.
It installs only the existing pinned solver profile. It runs 45 structural,
abstract-solver and ordinary-VM controls with no skips in the pinned environment;
the native test class is deliberately not selected. There is no Clang install,
target compilation/execution, benchmark, artifact upload or deployment step.
No native result is inferred from this Python-only lane. All formal performance
gates and production zero initialization remain untouched.
