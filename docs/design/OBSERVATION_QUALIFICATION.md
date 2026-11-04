# Sequential observation qualification: executable limits

## Scope and decision

This is a **test/documentation-only** addition to PR #638, commit
`527ce81e87343ab8939d7c7f9807aa9fad4f5559`, tree
`52af4adffee0b89bdb3c60d2d1c8fdbe7efc2e59`. All inherited files remain frozen.
No runtime, default route, CLI/schema, native authority, overlay, or deployment
change is made. No additional production read or repeated-validation feature is
introduced. The new package contains only test fixtures, counterexamples and a
test gate. Existing profiles do not import it.

Keep `post_analysis_observed`, `atomic_snapshot=false`, and
`native_qualified=false`. These fields describe **completed sequential
observations**, not convergence, stability, a fixed point, a joint snapshot,
linearizability or current-at-return validity. A checker report and completed
observations remain separate dimensions: observation does not erase diagnostics.

## What is observed

The current locked frontend loads detached private authority A, analyzes its
materialized inputs, then performs L followed by G. L checks the admitted lock
path, reads a bounded byte stream, parses bounded JSON, and compares it with
A.package_state. The existing equality is Python parsed-JSON equality, not raw
bytes, inode identity, or a new typed canonical-JSON relation. Equivalent
reserialization remains allowed.

G is the existing graph revalidation against A with original operations:
lexical binding resolution, sequential source-byte comparisons, and sequential
package reconstruction. It is neither a transaction nor an atomic graph read.
The final callback-free guards reduce caller-triggered races but do not exclude
other writers. The accepted stream may itself combine chunks from different
file states. Even “each complete file was valid at a read instant” overstates
the evidence. Read agreement and digests do not establish an instant-state
snapshot.

The safe interpretation is: the post-analysis lock-stream comparison and graph
traversal completed against the originally captured private authority without
an observed mismatch or terminal failure. It does not say the filesystem stayed
unchanged, that those inputs coexisted, or that they are valid now.

## Reproducible counterexamples

From the checkout root:

```
python -B -m experiments.observation_qualification.reproduce --rounds 8
python -B -m unittest experiments.observation_qualification.test_evidence experiments.observation_qualification.test_review_regressions -v
```

These fixtures mutate only temporary real files using supported checkpoints.
No parser, reader, graph-validation function, counter, guard, or authority is
replaced. Stack inspection in the scheduling helper recognizes inherited graph
traversal solely to choose when an adversarial writer acts. This is test
instrumentation, not a proposed runtime dependency.

1. **Current route residual:** During G, a checkpoint writes a malformed lock.
   The actual FrontendRequest still returns an accepted checker report and
   `post_analysis_observed`; an independent fresh locked load rejects
   `E_LOCK_INVALID`. This is expected residual behavior, not a test to “fix” by
   overstating or silently changing the observation contract.
2. **Eight identical successful rounds without a joint good state:** Initial
   load occurs before the adversarial window. Begin that window with lock good
   and source bad. During L retain that state; before G, make lock bad *before*
   restoring source. Before the next L, make source bad *before* restoring lock.
   Every transition passes through both bad. The other input remains bad even
   during partial writes. The actual same-owner revalidation returns True eight
   times against the same A; no joint good lock/source state occurs in this
   window. Existing counters are cumulative, never reset. Eight is a harness
   bound (allowed 1..8), not a convergence threshold or runtime option.
3. **Final lock bracket is not uniformly stronger:** After successful L-G
   rounds, a test-only extra L uses the original admitted operations, context
   and authority. Its callbacks make the graph bad before restoring the lock.
   Lock semantic equality succeeds while the graph is changed. This hypothetical
   tail is not part of the implemented adapter or a proposed owned lifecycle.
4. **Real torn stream:** The existing inherited Reader, using its supported
   four-byte chunk limit, reads the first chunk from `AAAAXXXX`. A checkpoint
   changes the same open file in place through `ZZZZXXXX` to `ZZZZBBBB` before
   the second chunk. The returned stream is `AAAABBBB`, which never existed as
   a complete file during this read. One half stays wrong during each write;
   the intermediate state is explicitly checked. Real `os.read` and real file
   descriptors are used. The digest control demonstrates that hashing the
   stream does not repair this temporal limitation. This isolates the reader
   property; it does not claim a new full frontend torn-source scenario. The
   four-byte setting belongs only to this reader fixture; the existing frontend
   retains its unchanged 64 KiB reader chunk configuration.

## Why finite repetition cannot certify convergence

For independently mutable objects and any finite sequential scheme, an
adversary can change an object after its last observation while allowing later
observations to agree. Adding a last guard moves that gap. The alternating
schedule additionally shows all observed values can agree without ever
coexisting. Requiring any finite number of identical outcomes, signatures or
digests does not distinguish that schedule from quiescence. ABA and graph-internal
sequential reads have the same limit. Eventual quiescence is an external
assumption, not a fact derived from equal samples.

An immutable coherent snapshot could support “validated this snapshot”, a
separate future design. Current-at-return validity additionally needs an
appropriate exclusion/version protocol covering all writers and the defined
boundary. Advisory locks ignored by other writers, unchanged metadata and watch
events do not supply that authority here.

## Optional future work is not implemented

A separately authorized fixed additional L-G pass could detect a persistent lock
edit during the first G while preserving graph-last ordering. It would still
admit alternating and final-G races. It is not necessary to support today's
literal non-atomic contract. A terminal L trades away protection against graph
mutation during that read; it must not be described as universally stronger.

Any future pass must use the original detached A, owner, exact handle,
operations, context, role caps and cumulative budgets. Stop on the first failure;
never retry away a mismatch, rebase authority, reopen a terminal context, reset
quotas or return an earlier successful pass after failure. Preserve first-origin
exception identity and precedence, cancellation, reentrancy/thread guards,
checker rejection and conservative serializer completion. A finite pass count is
not a hard runtime bound. That work requires separate design, tests and authority.

## Gate and provenance

The additive workflow checks the exact candidate head and exact #638 baseline
commit/tree, then uses Git alternate objects for a full tracked-source diff
excluding only this package, this document, and this workflow. It retains the
99 lexer/parser, 80 graph, and 813 prior-profile differential comparisons.

The aggregate gate contains all 881 inherited controls plus 11 new controls
(9 author and 2 independent): **892 hosted**, or **760 local** without the 132
consumer controls. Duplicate identities, count mismatch, skips, expected
failures, unexpected successes or ordinary failures are fatal. The hosted
workflow runs this gate twice on each of Python 3.11 and 3.12. Workflow intent is
not a claim that those hosted runs have already passed for a new commit.

```
python -B -m experiments.observation_qualification.gate
python -B -m experiments.observation_qualification.gate --include-consumers
```

Independent review of the preceding design approved this precise observation-only
contract and rejected convergence claims. This change preserves its key
counterexamples as repeatable repository evidence. New publication evidence and
any review findings must be reported separately for the exact candidate commit.
