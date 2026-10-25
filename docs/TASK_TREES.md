# Bounded consuming task trees

The hosted Rust runtime supports an explicit parent/child lifecycle for bounded
task groups. `group_adopt(mut parent, move child)` transfers the **actual child
owner**, its worker join handles, and its existing descendants into the parent.
Every parent join operation waits for all of these workers and releases their
reservations. Sharing a budget by itself still creates no parent/child relation.

This profile has at most **256 groups and 16 levels per tree**. The root counts
as one group and one level. It uses ordinary hosted threads, mutexes, condition
variables and reference-counted metadata. It is not an async scheduler, a global
heap bound, a proof of race freedom, or a termination guarantee for arbitrary
workers. The C backend rejects this profile explicitly.

## Source API

| Operation | Result and ownership |
| --- | --- |
| `group_adopt(mut parent, move child)` | `bool`; always consumes the child, including on refusal |
| `group_tree_snapshot(read root)` | Copy `GroupTreeReport`; observes the root and adopted descendants |
| `group_tree_join(move root)` | Drains/discards all remaining messages, joins the whole tree, returns `GroupTreeReport` |
| `group_tree_cancel_and_join(move root)` | Cancels and joins the whole tree, returns `GroupTreeReport` |
| `group_cancel(mut root)` | Cancels the root and every adopted descendant; the root still needs a join |
| `group_join(move root)` | Requires the root channel to be closed and drained; drains descendants and joins the whole tree; returns the root's flat `GroupReport` |
| `group_drain_and_join(move root)` | Drains every queue and joins every worker; returns the root's flat `GroupReport` |
| `group_cancel_and_join(move root)` | Cancels and joins every worker; returns the root's flat `GroupReport` |

All consuming operations have `alloc`, `block`, `panic` and `write` effects in
the current checked runtime profile. Adoption does not itself spawn a thread.
Its failure path can block while the supplied child's cooperative workers
clean up. A `false` result must not be interpreted as returning the child owner.

Build a tree from its leaves toward its root:

```hepta
let mut root = task_group(0, 0, 1);
let mut branch = task_group(0, 0, 1);
let mut leaf = task_group(1, 8, 1);
assert(group_spawn(mut leaf, worker, move buffer(8)));
assert(group_adopt(mut branch, move leaf));
assert(group_adopt(mut root, move branch));
let report = group_tree_join(move root);
assert(report.groups == 3 && report.joined_groups == 3);
```

The child handle is no longer usable after `group_adopt`, irrespective of its
return value. It cannot be retained to start work after its parent closes.
Existing rules also reject task-group returns, task-group parameters, storage
inside aggregates, and transitive spawning from workers in this finite profile.
Self-adoption fails the native borrow check and the independent concurrent IR
checker. Cancelling a group never satisfies its join obligation.

A normally sealed child can be adopted by an open parent. A cancelling,
failing, joining, or already-parented child cannot. A sealed, cancelling, failing
or joining parent refuses new children and worker admissions. Depth, node
count, budget identity and fallible child-slot reservation are checked before
committing the parent link. Refusal leaves the parent's children and aggregate
limits unchanged, increments its refusal counter, then cancels and joins the
supplied subtree with no runtime lock held.

## Failure propagation and queue progress

Explicit parent cancellation marks every descendant cancelled, seals and closes
their channels, discards queued values, sets their cancellation flags, and wakes
blocked senders and receivers. `group_fail` propagates from any adopted node up
to the root and then down the whole tree, including siblings. The first failure
recorded at the root is sticky. Failure closes channels and preserves queued
values until an explicit receive or the final draining join, retaining the
existing flat-group failure behavior.

The adoption/failure handshake is guarded by a topology mutex. A failing node
marks itself unavailable for adoption **before** reading its weak parent link.
It does so at each ancestor. A racing adoption therefore either commits first
and becomes visible to failure propagation, or refuses the failing subtree.
It cannot create a child whose failure has already escaped propagation.

A spawn holds the group admission gate through checked budget reservation,
native thread creation, and join-handle publication or rollback. Closure cannot
miss an admitted worker between creation and publication. No topology mutex,
group state mutex, budget mutex, or wake mutex is held across `JoinHandle::join`.

Each tree shares a condition-variable wake signal. Adoption rebinds the entire
consumed subtree to the parent's signal before publishing the transfer. A join
first seals all groups. It clears the pending-wake flag, inspects **every** queue,
discards the queued values, and waits on the condition variable only if some
group is still open and no notification was retained. Producers and completion
paths set the pending flag while holding their own group state lock. The waiter
never holds the signal mutex while examining group state. This retains racing
notifications and handles spurious wakes without an idle polling loop.

Inspecting all queues matters: a worker in the first child may wait for a worker
in a later child whose queue is full. Draining one child to completion before
visiting another would itself introduce a dependency deadlock. The native
qualification includes precisely this three-level case, with dependent root and
first-child workers and a producer in the last child's descendant.

After all channels close, joins may block waiting for cooperative workers.
Taking a child owner out of its parent slot for join does **not** remove the
stable shared link. A later sibling failure can still reach that child while
the parent is waiting on its native thread. This path has a separate latch-based
native control.

The lock order is ancestor topology, descendant topology, group state, then
budget or wake signal. Upward failure discovery holds only one topology mutex
at a time and releases it before moving to its parent. The bounded depth limits
recursive runtime traversal; no unbounded recursive scheduler is introduced.

The dynamic protection has a real cost. Each group adds topology metadata and a
wake-signal allocation; each spawn takes an additional admission mutex, and
producer/completion notifications lock the tree wake signal. Adoption visits
the consumed subtree to rebind its signal, cancellation visits every affected
node, and a draining join visits at most 256 queues per wake. Those traversals
are linear in the affected node count, with recursion limited to 16 levels.
The qualification measures correctness and observed completion, not a claim of
zero overhead or a performance advantage over Rust's other concurrency APIs.

## Shared reservations and actual cleanup

Adopted groups must either all be unattached or all point to the **same explicit
reservation pool**. Configure the root and attach children before starting their
workers, using the existing budget API. Active tasks are not retroactively
charged to another pool. Attaching/configuring a group after it already owns
children is refused. Two independently configured pools with equal numerical
limits still have different identities and cannot be combined into one tree.

The pool reserves admitted worker count, submitted buffer length, configured
queue slots and requested worker stack size. Reservation release occurs after
the corresponding native handles have actually joined. Fixed queue storage is
freed before its reservation is released. Child links retained for cancellation
and reports then contain completed metadata, without live child queue storage or
worker handles. An unrelated group can share the pool; joining the tree releases
only that tree's contributions and does not cancel the unrelated group.

The native controls refuse a real child-vector allocation and a real
`pthread_create` call. They check that transferred input buffers are freed once,
failed spawn reservations roll back, refused child subtrees are joined, and a
subsequent valid adoption/spawn succeeds. The fault allocator and pthread
interposer are qualification fixtures, not production dependencies.

These reservations are not process allocation or RSS measurements. They exclude
the application's other allocations, foreign code allocations, runtime metadata,
OS stack rounding/guard pages and CPU time. Ordinary initial `Arc`/queue
allocation failure remains process-fatal in this bootstrap profile. Worker
panics use the existing `panic=abort` build and are not contained exceptions.
Cancellation cannot interrupt arbitrary foreign blocking calls or a worker that
does not cooperate.

## Reports and protocol IR

`GroupReport` remains local to the root group: its `sum`, task counts and queue
counts do not silently become subtree totals. Its failure/cancellation flags can
reflect propagated failures. `GroupTreeReport` includes `groups`, `depth`,
`adopted_groups`, `adoption_refusals`, `joined_groups`, aggregate task/input/queue
counters, `sum`, failure code and cancellation status. It cannot be constructed
in Hepta source. Aggregate counter addition is checked; task result `sum` uses
the existing wrapping `u64` rule. A live snapshot observes each group under its
own lock and is not a simultaneous global snapshot. A successful joined report
has waited for the workers in every descendant.

Concurrent IR now records `adopt(parent, child,
refusal="cancel_and_join_child_subtree")` explicitly. The independent verifier
requires both owners to be live and distinct, consumes the child, and retains
the parent's join obligation. Success transfers the child's subtree obligation
to that parent; refusal is specified to discharge it through immediate
cancellation and join. Subsequent moves preserve the remaining linear parent
owner. Every normal CFG exit still has to discharge it, and every merge/backedge
must preserve its ownership state. The new tree join modes and Copy tree report
are recognized explicitly; unknown operations fail closed.

This checks an abstract runtime contract. It does not establish source-to-IR
refinement, the truth of the runtime adoption contract, scheduling progress,
bounded budgets, cancellation termination, or whole-language soundness. Native
tests and independent IR checking are separate forms of evidence.

## Reproducible qualification

```sh
python3 tools/validate_task_tree.py --repeats 3 --output artifacts/task-tree.json
python3 -m unittest tests.test_task_trees
```

`validate_task_tree_report(report)` requires at least three repeats by default.
Each repeat executes both actual Hepta source programs and the native runtime
matrix: 128 adoption/failure races, 64 spawn/close races, four forced adoption/
failure orderings, all three legacy join modes, both failure directions,
allocation/thread refusals and recovery, topology/budget boundaries, 64 spurious
notifications, interdependent queues, and a failure during child join.
It also executes failure propagation from the deepest leaf of a 16-level tree
on a worker with the minimum supported 64 KiB stack request; this checks that
specific host execution without claiming to measure the actual OS mapping.

Four separately compiled wrong-runtime controls must also fail: orphaning a
child during join, dropping descendant cancellation, detaching a refused child,
and short-circuiting the full-tree queue visit. The last must hit its two-second
qualification timeout; the other three must produce their expected assertion
failures. Their failures and timeout partials remain in the report.

The report records raw stdout/stderr bytes, exit/timeout status, elapsed duration,
exact command lines, binary and linked-object identities, pinned rustc, native
C compiler and bundled linker identities, current compiler/source hashes, and
the complete concurrent graphs plus independent command-line replay results.
The validator re-lowers the unchanged source, rechecks the graph, verifies actual
run denominators and raw observations, and rejects inflated claims. These hashes
are evidence bindings, not signatures or a proof that an arbitrary report author
truthfully described an external process.

The qualifier explicitly selects the pinned compiler's bundled LLD through
stable linker arguments. A direct BFD link on this host pulled a libgcc
`pthread_create` wrapper that collided with the qualification interposer; the
initial failed build attempt was retained. A second attempt established that
the `linker-features` codegen switch is unstable on pinned Rust 1.90, so the final
command uses stable `-B`/`-fuse-ld=lld` linker arguments without enabling unstable
compiler features. Production runtime code contains neither linker workaround
nor interposer.
