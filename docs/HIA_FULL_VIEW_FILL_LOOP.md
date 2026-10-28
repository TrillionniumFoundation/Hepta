# Registered full-view fill loop

`hepta.hia_fill_loop_opt.rewrite_full_view_fill_loop` implements the finite
`full-view-fill-loop.v1` transformation. Primitive v1–v6 Core is admitted;
composite and v7 input is rejected. A v1 input is upgraded to v2 only when a
replacement actually introduces `buffer.fill`. Existing v2–v6 versions are
preserved, and the complete result is reverified before it is returned.

## Structural contract

The loop has one non-entry header, one body, one direct preheader and an exit.
The preheader supplies a real `usize 0` constant as the initial index. The
header performs exactly `buffer.len(view)` and `compare.lt(index, length)`, then
branches to the body or exit. `view` is a carried `mutbuf`; the index is `usize`.

The body receives the same carried values in the same order. It contains
exactly a `usize 1` constant, `buffer.store(view, index, byte)` and
`int.add.checked(index, one)`, in a valid dataflow order. `byte` is a carried
`u8`. The body jumps back with every carried value unchanged except the new
index. No other block can enter the body; the header has exactly the preheader
and body as predecessors. The final index and comparison result cannot escape
on the exit edge. The length may escape and its computation is retained.

The rewrite retains the header length computation, emits `buffer.fill` using
the same view and byte, keeps the original exit arguments, and removes the
now-unreferenced body. There is no annotation that can waive these constraints.
Another view's extent, a caller-supplied bound, a nonzero start, a different
stride, a wrapping increment, an extra load/call/trap, an escaping final index
or an extra loop entrance does not match.

## Why the declared behavior is preserved

With index initially zero and unit increments while `index < length`, each
store is in range and the next index is at most length. The checked increment
therefore cannot overflow. The same view is used for the length and writes,
and its extent is unchanged. The invariant byte is written to every index
exactly once; an empty view has no writes. The original owner/loan transitions,
allocation sequence, remaining operations and exit are retained.

This is a structural argument plus executable finite controls. There is no
checked formal theorem of this optimizer, exporter, LLVM lowering or complete
language. Tests exercise normal values, resource ledgers, allocation failure,
bounds/cast traps, valid near-miss programs and independent Rust/native paths.

Instruction counts necessarily change. An execution stopped at a fixed VM
instruction budget can differ; it is not evidence of instruction-budget
equivalence. Host interruption and host allocation failures are also excluded.
The Python VM's fill implementation may use a bounded temporary pattern that
the scalar loop did not allocate. These limits are explicit false fields in
the transformation's claim record.

## NDU and measurement

The NDU adapter binds the exact baseline, pass identifier and objective. It
reproduces the candidate and rejects imported bytes that differ from that
registered result. It retains no-change if there is no rewrite, native bytes
are identical, semantic observations disagree, timing is noisy, the projected
saving does not repay the declared search cost, or actual NDU feasibility does
not admit the candidate. Models cannot substitute a claimed score for these
observations.

`examples/hia_ndu/fill_loop.json` is a finite allocation/fill/read/drop kernel.
It is a real compiled workload, but is not an independently selected industrial
hot function. The predeclared paired protocol includes allocations and cleanup
inside each native call and records the enclosing command's total wall time.
It does not establish universal Rust superiority or production net benefit.
