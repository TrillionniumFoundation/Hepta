# R10: private full-width scalar byte I/O

## Status and exact scope

This is an authored candidate, with zero generation, compiler, candidate VM,
Native or qualification executions. The actual R9 10,000,001-step failure is
unchanged. Its full actual custody belongs to Root, recipe
20fb8d2851e23f0f30577c916f270f1df10bee57.

The before generator is 59,854 bytes, Git
8dde3a64f7388f81f8996888c97d43def2b336db. Its actual assembly is 398,741 bytes,
Git 5e998dee9ed4c5b4156ba3b778b218ca1fd5992c, SHA-256
2f271037fa0adfbc1875fc7759bdf058842db57e1dee591db8e84122f8cad4e7.
Both complete before-images are preserved in this packet.

The new generator is
`overlay/tools/generate_hia_file_render_checker_word64_bytes.py`.
Its independent output path is
`examples/hia_bootstrap/file_render_checker_word64_bytes.hepta`; that candidate
asset does not yet exist. Every existing generator definition other than
`document` remains byte-for-byte. Four exact text inverse edits restore the
whole old generator, including AST. These authoring checks have actually run
using only stdlib. They have not called either generator or a Core verifier.

The new Core projector requires the exact complete rendered R9 preimage before
editing. It changes four single-block helpers and one successful block:

| Function | Role | Old selected-path ops | New authored ops |
| --- | --- | ---: | ---: |
| f22 | eight-byte write | 54 | 33 |
| f23 | eight-byte read | 51 | 39 |
| f24 | four-byte write | 26 | 17 |
| f25 | four-byte read | 23 | 19 |
| f92 b2 | successful two-byte write | 11 | 9 |

All 107 functions, 1,456 blocks, names, signatures, effects, annotations and
external f0 ABI remain. The other 102 function documents are unchanged. The
future generated op count must be 6,299, versus actual R9 6,347. Those counts
are strict generator assertions, not already-generated results. There is no
change to the public compiler, VM, buffer layout, lexer/cache policy, error
field, caller or default selection. There is no field-width, cursor-bound or
workspace-initialization assumption.

## Full-width algebra and effect proof

The fixed opcode authority defines usize as unsigned 64-bit and u8 as unsigned
8-bit. The projector rechecks those widths. Let M=2**64, x be any legal word in
[0,M), and p be any legal offset in [0,M). Every claim below is over that full
domain, not only the values observed by the Counted diagnostic.

### Writes

For byte i the original stores
`wrap_u8((x >> (8*i)) & 255)` at `(p+i) mod M`. The candidate successively uses
`y_0=x`, `y_(i+1)=y_i >> 8` and `a_0=p`, `a_(i+1)=(a_i+1) mod M`, storing
`wrap_u8(y_i)` at a_i. Unsigned shift composition and modular-add associativity
give the same value and address. Wrapping to u8 already removes every bit above
bit 7, making the preceding AND redundant for every x.

Physical stores remain individually ordered from byte 0 through width-1.
Each address increment and next right shift is emitted only inside
`if index+1 < width`, after that byte's successful store. **No address increment
or shift occurs after the last store.** The original zero return remains after
it. If any store traps, no later increment, shift or store is reached; every
previously successful store has the same address and value.

For f92 the success-block change is narrower: remove only the unique constant
255 and its unique AND feeding an existing wrap-u8 cast. Redirect that cast to
the original full word. The existing high-byte shift, stores, return, SSA names
and both preceding control-flow blocks remain otherwise unchanged.

### Reads

Each candidate still performs exactly width individual byte loads, in the same
ascending-index order at `(p+i) mod M`. The first load precedes all new address
calculations. An increment is emitted only before a subsequent load (`if
index`), so there are exactly width-1 increments and **none after the last
load**. No read is widened, omitted, cached, repeated or reordered.

Let b_i be the actual byte returned by load i. The old result is
`OR_i (b_i << (8*i))`. The new result starts at the highest loaded byte and
applies `result=(result << 8) OR b_i` for descending i. Induction gives the same
byte coefficient for every i. Four-byte results retain zero upper 32 bits;
eight-byte results cover all 64 bits. Packed intermediate values never require
more than width bytes. All new shift counts are the constant 8, strictly below
64; all old counts 8..56 were also valid. The unchanged VM checks shift counts
and wraps left-shift results, so these pure operations introduce no overflow
trap.

Only pure, non-trapping byte packing moves after the final physical load.
On a short buffer the first failed load sees the same view and address. There
are no earlier or later memory writes from the read helper, and no later load
is executed. The amount of VM fuel consumed before that access intentionally
changes; the memory semantics do not.

### f92 refusal and first-error behavior

The exact `value > 65535` branch and its f21(error69) call remain. f21 itself is
unchanged. Its real policy first loads byte 40, not a full-word error value.
When that byte is zero it writes eight error bytes at 40, reads four cursor
bytes at 24 and writes the cursor as eight bytes at 104. Nonzero byte 40 keeps
the original no-write return. The changed f22/f25 callees preserve every byte
operation in those paths, including a partially written error field or cursor
copy on a short buffer. No new guard or shortcut can suppress those effects.

The fixed runtime still validates the underlying view, mutability and bounds at
each physical access, before the write. Thus the same first failed physical
operation has the same error code/message and prior side effects whenever fuel
is sufficient to reach it. Expired/nonmutable-view comparisons are additional
private-callee controls, not a new public capability ABI. No new owner, loan,
resource, function call, call depth or memory allocation is introduced.

## Mechanical checks in the executable candidate

The strict `_scalar_byte_trace` recognizes only the reviewed straight-line
operations. It normalizes all addresses modulo 2**64 and results as disjoint
byte lanes; it records each physical access and each written byte's source bit
position. It rejects unknown operations, invalid/nonconstant shifts, unexpected
masks, overlapping lanes or changed operation shapes. Old/new normalized return
and ordered access traces must agree, with offsets exactly 0..width-1.

The projector stores every complete before/after edit. Reversing those edits
from the actual transformed document must reproduce the whole original Core
document. It separately checks every unaffected function and all function ABIs,
the full 107/1456/6299 inventory, and then calls the original complete Core
verifier. These are pending execution-time checks. The original R9 317-cast
projection remains intact and has its own separate report field.

## Actual cost evidence and limits of inference

`authority/R9-STEP-COUNTS.json` is the actual complete diagnostic cost record.
Each selected leaf's exclusive cost equals its call count times the old full
path cost, and f21 has zero calls. All selected counted calls therefore
completed on the observed paths; no partial helper call is guessed.

`COST-BOUND.json` derives 664,176 fewer charged operations in that already
observed semantic prefix. The arithmetic value 9,335,825 is **not the final
program cost**. Remaining phase-1 work was not observed after the old stop.
A candidate fuel stop can occur at a different instruction and must retain its
own actual partial buffers. It must not copy or synthesize the R9 failed state.

Current R9 native bytes are 545,428 and actual ELF bytes are 1,040,384, leaving
8,192 bytes under the unchanged 1 MiB cap. Fewer Core ops do not prove machine
fit: changed liveness/lowering must still be compiled and packed. No size,
fuel, default, whole-language, current-cold or public-compiler PASS is claimed.

## Next actual gates, in order

1. Fresh-bind the complete fixed host source, this generator, actual R9
   preimage, original actual u32 B3 and unchanged runtime/observers. Generate
   and check under original owners and Core limits; save full reports and
   independently parse/reverify the actual generated source. Do not prefill
   future source/image/ELF pins.
2. Use the original u32 compile and pure-HIA pack path: 20s compile, 10 CPU
   seconds, 1 MiB and original 180+3 owner. Preserve all real F/O/W before/after,
   stdout, request, receipt, exception and cleanup. Reject oversized ELF.
   Ordinary compiler and public R5 component pins stay unchanged.
3. Add full-width helper VM boundary controls at 10M/1MiB/depth128, one original
   180+3 owner: all short extents, unaligned/full/high offsets, dirty storage,
   full-width patterns, f92 invalid values and first-error partial writes.
   Save actual before/after bytes and access events before asserting. These
   additional cases never replace the retained controls.
4. Run original Native162 and all six logical VM cases in their original
   order/input/assertions, including the cross-target 10M case and full
   buffer/original-Native-oracle comparisons. Any failure stops later stages;
   retain it, with no automatic retry or larger fuel.
5. Only after those gates pass, run original aggregate kernel130, observer
   build, pipeline7 VM, six full kernel frame pairs and two last-byte faults,
   preserving original bodies, inputs, assertions, budgets and failure history.

The exact executable prefix/eight-group successor must be independently bound
to actual new products. This candidate packet itself does not authorize a run.
