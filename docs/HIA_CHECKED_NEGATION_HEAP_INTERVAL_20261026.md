# HIA v6 checked-negation interval resource admission — P1

**Parent:** PR #242 HEAD `29c0e22dc1067f9fb5f9e5e2353e031acec90e54`
(descendant of PR #236). This is one small lowering/analysis change, not a
second IR, memory optimizer, interpreter, native compiler or proof authority.

## Concrete limitation

The canonical executable HIA Core already verifies `int.neg.checked`,
and the standalone VM/native backends implement its machine-width trapping
semantics. The optional finite-live-payload analyzer, however, did not
propagate a known or joined interval through that opcode. Consequently a
literal or diamond/select of strictly negative bounded integers used as a
positive allocation size was reported as entirely unknown. Such a valid
AI-generated resource plan could not satisfy even a small proven heap budget.

## Conservative interval transfer

Let the already independently typed operand have known interval `[lo, hi]`.
Negation maps its endpoints to `[-hi, -lo]`. **Only** if that entire image
fits the exact destination type's integer limits do we retain the interval.
For singleton values known to overflow, we refuse explicitly. A partially
overflowing range becomes unknown, so it cannot authorize a later heap bound.
Unknown dynamic inputs remain unknown. This cannot manufacture ownership,
pointer provenance, successful allocation or general semantic equivalence.

No path relaxes the 64-bit allocator `MAX_REQUEST` bound. A bounded negative
i32 choice `-7 / -12` is now certified with live payload upper bound 12,
including a real VM test for both branches. A `-128:i8` trap, a nonzero
`u8` negation trap, an unknown i32 parameter and a joined range containing
the minimum signed value must all fail static heap qualification.

### Additional mathematical check executed locally (not full Hepta)

For every one of the **32,896** nonempty signed i8 closed input intervals,
compared the proposed bounded-negation admission rule against every integer
in that interval. All **32,640 admitted** intervals enclosed every
nontrapping negated result; 256 ranges containing the signed minimum were
conservatively rejected. This is an isolated transfer-function check, **not**
execution of the in-repository checker/VM/native compiler.

## Exact-checkout acceptance

```bash
python -m unittest tests.test_hia_heap_negation tests.test_hia_heap_intervals \
  tests.test_hia_heap_bound tests.test_hia_static_budget \
  tests.test_hia_vm_call_depth -v
```

The CI queue is not used as a development stop. No full in-repository
test or LLVM/native parity proof has been performed from this environment.
The analyzer still refuses arbitrary live-heap sizes, unbounded loops,
owner-valued foreign calls, partially overflowing intervals and unsupported
new opcodes. Native RSS and external allocator costs remain outside this
payload-byte model.

`whole_project_blockers_closed=false`.
