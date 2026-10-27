# HIA P1: exact SSA checked division/remainder for finite live payload bound

On the converged HIA v6 branch, VM and LLVM already execute
`int.div.checked` / `int.rem.checked` with integer zero-divisor and
signed-MIN/-1 overflow traps. The same canonical static heap analyzer
previously discarded all div/rem results, causing refusal even when an
allocation extent came from two exact integer constants.

The added `hia_heap_bound._bounded_divrem` transfer accepts **only**
a pair of exact typed singleton inputs. It rejects zero divisor and the
signed minimum / -1 case; for valid signed division uses truncation
**toward zero**, unlike Python's negative floor division. Remainder is
`dividend - trunc_quotient * divisor`, preserving the VM and LLVM
signed remainder convention. Unknown/broad intervals remain UNKNOWN.
The canonical executable HIA Core verifier, Rust shadow, LLVM emitter,
VM, source/ABI/sandbox boundaries, and all language/proof claims remain
unchanged. This opt-in budget analyzer does not add an unsafe fallback.

## Validation

Independent finite arithmetic enumeration executed on the model host for
every i8 and u8 dividend/divisor pair: **130,559** defined pairs with
truncating quotient/remainder, **513** trapping cases across both types.
No arithmetic identity violations were observed. This controls the
arithmetic formula only, not the actual Hepta parser or native codegen.

Committed `tests/test_hia_heap_division.py` uses the real repository
verifier/VM/static gate (not yet executed on a complete checkout), including
actual 37/4 => 9 and remainder 1 byte allocations, budget equality,
zero divisor and signed overflow traps, unknown input refusal and an
exhaustive typed scalar div/rem helper comparison.

To run once a complete exact-code checkout is accessible:

```sh
python -m unittest tests.test_hia_heap_division tests.test_hia_heap_shifts \
  tests.test_hia_heap_negation tests.test_hia_heap_intervals -v
```

Remaining P0–P7 semantics, arbitrary C/C++ L2/L3, full Rust memory-model
proof, target ABI/platform, production Agent A/B and physical hardware
are NOT closed by this transfer. `whole_project_blockers_closed=false`.
