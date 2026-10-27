# HIA P7: Python JSON pre-decode resource budgets (2026-10-27)

## Observed weakness

The existing `hepta.hia_program._decode` enforced an 8 MiB JSON input byte
limit, then called the standard `json.loads` and only afterwards walked the
materialized object graph to enforce `MAX_NODES=262144` and `MAX_DEPTH=64`.
Even a smaller-than-8-MiB dense array could therefore allocate hundreds of
thousands of Python objects before being rejected. The separate Rust shadow
decoder already has an early node/depth budget; this change closes the Python
admission ordering without replacing the verifier or the standard JSON decoder.

## Narrow implementation

`hepta.hia_json_preflight.preflight_hia_json` scans a bounded UTF-8 text
without materializing its object-value tree. It counts the same structural
nodes as the existing `_structure`: root depth zero, array elements and
object *values* counted, object keys not counted. It rejects when the next
node would exceed 262,144 or depth would exceed 64. Object keys are decoded
one at a time solely for duplicate-key equivalence (including Unicode
escapes) and are rejected before deserializing the corresponding value.
Only the already-supported integer/string/Boolean/null JSON subset is
admitted; fractions, nonfinite numbers and malformed tokens still reject.

The original standard-library `json.loads`, duplicate-key hook, structural
verification, canonical serializer and native HIA instruction verifier remain
in place after preflight. An early resource-budget violation reports
`E_HIA_LIMIT`, while invalid JSON reports `E_HIA_FORMAT`. Input bytes,
native emitter, Hepta source producer, LLVM, Rust shadow, C/C++ migration
and agent workspace code are otherwise untouched.

## Actually executed

Local Python 3.13 on exact new module and pure test bytes:
`python -m unittest discover -s tests -p test_hia_json_preflight.py -v`
**6/6 passed**, zero skips. This includes 2,000 randomized valid JSON trees
and a monkeypatched negative ensuring no whole-document `json.loads` is
called for a dense over-budget scalar array. The Git blobs for the module
and pure tests match the locally executed files byte-for-byte.

## Complete-checkout acceptance (not executed here)

```sh
python -m unittest tests.test_hia_json_preflight tests.test_hia_json_predecode -v
python -m unittest tests.test_hia_program tests.test_hia_program_llvm -v
python -m unittest tests.test_hia_rust_scalar_vm tests.test_hia_rust_shadow -v
```

These commands require a full exact-source checkout; the integration tests
and Rust/LLVM native paths have not been executed on this combined commit.
The preflight scanner is not a sandbox for an intentionally enormous Python
object already constructed by a caller, nor a whole-program RSS bound or
language soundness proof. P0–P7 broad blockers remain OPEN/PARTIAL;
`whole_project_blockers_closed=false`.
