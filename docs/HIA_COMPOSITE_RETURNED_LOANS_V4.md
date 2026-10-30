# Composite v4: parameter-field returned byte loans

`hepta.hia.composite.v4` adds a bounded composition boundary to the existing
nominal elaborator. It retains records, enums, partial initialization and
cooperative tasks, and normalizes to `hepta.hia.program.v8`. It does not add
primitive operations, pointer casts or unchecked runtime access. Every
elaborated program is independently checked by the existing primitive verifier
before interpretation, independent Rust comparison or native emission.

Composite v1 still targets primitive v6; composite v2 and v3 still target
primitive v7. They reject v4 returned-loan metadata even in otherwise unused
functions. Existing source lowering remains its separate v1/explicit-v8 route;
this change does not silently add borrowed aggregates to the Hepta source
language or promote the Rust shadow to production authority.

## Exact function contract

A v4 function may return primitive `readbuf` or `mutbuf` values. Its optional
`return_loans` array contains exactly one entry per **nominal result**:

```json
"returns": ["readbuf", "mutbuf", "usize"],
"return_loans": [
  {"param": "views", "fields": ["inner", "right"]},
  {"param": "writer", "fields": []},
  null
]
```

The object form has exactly `param` and `fields`.
`param` names an original formal parameter, not a block-local alias, result
name, generated name or numeric slot. `fields` is a list of ASCII record field
names in outer-to-inner order. An empty list selects a direct primitive loan
parameter. Its length is bounded by the existing 32-level type-path limit.
Integers, booleans, extra keys, missing names and unsupported path shapes
reject. Every nonloan result requires `null`; omitting the array is equivalent
to all null entries and therefore does not authorize a borrowed result.

The original primitive-formal string annotation is also retained: `"writer"`
is equivalent to `{"param":"writer","fields":[]}` only when `writer` is an
original primitive `readbuf` or `mutbuf` parameter with sufficient permission.
A record parameter's name alone is rejected, even if that record has one loan
field or empty fields erase from its layout. Generated names and block-local
aliases are not accepted. A function can mix these two explicit forms; both
resolve through the same original-parameter and field-path checks before the
existing primitive verifier checks their actual ancestry. Missing, malformed
nonobject and invalid string origins retain the original `E_HIA_LOAN` refusal.

The selected original parameter must be a primitive loan or a finite record
without owning resources. A path traverses complete record fields only and
must end at one incoming `readbuf`/`mutbuf` leaf. A `mutbuf` result requires a
`mutbuf` leaf. A read result can reborrow either permission, as permitted by
primitive v8. Generic records resolve to their exact concrete layouts before
the path is interpreted.

Owner presence is determined from the bounded flattened primitive slots,
including actual partial/task owner tokens. It does not recursively expand
shared zero-width record fields. This also removes an exponential ownership
walk present in the earlier nominal implementation; empty record prefixes
contribute zero to the selected leaf's offset.

Owner, scalar, enum, task and partial-record origins reject. An owning record
cannot be used as an origin even if it also contains an unrelated incoming
loan. Returned nominal aggregates that contain loans continue to reject.
Partial record fields, task state/results and enum payloads retain their
existing stored-loan exclusions. Local records containing loans retain the
previous checked behavior; no general escaping stored-borrow model is added.

## Origin mapping and independent admission

For each result the elaborator resolves the original parameter and the sum of
the exact flattened widths preceding the selected leaf. It then obtains the
leaf's **actual generated entry parameter name** from the entry environment.
The emitted primitive function has the ordinary v8 annotation:

```json
"return_loans": ["h2internal_4", "writer", null]
```

Those generated names are illustrative; they are never accepted from the
nominal caller as origin metadata. A scalar or owner aggregate result expands
its single null annotation to every primitive result slot. The offset and
entry binding are based on the original parameter layout, not on whichever
SSA name happens to be used at a return block.

The primitive verifier separately checks the resulting annotation, all CFG
edges, call argument aliases, return ancestry, permissions and resource
consumption. A return from the wrong nominal field still lowers to actual
primitive instructions and is rejected there; successful structural
elaboration itself grants no admission. A returned loan must satisfy the
existing v8 parameter/direct-child rule. A CFG join cannot substitute a
different incoming origin merely because its types match.

Public `VerifiedProgram` constructors remain untrusted. When both nominal and
Core bytes are present, consumers repeat elaboration and require the same
canonical primitive snapshot. Caller mutations after verification do not
change the stored nominal snapshot or executable bytes. Public export
eligibility is determined from the original nominal signature: borrowed or
aggregate entrypoints do not become public C ABI exports after flattening.

## Composition with partial owners and cancellation

The new test corpus constructs two fallible byte owners in a partial record.
It borrows the actual initialized fields, packs the views into a nested
loan-only record, calls a CFG-renaming helper through another helper, and
returns the two loans with their origins swapped explicitly. The mutable
case writes through each returned loan and later reads both original fields
with asymmetric weights. This makes incorrect field binding observable.
Local children end before parents and owners are released.

Separate first/second allocation-failure paths consume real empty owners and
release earlier allocations. A cooperative task example creates and ends a
returned loan during `poll` before carrying its partial owner state into
pending cancellation, running cancellation or completion. No loan survives in
the task state. This exercises the existing explicit cleanup protocol; it does
not introduce exception unwinding or implicit cleanup at a VM budget stop.

## Executable checks and retained observations

The focused tests are in `tests/test_hia_composite_returned_loans.py`:

```sh
python -m unittest tests.test_hia_composite_returned_loans -v
```

An actual Rust toolchain and Linux Clang are required for the independent and
native methods. Missing prerequisites produce skips rather than qualification.
The safety-contract runner additionally requires zero skips. The registry and
the new capability's explicit tests are reviewed in
`docs/HIA_SAFETY_CONTRACT.json`.

The layers checked by these methods are distinct:

| Layer | Actual check | Scope limit |
| --- | --- | --- |
| Nominal frontend / CLI | Verify, inspect, normalize and run v4; reject malformed annotations and historical schemas | Finite standalone nominal JSON, not a new source syntax |
| Primitive authority / Python VM | Recheck exact flattened origin names, aliases, CFG and ownership; execute values and stopped ledgers | Existing v8 operational rules, not a soundness theorem |
| Independent Rust | Parse normalized primitive bytes independently; compare full ledgers at normal/error/trap/step-stop paths; reject invalid raw Core | Does not independently elaborate nominal input; nominal wire input is refused |
| Native LLVM | Execute real linked allocator observers and deliberately wrong native controls | Actual Linux host only; allocator observations do not prove all borrow lifetimes or backend refinement |

For retained focused observations, set `HEPTA_COMPOSITE_V4_EVIDENCE_DIR` to a
new output directory. The tests retain actual CLI output, Rust build/process
records and executable, normalized/nominal fixture bytes, native objects,
observer sources, executable files and process outputs. This optional recording
does not change the checks. The output is evidence of that invocation and its
source state, not an importable admission receipt; recorded counts must come
from the terminal test result and actual observation files.

The scalar/guarded optimization proof engines do not gain v8 support merely
because composite v4 now normalizes there. Static-budget and Agent consumers
keep their explicit primitive-profile boundaries. A new registry entry is
neither an optimization proof nor a resource budget. No arbitrary foreign
lifetime, asynchronous cancellation, global optimality, process-memory bound
or universal performance advantage is established by this increment.
