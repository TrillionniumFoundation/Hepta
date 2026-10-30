# Composite v4: partial records with parameter-bound returned loans

`hepta.hia.composite.v4` is an explicit nominal input profile. It uses the
existing nominal elaborator to compose partial-record typestates with the
existing primitive v8 returned-loan contract. It adds no primitive opcode,
evaluator, Rust Machine, backend, optimizer or high-level source syntax.
Python remains the production admission authority. Optimization policy remains
`no_change`.

The concrete previously refused composition is an initialized buffer field in
a partial record, borrowed by a caller, passed to an internal helper that
returns a child view, used in the caller, then ended before the parent ends and
the field is taken and restored. Composite v3 supports the partial record but
rejects the helper's borrowed result; primitive v8 supports the returned loan
but does not take nominal partial-record input directly. V4 exposes that
composition through an explicit checked frontend adapter.

## Compatibility and admission

| Nominal input | Primitive target | Borrowed function results |
| --- | --- | --- |
| Composite v1 | Primitive v6 | Rejected |
| Composite v2 | Primitive v7 | Rejected |
| Composite v3 | Primitive v7 | Rejected, including `return_loans` annotations |
| Composite v4 | Primitive v8 | Primitive views bound to primitive borrowed formals only |

Existing v1–v3 normalization targets, canonical bytes and accepted/refused
grammars remain unchanged. The legacy nominal-v2 import remains a separate
explicit adapter targeting composite v1. V4 is not selected implicitly for an
older document.

The input retains exactly `schema`, `module`, `types` and `functions`. V4
functions may add `return_loans`. That list has one element for each **nominal
result**, before flattening:

- A primitive `readbuf` result names an original primitive `readbuf` or
  `mutbuf` formal.
- A primitive `mutbuf` result names an original primitive `mutbuf` formal.
- Every other result has a null annotation. An omitted annotation list means
  all nulls and therefore cannot admit a borrowed result.
- A generated name, nominal formal name, record field path, local owner or
  arbitrary string cannot stand in for a primitive borrowed formal.

All stored-loan aggregate results remain rejected. A record containing a
`readbuf` does not acquire a returned lifetime merely because its layout can be
flattened. Partial records still reject any loan-containing base layout,
including when its loan field is currently absent. Enum payloads and task
state/results keep their existing stored-loan restrictions.

## Origin binding through flattening

Primitive formal names survive flattening unchanged. A nominal formal expands
to private generated primitive names. In V4, only the original primitive
borrowed formal can be named by `return_loans`, so expansion cannot redirect an
origin to a generated owner token or nominal field.

For example, the checked-in
[standalone input](../examples/hia_program/composite_returned_loans_v4.hia)
declares a helper whose results are a partial `Pair` containing its scalar
`second` field, followed by a `readbuf`:

```json
{
  "returns": [
    {"partial": "Pair", "initialized": ["second"]},
    "readbuf"
  ],
  "return_loans": [null, "input"]
}
```

The partial state has a real private linear `buffer` token plus its `usize`
field. The normalized primitive result and origin lists are therefore:

```json
{
  "returns": ["buffer", "usize", "readbuf"],
  "return_loans": [null, null, "input"]
}
```

The helper consumes and returns an unrelated partial scalar state while its
caller retains the owner of the borrowed buffer. Transferring the owning
partial record while a loan of its field is live remains forbidden. The
adapter never creates a second owner or changes that loan's primitive root.

The ordinary `verify_program` path independently checks every generated
primitive function, call, CFG edge and return. Frontend annotations alone do
not establish the actual origin. Lowerable counterexamples with a wrong
formal origin, an early parent end or a moved borrowed partial field still
fail primitive v8 verification. The independent Rust verifier rejects those
same normalized candidates before execution, even under a one-step budget.

## Execution and public interfaces

Automatic exports still come only from original scalar nominal signatures.
Helpers with partial/record arguments, owner results or borrowed results are
internal. Raw Rust input remains primitive v1–v8: Python first elaborates and
verifies the nominal input, then the existing bound-v4 crosscheck submits those
exact canonical primitive bytes to the same Rust Machine. V4 does not make
Rust the nominal or production admission authority.

Direct LLVM consumes the same verified v8 Core. Its public ABI remains scalar
C entrypoints. No callback, foreign view parameter, reentrant call, thread or
external lifetime contract is added. Native build receipts continue to say
`native_compiled_not_executed`; separate actual call records provide execution
observations.

Normal returns and explicit allocation-failure branches consume actual owners
and loans. Traps and budget/depth stops retain the actual stopped ledger. This
increment adds no unwind or destructor behavior after an abort, asynchronous
cancellation, process failure or foreign exception.

## Reproduction and evidence boundary

Run the standalone example from the repository root:

```sh
python -m hepta hia verify examples/hia_program/composite_returned_loans_v4.hia
python -m hepta hia run examples/hia_program/composite_returned_loans_v4.hia \
  --function partial_result --arguments '[37]'
python -m unittest tests.test_hia_composite_returned_loans -v
```

The new module contains 13 methods: eight nominal/Python methods, three actual
Rust methods and two actual LLVM methods. The frozen qualifier also checks
their exact method inventory and requires no skips, failures, errors, expected
failures or unexpected successes. It must run on a clean exact commit:

```sh
python tools/qualify_hia_composite_returned_loans.py \
  --expected-head EXACT_40_CHARACTER_COMMIT \
  --output-directory /tmp/new-composite-v4-evidence
```

Its required finite corpus is 153 Rust comparisons, four raw Rust refusals and
31 actual native calls. These observation counts are not additional test
methods and must not be added to the 13-method denominator. The qualifier
retains raw process output, canonical programs, original nominal input, LLVM
IR, linked artifacts, allocator driver and source/toolchain/binary identities.
The source tree must match before and after the run. The independently
reviewed safety matrix retains all prior 103 methods and adds these 13,
selecting 116 unique methods; integrated critical coverage requires the new
module.

The corpus includes read/mutable forwarding, direct children, renamed CFG
parameters and recursive call forwarding; a partial result preceding a loan
result; every actual VM step boundary in both recursive fixtures; heap, call
depth and injected allocation failures; and a wide failure index transported
by the existing bound-v4 API. LLVM scalar calls exercise sizes 1, 7 and 19.
The independent allocator observer is deliberately used within its existing
one-byte-payload fixture and checks actual allocation failure and release.
This is Linux x86-64 native evidence, not a cross-target execution claim.

The new refusals cover missing/malformed annotations, permission escalation,
generated-name origins, stored-loan returns, stored-loan partial layouts,
nominal aggregate origins, uninitialized fields, incomplete finish, escaping
local owners, owner motion under a live returned child, wrong primitive
origins, premature parent end, inaccessible public entries and invalid unused
functions. Existing partial-record/task/chain fixtures retain the same
normalized structure and Python ledgers when explicitly re-expressed as V4
without borrowed results.

## Remaining blockers

This closes the finite nominal partial-record/primitive parameter-loan
composition gap. It does not close all of P0 or P1. Historical source, bridge,
local-view and task/I/O routes still require their own convergence work.
General memory/provenance, arbitrary recursive ADTs, complete partial
initialization, stored escaping loans, external lifetimes and complete
cancellation/error cleanup remain open. This finite adapter and its execution
corpus establish no source/Core/native refinement theorem, performance
improvement, physical-device qualification or whole-language soundness.
