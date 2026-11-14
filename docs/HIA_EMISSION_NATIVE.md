# Native compile and emission control

`examples/hia_bootstrap/emission.hepta` owns the complete control flows of
`HIAAgentService._compile` and `_hia_emit`. The optional selection is
`HEPTA_HIA_EMISSION_MANIFEST`. A present invalid or empty selector fails without
falling back to the retained methods. The two original implementations remain
available as independent references; removing them is not part of this owner.

This component moves the original control decisions and effect order into HIA.
It does not replace the Core emitter, native compiler/linker, filesystem, Store,
SQLite, clock, digest implementation or Python's opaque object protocols.
`tools/generate_hia_emission.py` is a Python authoring aid for the checked-in HIA
source. Its existence is not evidence that the entire toolchain is native.

## Owned control and provider boundaries

The HIA image chooses the original deadline clamp branches, exact-byte admission,
temporary-directory entry and exit sequence, metadata short circuits, repeated
kind comparisons and publication order. It also chooses verification-receipt
iteration, canonical or explicit plan selection, the original `any` check loop,
export conversion loops, compile keyword presence and the final response path.

The foreign adapter performs named primitive operations. These include original
provider calls, opaque attribute and item access, iterator operations, arithmetic
on original Python numeric objects and comparison/truth protocols. It does not
call either retained control method on the canonical selected route. Explicit
user overrides are ordinary foreign callables, whose contents are not restricted
or silently replaced.

The compile providers are imported and bound together at the original first
operation, before budget rejection. Later replacement of the module's compile
provider does not replace the already captured callable. Clock and digest
providers retain their original fresh lookups. Store method lookup and argument
evaluation retain the original order, including the case where `put` succeeds
but the following assignment to the result mapping fails.

The public emit flow captures the original dynamic `self._compile` callable
before evaluating output-kind and remaining-time arguments. An override that
changes during those later operations cannot replace the captured callable.
Empty exports omit the keyword; nonempty exports pass the original tuple.
Default selected compilation enters a child HIA frame. The signature call remains
the separate admission owner or explicit foreign signature provider selected by
the original global lookup.

## Context managers and runtime object protocols

The original `with` statement binds class special-method descriptors to the real
manager and ignores instance shadows. The interpreter's lookup order is measured
on private descriptors, with no user object involved and no version threshold.
HIA iterates those facts and issues each actual user lookup. An entry failure
does not invent an exit call. Normal exit does not truth-test its result.

If a body effect raises, the HIA image chooses exceptional exit and suppression
or propagation. Native-issued exit and truth operations run while the original
Python exception handler is active. This preserves `sys.exception()`, bare raise,
replacement exception context and the original traceback passed to `__exit__`.
After suppression, the handler is left before subsequent effects resume, restoring
any outer exception. HIA preserves the original unbound `result` or `data`
continuations and the metadata failures that precede them.

The generator entry protocol is also measured on a private iterator. HIA owns
the number of extra iterator conversions, the check loop and its short circuits.
Generator-internal `StopIteration` follows the original PEP 479 boundary; initial
iterator conversion and the external `any` truth operation retain their original
exception family. Normal and short-circuit loop releases are explicit HIA-issued
operations. No extra input shape, integer magnitude or frame-count quota is added.

## Unknown effects and nested owners

The continuation ABI has an 80-byte request, a 128-byte retained state and a
96-byte result. It binds mode, sequence, issued port, creator process and thread,
and per-frame identity. A native acknowledgement is checked before the next
effect. Frames are retained before any foreign effect can begin.

If native transport or receipt decoding fails after an effect, the frame remains
fenced and unconfirmed. There is no retry, automatic directory cleanup, invented
completion, refund or replay. Ordinary transport exceptions that the public
request wrapper could otherwise record as rejection become `EmissionUnknown`.
Existing ordinary `RuntimeError` identity and process-control exceptions remain
unchanged while custody is retained.

An actual nested emission/compile native failure marks its still-active causal
ancestors unconfirmed. The parent cannot misclassify the child's lost ACK as a
confirmed foreign exception. This relationship follows the active call scope,
process and thread; it does not infer unknown state from an exception class or
the size of a global registry. Confirmed foreign errors still follow the original
cleanup and exception semantics.

This causal relationship currently covers `EmissionFrame` ancestors only. The
separate admission, context, Store, ledger and evaluation owners do not publish
their native delivery failures to this emission scope. An uncaught foreign-owner
`RuntimeError` can still leave the public request journal running, but that does
not establish cross-owner causal custody. A foreign callable or context manager
that catches such a failure can hide it from this component. Cross-owner unknown
propagation remains an explicit gap; normal multi-owner composition does not
close it.

## Independent original observations

The five files under `tests/fixtures/hia_emission_original_73f1634/` are immutable
inputs frozen before candidate execution. They contain both complete original
method bodies from published `73f16346e7f84fa13305777a4595e2d1b422dee9`, an
independent fake-provider oracle, 954 ordered cases and the complete original
caller inventory. The implementation is based on the later published dispatch
repair; the original bodies and frozen caller scope remain those of 73.

The cases include first failures and failures after actual fake effects,
context-manager suppression and replacement, dynamic provider changes, one-shot
iteration, numeric protocols, original publication order and composed emit/compile
calls. Equality covers canonical trace bytes, argument snapshots, returned values,
exception cause/context and identity observations, temporary-directory state and
retained Store effects. Cases and expected semantics must not be edited to fit
the candidate.

The original-only freeze observed CPython 3.12.14, 3.13.5 and 3.14.10 independently.
With lookup order differs on the observed 3.14 runtime, and an extra generator
iterator conversion is observable on the observed 3.13 runtime. These differences
remain in the comparison. The package's supported runtime range is unchanged;
the freeze does not claim an observation of Python 3.11, arbitrary metaclass
mutation or all possible finalizer schedules.

The original caller inventory is nine ordinary complete modules with 112 ordered
methods, plus eight separate administrator/owner modules with 128 methods. The
ordinary qualifier runs all 112 with both retained control methods forbidden in
the test process. It does not merge the separate 128 methods into that count or
claim that in-process Python poison instruments every subprocess. The only
permitted old-source adjustment is the exact decimal helper-registry count in
one original assertion; all other bytes, test identities and original budgets
remain fixed.

## Qualification commands and scope

The component test setup requires exactly one nonempty source of authority:

```sh
HEPTA_HIA_EMISSION_COLD_REPORT=/absolute/current/cold.json \
HEPTA_HIA_EMISSION_EVIDENCE=/absolute/new/component \
python -B tools/run_hia_unittest_gate.py tests.test_hia_emission_native

python -B tools/qualify_hia_emission_callers.py \
  --cold-report /absolute/current/cold.json \
  --evidence /absolute/new/callers
```

The matching-cold builder checks the current complete source map, compiler bytes,
compile receipt, produced image and every component input before and after the
build. An explicit development compiler is available through
`HEPTA_HIA_EMISSION_DEVELOPMENT_COMPILER`; development evidence remains labeled
development and cannot substitute for a matching-current-cold gate.

The component checks two distinct integration boundaries: a freshly built wheel
running the actual installed emission worker, and an eight-owner public
emission/evaluation/adoption composition in the source process. The latter is
not an installed eight-owner worker observation. Their evidence and limitations
remain separate.

Source declarations, the finite oracle, component observations and ordinary
caller results have distinct scopes. None establish all-input equivalence,
whole-project dynamic-caller closure or completion of the entire native rewrite.
