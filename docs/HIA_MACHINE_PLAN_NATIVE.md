# HIA machine-plan control owner

## Boundary and selection

The explicitly selected `HEPTA_HIA_MACHINE_PLAN_MANIFEST` owns the complete
control flow of `validate_plan`, `register_assignment_witness`, `code_options`,
and `preservation_checks`. It also owns `_require`, `_permutation`,
`_terminal_arguments`, and the nested generator/lambda control used by those
bodies. The four original public bodies remain mechanically renamed as
`_reference_*`; their source/AST comparisons and the unmodified original
44 caller tests remain independent controls.

With no selector the original behavior remains available. A selected manifest
must be freshly admitted against its HIA source and image. A selected failure
does not call a retained plan body. A `ContextVar` pins the admitted instance
through nested plan callbacks, including a caller's replacement witness hook.
Changing the environment during that callback cannot select another image for
the in-progress operation. A subsequent independent operation performs its own
selection. The generic loader's pinned-helper hook and admitted source identity
are preserved.

This component is not the complete native backend. `_Function`, `_Emitter`,
machine-plan consumers, ELF/linker/tool policy, and other unselected owners keep
their own boundaries. The fixed Python bridge still performs the individual
object operations requested by HIA: object lookup, actual calls, iterator
advance, arithmetic/comparison primitives, construction, imports, and reference
ownership. Original globals and caller hooks remain observable through those
requests. In particular, `validate_plan` requests the existing `_decode` at the
original point; this component does not claim to replace public normalization.
No all-input equivalence, default activation, cold qualification, or deletion
approval follows from the development controls below.

## HIA program and representation

`tools/hia_machine_plan_control.py` is an authoring compiler for the finite
original API bodies. `tools/generate_hia_machine_plan_control.py` emits their
ordinary HIA control interpreter and immutable policy table;
`tools/generate_hia_machine_plan.py` is the canonical generator entry point.
Runtime never imports those authoring modules, walks an AST, or receives a host
policy plan. The selected HIA image emits its own table, executes branches and
loops, orders foreign operations, and decides every continuation and retirement
request.

The current source contains 16 semantic functions, 1,433 control instructions,
135 literals, and at most 419 object slots in one frame. Its immutable table is
40,376 bytes. A private frame reserves 1,024 bytes of protocol/header space plus
eight bytes per slot, so its workspace is 4,376 bytes. The largest emitted
foreign-request frame is 240 bytes; the physical output arena is 2,048 bytes.
These figures are derived from the checked finite authoring source. They do not
limit the number of Core functions, blocks, values, iterator elements, returned
rows, or the extent of caller-owned objects.

Core objects are not serialized into a bounded JSON arena here. Every foreign
value occupies an opaque owning slot, and HIA requests actual access in the
original order. Long inputs cause repeated continuations, not truncation,
pre-normalization, a changed public node quota, or a hosted semantic fallback.
Each nested original semantic call has its own private frame. Physical Python
operations, allocation failures, and foreign callback execution remain explicit
interop; the development observations are not a proof of every possible foreign
object, physical recursion boundary, Python version, or asynchronous interrupt.

The emitted literal table carries an explicit identifier-interning tag.
This preserves the observed identity of original ASCII identifier constants
passed to foreign mapping operations. The bridge boxes the requested literal
representation; it does not infer the next policy operation from its contents.

## Permissions, exceptions, and lifetime

Each frame receives a process-monotonic, non-recycled private nonce. An issued
request is bound to the exact immutable `Issued` object and all its bytes.
Before executing its primitive, the bridge consumes its host permission and
obtains a separate actual HIA claim. HIA cannot advance that frame until the
primitive's outcome has been acknowledged. A duplicate object, stale nonce,
completed claim, changed request, or terminal replay does not execute the
foreign operation again.

HIA maintains the birth order of temporary operands and requests their
retirement at the original expression boundaries. Original function and
generator locals remain held while an original exception traceback holds their
frame. Generator cancellation asks HIA to retire its temporary values and then
drop its local references. Dropping a closure cell reference does not clear a
cell independently held by another generator. The native retirement command is
admitted only in yielded or terminal stages; it cannot retire an unacknowledged
pending request.

The fixed catcher leaves its Python exception handler before HIA-authorized
operand retirement. The shared `hia_exception_delivery` mechanism then delivers
the same exception object without substituting a generator rethrow. When an
original handled exception must be visible to a foreign operation, the bridge
first requires that the actual delivery raises that exact object. A closed
delivery mechanism or a different interrupt cannot authorize the operation
under a replacement handled exception.

A partial constructor owns and releases its two private arenas even while the
original allocation exception and traceback remain held. It does not clear
caller arguments or closure slots merely to release those arenas. If an actual
callback has run but its reply or acknowledgement is interrupted, the frame
closes and retains the unconfirmed state. That private fault-injection boundary
does not permit automatic retry or pretend that the effect was absent.

## Builds and package custody

`tools/build_hia_machine_plan.py` consumes a completed matching-source cold
report through the shared strict builder. Cold admission precedes creation of
the parent evidence directory or candidate. Development controls use
`HEPTA_HIA_MACHINE_PLAN_DEVELOPMENT_MANIFEST` explicitly and cannot override a
simultaneously requested `HEPTA_HIA_MACHINE_PLAN_COLD_REPORT`.

The checked source is `examples/hia_bootstrap/machine_plan.hiaasm`. The package
resource registry and manifest include that exact file. The installed control
builds and installs an actual wheel with the complete five resource groups,
then runs a fresh `-I -S` child with an empty `PATH`, all seven retained plan
bodies/helpers forbidden, and authoring imports forbidden. It also checks warm
source changes and missing-source refusal. This is component package custody,
not qualification of an unrelated repository tree or compiler.

## Preserved observations and current development scope

The original peer `acffa9262f31d073f8f0a6f0201eae201039f619` was observed
independently. Its ordinary case matched, while a `sha256` string subclass and
an `as_dict` temporary root with a destructor did not. Those original inputs,
failures, and compiler observations are retained in capsule
`9914a68154b67b4c6d8476dd23339536483c7dbe`.

The initial complete controller's three corresponding cases and original
44 callers passed in the separately retained R1 development scope
`774c74c08021ae3cac7e2f60839e896e56daf6c2`. A later scratch reset lost the full
raw observations of its next lifecycle revision. Exact source recovery and
the failed post-reset launch are retained separately in `225c264e…`,
`ba4d6e81…`, and `e37e41f9…`; they do not recreate the missing raw evidence.

The new recovery scope starts from published `f8d9680a9b0ae609850c006480a7d1f68ea00979`
and uses retained compiler SHA256
`81b6fad94493546b5bf3f858248f25b19aded88bf8f3aaad18140aa317dac109`
on CPython 3.12.14. Rebuilding recovered R2 reproduced its previously observed
HIA and image hashes. Five new controls then produced one pass and four
failures: three demonstrated product differences and one opcode-trace arming
error in the test. Capsule `ad1e6463bff9bbaa67b8806a52a6e7d2a8ebd762` preserves
the exact failing sources, new raw compile, report, and logs.

R4 fixes only those three demonstrated product differences and the trace
fixture. Its HIA source SHA256 is
`ab35c1c2fc2928e2932be9644859e8b200ad19f4ec65d65af93b1d2ac24c35c2`;
its development image SHA256 is
`e7d51f6c915a164db8a717d5bfd35d051523900cb790987138a6e5ea6eab3836`.
Separate terminal gates establish:

- the same five targeted controls: 5/5, 0.859 seconds;
- the retained source/native component controls: 12/12, 260.428 seconds;
- the expanded control module: 9/9, 61.774 seconds, including 1,376 complete
  native/ordinary-Core-VM source/output/workspace comparisons with canaries,
  the three original peer witnesses, six held-error lifetime/context cases,
  stale nonce/pending-retirement refusal, and real reply-store interruption;
- the original selected callers: 44/44, 36.072 seconds, with all four retained
  public plan bodies forbidden and no unittest anomalies.

Each gate records its own complete loaded/executed IDs, raw output, source
before/after, and exact manifest/image identity. The three counts are separate
observations and overlap; they are not presented as one combined suite. The
original 44-caller regression is a separately reported gate. Current-source
cold and full repository qualification are required after integration.
