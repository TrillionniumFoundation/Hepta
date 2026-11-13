# Native Agent verification coordinator

This optional owner places seven existing Agent verification method bodies and
their lazy claim generator in an ordinary HIA program. It does not replace the
whole Agent or claim a proof of the implementation. Default selection and
retirement of hosted production owners remain separate integration decisions.

## Owned policy and remaining providers

The complete owned entry inventory is `_subject`, `_hia_verify`, `_verification`,
`_replay_verification`, `_required_claims`, `_check_native_refinement_evidence`,
and `_native_refinement_binding`. HIA chooses subject and claim branches,
ordered receipt/evidence validation, all loops and short circuits, artifact
construction, foreign-effect permissions, exception handlers and retirement.
The generator expression in `_required_claims` has its own native frame and
captured claim cell; it remains lazy and returns the original comparison object
on a short-circuit edge. A true onward edge releases that object before reading
the next expression.

The existing behavior-equivalence and independent native-refinement engines,
proof-contract producer/consumer, Core verifier, native emitter/linker, object
and artifact providers, SQLite/request journal, clock, and installed identity
providers remain declared dependencies. This coordinator calls their original
interfaces at HIA-selected points. It does not relabel those providers as moved
to HIA, run a hosted copy of any owned body, or imply end-to-end HIA execution.

`tools/hia_service_verification_policy.py` is an authoring-only copy of the
original seven bodies. A finite reviewed compiler emits an immutable control
table and ordinary HIA operations. The HIA image itself expands and emits that
complete table. Runtime Python neither imports the authoring package nor
interprets its Python source/AST. The independent test oracle retains the
pre-owner source and uses the actual service module's provider globals.

## Fixed foreign mechanisms

Opaque slots hold the actual Python objects. Fixed ports perform a single
object primitive chosen by an issued HIA frame. Ordinary calls move the native
temporary callee and arguments onto the real interpreter call stack. Keyword
expansion is deliberately staged: a fixed `DICT_MERGE` primitive admits the
original mapping, HIA releases its temporary mapping, and a separately issued
call consumes the prepared argument tuple/dict. The `kind` keyword followed by
one mapping is a distinct fixed shape. Dictionary displays use `DICT_UPDATE`,
which permits replacement; they do not borrow duplicate-key refusal semantics.

The opcode templates support only the explicitly checked CPython 3.12, 3.13,
and 3.14 families. Their exact instruction inventories fail closed when the
actual interpreter template differs. This remains a hosted interpreter
mechanism, including physical call frames, original exceptions, PEP 479,
mapping behavior and object finalizers. It is not a claim to have replaced
CPython with HIA. Executed controls are specific to the reported interpreter;
an allowed profile does not transfer results between versions.

Only HIA's once-issued frame may execute a port. The Python transport checks
the exact issued object and raw frame, consumes a real native claim before a
foreign operation, and acknowledges only a known outcome. Reentry into the
same permission, fabricated/replaced frames, and a lost claim/result/ACK cannot
authorize a retry. Unknown retirement retains its state instead of guessing
which objects or effects were completed. New independent calls are distinct
operations; the existing request journal continues to own public replay.

Original function locals survive a retained error traceback. The bridge does
not clear all foreign slots on error or invoke GC. HIA retires its original
temporaries and named locals under the observed CPython frame profile when the
frame is actually released. Closing a service prevents new calls; already
owned frame retirement remains attached to its held image.

## Selection and proof custody

`HEPTA_HIA_SERVICE_VERIFICATION_MANIFEST` explicitly selects the component.
The strict loader freshly reads the complete manifest, HIA source and image
before every new admission and rereads them after mapping. Only immutable code
bytes may share a cache entry. An active worker helper bundle is authoritative;
no ambient image is substituted for a missing bundle entry.

The service retains the exact admitted image and source/manifest bytes in its
held checker capability. `_hia_verify` and `_verification` supply that same
capability to the existing proof producer/consumer. Selector or file drift
cannot silently rename the old service's executing code. A different service
with a different image cannot consume an old proof merely because current
environment paths happen to match its text. Serialized evidence cannot rebuild
this in-process capability. The component belongs to `HELD_NATIVE_OWNERS` and
the explicit helper bundle; it is not an ambient Core-checker selector.

Static binding calls made within this coordinator use its active held scope.
A standalone static binding call outside any service continuation performs a
fresh explicit admission if configured. The unselected route preserves the
original method signature and forwards actual arguments without retaining an
extra facade-owned reference through the original frame's retirement.

## Build and qualification boundaries

`tools/build_hia_service_verification.py` has separate matching-source cold and
explicit development modes. The former requires the existing complete cold
source contract and original 180-second work plus 3-second cleanup limits.
Both validate actual compiler/source/image bytes and both the returned and
persisted compile receipts, preserve the compiler's original 20-second child
limit, publish to a new evidence directory, and reread every consumed input and
published result. The development mode never creates current-source cold
authority or changes default selection.

Permanent Source controls cover the exact original bodies, regeneration,
finite call/import inventory and runtime/authoring separation. Adapter controls
are explicitly controlled transports: they check source/cold/receipt admission,
duplicate fields, exact types, active-bundle refusal, warm drift, post-map drift,
FIFO rejection and mutually exclusive fixture routes. Native controls require
an explicitly supplied current cold report, development compiler, or development
manifest. They separately record ordinary-VM/frame comparisons, controlled
foreign-object differentials, actual SQLite/proof/replay effects, installed
execution and original Agent callers as those groups become qualified.

The source-owned caller driver is `tools/qualify_hia_service_verification.py`.
It preserves the four original Agent modules, their exact ordered 48 test IDs
and source hashes, their per-test assertions/budgets, and the retained
1800-second group supervisor and cleanup. It requires the original real Z3
4.15.4.0, Clang 20, GNU linker and JSON-schema dependency. Every seven-method
reference body is poisoned in the test process. Child processes inherit the
explicit selector, not those in-memory patches. Actual returned native frames
and all eight method/generator modes are counted separately from image creation
and mechanism emission. A successful component test does not replace this
original caller group.

Run the permanent groups with exactly one fixture selection:

```sh
HEPTA_HIA_SERVICE_VERIFICATION_COLD_REPORT=/absolute/current-cold.json \
HEPTA_HIA_SERVICE_VERIFICATION_EVIDENCE=/absolute/new/component-evidence \
python -B -m unittest tests.test_hia_service_verification_native \
  tests.test_hia_service_verification_builder tests.test_hia_service_verification_qualifier

python tools/qualify_hia_service_verification.py \
  --cold-report /absolute/current-cold.json --evidence /absolute/new/original-agent-48
```

The fixture alternatives `HEPTA_HIA_SERVICE_VERIFICATION_DEVELOPMENT_COMPILER`
and `HEPTA_HIA_SERVICE_VERIFICATION_DEVELOPMENT_MANIFEST` are mutually exclusive
with each other and the cold report. The caller driver instead has an explicit
`--development-compiler` alternative. That route still checks the full current
development source contract and never borrows the compiler's older cold report.

At the initial development checkpoint, 38 controlled seven-method cases,
10 call-lifetime observations, and one real public SQLite/proof/replay control
were completed on CPython 3.12. An additional 60-case mapping/generator group
first exposed eight real late-release differences; the successor HIA added an
onward release and all 60 then matched. Original failures remain evidence.
These observations are not the permanent full component, installed wheel,
original Agent 48, CPython 3.14, current-source cold, or whole-stack qualification.
No fixed limit on caller object size, integer width, mapping length, or public
program input is added by the coordinator. Existing fixed image/table extents
bound its generated private program, not the caller's opaque objects.
