# General Core function lowering: development work in progress

This branch holds an unqualified authoring candidate for moving the complete
`_Function` policy in `hepta.hia_program_native` into HIA. It is not integrated
into the ordinary product entry. The first actual authoring run checked the
original 22 methods and five helpers, then generated one literal-pool unit before
the first control unit failed the unchanged Core type verifier. Revision 3
corrects only the internal helper return types and remains unexecuted.
No native compilation, Core VM, component/caller result, installed owner or
matching-source cold qualification exists for this Core candidate.

## Exact source and proposed boundary

The independent base is commit
`608157e52b0b94e0d294f6b99c4e809869f183aa`, tree
`e7c29a60796a1a78946a2c667aa80df86529e532`.
The complete original 47,839-byte module is retained at
the `tests/fixtures` directory, named `hia_program_native_608.py.txt`, as the independent oracle.

The proposed owner is all 22 `_Function` methods and the five helpers
`_reject`, `_words`, `_bounds`, `_normalize`, and `_prologue`.
It includes frame and slot assignment, edge/call staging, register versus slot
selection, all 50 currently supported Core opcode branches, range and allocation
control, chains, block and terminator order, trap emission, and function reports.

The authoring policy is copied from that exact source; a restricted authoring
compiler lowers its control into explicit continuation instructions. The later
generator is intended to render those instructions as HIA. Unsupported syntax
must refuse generation. Runtime must not execute or import this authoring policy,
compiler, or oracle. This is a source-translation design, not a table of
precomputed program outputs.

The original `_Emitter` module policy, verifier, machine-plan provider, wrapper
construction, native Code primitives, ELF writer, linker, filesystem operations,
and arbitrary object effects remain outside this proposed owner. Code state,
encoding, and ELF are independently owned work and are not modified here.

## Intended observation discipline

HIA will choose every control branch and the order of individual primitive
observations: attribute/item binding, calls, iteration, truth and rich comparison,
arithmetic, packing, and writes. Actual Python objects and their foreign hooks
remain observations, including independent `__ne__`, evaluation order, exceptions,
and reentrant effects. A mere Python wrapper around the former lowering decisions
would not satisfy this scope.

A source-bound explicit selector, immutable selection scope, versioned one-shot
continuation protocol, and finite HIA unit split are planned. The existing
compiler limits, 64 KiB frame limit, 16 MiB text limit, original caller
denominators, and 3/5-second product budgets must remain unchanged. No performance,
ABI, lifetime, or foreign-domain equivalence claim is established by this static
checkpoint.

## Custody and execution status

The local executor became unavailable during a write. Its last filesystem
mutation acknowledgement is unknown. These files were recovered from retained
tool-call text and the canonical original module, then saved through Git APIs.
The earlier policy reconstruction matches its observed 21,778-byte size, but its
original local hash is unavailable. It is explicitly not presented as a
byte-verified restoration of that local file.

The current candidate additionally uses the original frozenset kind for
`BYTE_RESOURCES`, and refuses a reducer shape lacking an explicit default.
These are new static edits. The earlier requested source text is retained
separately under `experiments/hia_core_lowering_20261111/static-wip-r1`; no prior observation is relabelled.

The first remote authoring request was never dispatched. The corrected r2
request ran once on the pinned CPython 3.14.4 executable, with the original
180-second guardian. All four new Python files passed syntax checks; the complete
22-method class and five helper ASTs matched the retained oracle. It compiled
28 modes into 1,922 control instructions with at most 510 object slots.
The complete 3,925-leaf base and 3,936-leaf candidate byte/mode inventories
matched before and after the attempt.

Of 32 planned HIA units, the literal pool passed the public Core roundtrip.
The first control unit failed with `E_HIA_TYPE` because a `u32` helper result
was compared to a `u64` literal. The run finished HOLD after 22.007921965 seconds;
the guardian naturally reaped the leader and observed ECHILD without timeout or
live-child killing. The original report and logs are preserved in commit
55e39d6a65ff848ee7596c548ddbf98e391bcbdf under the remote-authoring-r2 terminal
directory. No native compiler or product test ran in that remote request.

Separately, seven earlier pushes to this development branch triggered the old
GitHub workflow. Those runs failed and are not native qualifications. In the
latest run, 43085426169 at exact head 55e39d6, the source job rejected a document
reference and the cold command rejected source-closure drift before writing a
cold report. Its job logs and exact run identities are preserved separately.
Future evidence and unexecuted source checkpoints use `[skip ci]`.

## Static revision 2

The renderer emits HIA control units with 64 finite control instructions per
unit, and a separate HIA-owned typed literal pool. The HIA program chooses
cross-unit handoffs using its own program counter. The bridge decodes only the
versioned literal framing and primitive requests. It binds all 22 original
method signatures to native invocations; the ordinary product selector and
source-bound loader have not yet been added.

The 128-byte request/acknowledgement protocol carries a sequence, phase, mode,
object handles and raw truth/iteration observations. Private state remains HIA
owned. Foreign permission is consumed before the effect; BaseException in a
native step, post-call framing or foreign effect permanently closes the session.
No claim about that protocol is validated by this unexecuted source.

The intended initial domain retains normal module and built-in bindings.
Monkeypatching the five private helpers or the reducer built-ins is not silently
presented as equivalent: helper names always select their HIA implementations,
and sum/max/any generator control is compiled into HIA. Literal object identity,
arbitrary stack/traceback introspection, foreign finalizer timing, recursive
resource exhaustion, and tampering with private registries are also unproven.
Normal public method argument binding, dynamic receiver attributes, independent
rich comparisons, module value observations and actual Code effects remain
explicit compatibility targets. Remaining limits must be reported rather than
removed by an implicit retained-owner fallback.

Source revision 2 also refuses value-context chained comparisons, which are
absent from the current policy, rather than incorrectly normalizing arbitrary
rich comparison results into booleans. Original source and all prior unknown
write records remain unchanged in history.

## Revision 3 type correction

Internal startup, instruction-group and dispatch helpers now return `u64`,
matching the existing word-sized status comparisons. The public lowering and
literal-pool entries still return `u32`. Every defined internal status remains
one of 0, 1, 2, 4 or the unchanged ABI refusal value; the final entry conversion
does not add an admitted status. This is an authoring type correction, not a
change to the verifier, compiler caps, packet, phase sequence or policy IR.
The corrected ca871 source was generated once on the pinned desktop CPython 3.14.4:
all 32 public Core roundtrips and all original caps passed in 65.0857341099 seconds.
The original 3,925-leaf base and 3,937-leaf candidate stayed byte/mode identical.
The guardian naturally reaped the process and observed ECHILD; it did not time out
or kill a live child. Compact raw results are preserved in 9efc2fb. No native
compiler, VM or product test ran in that source-only request. The original failing
source and the first unknown local write remain preserved.


## Ordinary entry integration draft

The new integration source is a separate, unexecuted revision. It does not
inherit a native or product pass from the source-only r3 run. The explicit
environment selector is HEPTA_HIA_CORE_LOWERING_MANIFEST. The ordinary backend
entry captures either its admitted 32-image bundle or the absence of a selection
for the entire emit, including reentrant emission. Subclasses of the retained
private Function class keep their existing behavior.

The five shared helpers use the selected HIA owner within that captured scope.
Outside it their earlier public-admission and target-error behavior remains
hosted. Direct selected Function invocations resolve their five helpers through
the HIA owner. The original 22 method bodies and five helper bodies remain
separately available for AST and semantic comparison; a selected load failure
does not call them.

The loader reads the installed ABI, every HIA unit source and every unit manifest
on selection. It binds one compiler identity across all 32 images and caches
immutable mappings as a complete bundle. The backend implementation identity
also binds both new Python bridge modules, the ABI, all 32 source hashes, the
bundle hash and all actual image hashes. A changed unit-manifest key requires
fresh image admission. An unchanged warm key retains its already immutable
mapping; changing a disk image alone does not rewrite that mapping.

The strict builder requires a successful matching-source cold report before
creating its output directory. Development use of the old 0e09 compiler is
separate and cannot authorize that production builder. The new component gate
declares four source methods and eight native methods. The caller gate keeps the
original five machine modules and their 51 identifiers, plus the four existing
general Core modules and their 50 identifiers. All loaded and executed
identifiers must match, with zero errors, failures, skips, expected failures or
unexpected successes. No existing test or original time limit is changed.

The installed control builds a real wheel, compares every installed Python file
and declared resource, and invokes ordinary emission in an isolated child with
no site initialization, empty PATH and an authoring-import refusal. These are
unexecuted controls until a new result explicitly records their actual execution.

The 18 primitive kinds remain hosted observations, including object allocation
and storage, arbitrary precision arithmetic, interpreter builtins and actual Code
methods. Python generator objects are not created for HIA reductions; arbitrary
foreign StopIteration/PEP479 behavior and monkeypatching reducer builtins are not
included in the ordinary verified-builtin claim. The existing arbitrary
recursion/resource, finalizer and introspection limitations also remain.
No retained implementation is removed and no default selection is enabled.

## Instruction owner integration boundary

The ordinary-entry draft additionally preserves the exact 7186dee24f33173c25f2246a6dfe15eeda053992 machine-state and instruction-control source. The backend identity includes hia_machine_state_native.py, hia_machine_instructions_native.py and hia_json_wire_native.py alongside both Core-lowering bridges. The existing native_encoding_scope implementation and its independently selected Code owners remain unchanged. The complete original Function and helper oracle is still the exact 608 source; these bodies did not change in 7186. This source merge does not inherit native/caller qualification for the new composition. Its private v72 contract definition still requires actual regeneration and source-bound validation before any cold-built claim.

## Original-source recovery and execution accounting

The 32 original r3 HIA files were recovered from the same e86 custody archive:
2,218,343 compressed bytes with SHA256
400f59e67817fb9a6fc3ce744b4bb93c64957d932272880af7bb382325a2c450.
All 58 members were independently checked against their original byte, size,
mode and uid/gid records. The 32 source files total 5,546,188 bytes and were
published without regeneration in 028058563592a853c7b4eeea145b35f5545aaa94.
The original read timeouts, partial transfers and subsequent complete recovery
remain in that commit's custody history. This establishes source custody only.

The selected-caller producer distinguishes invocation attempts from ordinary
method returns and actual native step returns. Its native_step_returns ledger
records the group, original mode and mode number, actual control-unit index,
unit name, admitted image, ABI and bundle digests, returned status and count.
A row is added only after LoweringSession.step completes the actual HIA entry
and admits its output frame. Status1 can request a later rejection primitive;
it is not a claim that the method or product succeeded. The original _reject
method therefore need not return normally. All 27 public policy modes must have
actual native step returns across the complete 12 + 51 + 50 run, and each of its
three groups must have actual returns. The unchanged 28th private diagnostic
mode is outside that 27-mode requirement.

Control-unit index 0 denotes core_lowering_000. The complete bundle includes the
literal pool at bundle index 0, so a control unit's bundle_image_index is its
unit_index plus 1. All 32 source/image bindings remain independently admitted,
including the pool.

The producer separately retains before/after original bytes for the caller
bundle and the component's fresh qualified bundle. It captures the latter after
unittest has performed its one real setUpClass, before the first method, without
calling setup again. Cold mode requires both actual build.json receipts and
both sets of 32 images/manifests. The original machine and general Core groups
use the caller bundle. Development mode is explicitly separate and may reuse
the selected development bundle for the component; it never claims a fresh
cold build. These revised producer controls have not yet been executed.

### Development phase isolation

The caller driver accepts `--development-group component|original-machine|original-core` only with an explicit development manifest. A supplied cold report rejects that option before creating output. The selected group still loads and executes its entire original 12, 51, or 50 method set, preserves all five anomaly refusals, and records the same native return and input-identity observations. Its successful status is `DEVELOPMENT_GROUP_PASS`, its scope is `EXPLICIT_DEVELOPMENT_GROUP_ONLY`, and it explicitly does not claim complete three-group qualification. This permits three independent process owners with the original 180-second boundary each. A separate development aggregate must bind all three reports to the same candidate and original compiled bundle, require all 113 original methods and the 27 public modes in the union of actual native returns, and preserve every phase's original receipt. The ordinary default and cold invocation still require all three groups in one report and retain their existing complete-coverage requirements.

The ABI contains 28 modes: 22 `_Function` methods, five shared helpers, and the independent `_native_globals` fixture mode. The 27 public product control modes remain the required cross-group union. The existing component literal-owner method separately invokes mode 28 and compares its entire returned structure with the original constants; the component and complete reports additionally require its actual HIA step-return observation. It is not silently removed from the ABI or relabeled as an ordinary product call.

## Current integration candidate

This independently identified successor composes the selected Core owner with the admitted machine encoding/state/instruction and machine-plan boundaries. The original Function methods and helper ASTs remain unchanged. ELF selection is deliberately not imported from the incomplete upstream ELF candidate. Sources use `.hepta`. This composition has not yet passed its own source/native/cold/caller qualification. Hosted object primitives, default activation, the Emitter, runtime and whole-product retirement remain open.

### Current candidate development observations

The 32 checked-in HIA units were actually regenerated with the original 180-second process owner, then compiled using an explicitly reused older-source v78 compiler. This is development construction, not current-source cold admission. The complete three-group development producer passed all 12 component, 51 original machine and 50 original Core methods (113 total), with all five anomaly lists empty and the original methods unchanged. The external original 180-second owner completed naturally in 136.673636510 seconds. All 27 public modes had actual admitted HIA step returns; the private literal-owner mode was also observed. The report distinguishes invocation attempts, admitted native step returns and ordinary method success. The original Function/helper owners were forbidden in selected ordinary calls.

These observations do not qualify the new source closure, default activation, the Emitter, arbitrary Python primitive execution or the whole product. A separate frozen source, own cold replay, exact native workflow and retained full regression remain required. Original upstream WIP and failure observations above are retained as history, not relabelled as passes.
