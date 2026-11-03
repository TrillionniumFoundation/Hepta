# Isolated shallow authority-state admission

This profile extends `experiments.authority_maps.Owner`. Normal production code and defaults are unchanged. All earlier experimental profiles keep their previous counters and behavior. The next stage is deliberately small: it admits the state entries transferred by the initial shallow authority copy, not all objects reachable from that state.

## Actual operation and semantic boundary

The owned loader first calls `copy.copy(graph)` on a `LoadedProject`, then independently deep-copies its `source_bytes`, `bindings`, `package_state` and `package` fields. The exact current `LoadedProject` dataclass has eleven ordinary instance fields. Default object reduction creates a new instance via `copyreg.__newobj__` and shallow-updates its new state dictionary. `LoadedProject.__init__` is not invoked. The original field values are not recursively traversed.

A small private `_authority_shallow(captured_copy, graph)` seam preserves the original one-argument call and captured-callable evaluation. Its legacy implementation deletes the captured callable then value in `finally`, preserving temporary-finalizer order even through retained exception tracebacks. The original private `_authority_copy` seam and four independent fresh deep-copy memos remain unchanged.

The new profile requires exact `LoadedProject` type, exact `dict` state and all eleven exact string field names, with no missing or extra state. It does not inspect any field value. This is necessary to preserve shallow-copy semantics:

- Shared field values remain shared and retain identity with their original values.
- If a field points to the original graph itself, the copied field still points to the original graph, not the new shallow instance.
- If a field points to the original state dictionary, the copied field still points to that original dictionary, not the copied state.
- Arbitrary aliasing and cycles inside field values are accepted without recursive traversal or cycle detection. The shallow operation never follows them.
- Unknown objects stored as field values cannot trigger their copy/reduction/iteration/attribute hooks through this shallow transfer. This says nothing about later operations on those values.

## Count and refusal semantics

`shallow_fields` defaults to 4,096 cumulative admitted state entries per owner and must be a positive exact integer. Each validated state key is charged once before proceeding to the next entry. Eleven permits one canonical graph; ten refuses before `copy.copy` runs. Twenty-two permits two; twenty-one refuses the second, retaining prior charges. No refund occurs after copy failure or post-copy cancellation. A failed operation leaves the owner terminal and does not append a new handle. Earlier completed handles cannot reopen that owner.

The root/type/state-size inspection and finite hook checks are not counted. Unknown keys may reject before charging that key. There is no root-object or recursive-depth unit. Field values of any size, such as a list of one item or one hundred thousand items, still contribute one field entry. These are not graph-node, byte, allocation, deepcopy-call or elapsed-time counts, nor a hard memory/CPU ceiling. State reconstruction, interpreter bookkeeping and downstream work remain unmeasured.

## Finite protocol policy

After an entry checkpoint, the profile checks original module/class/seam/copier identities and finite canonical copy behavior:

- `copy._copy_dispatch` exact dictionary identity and the `LoadedProject` entry;
- the shared reducer-table identity and target-class entry;
- `copy._reconstruct`, `copyreg.__newobj__`, `__newobj_ex__` and `_slotnames`;
- class `__copy__`, `__reduce__`, `__reduce_ex__`, `__getstate__`, `__setstate__`, `__getnewargs__`, `__getnewargs_ex__`, `__new__`, `__dict__`, `__getattribute__`, `__getattr__` and `__setattr__`;
- absence of slots and absent/None/exact-empty-list `__slotnames__`, allowing the standard lazy empty cache.

Hooks are checked statically against the trusted canonical class. Unknown root types are refused by identity without their attribute/hash/equality hooks. There is no caller checkpoint between state inspection and actual shallow copy. An exit checkpoint runs after the real copy and can reject without refund or publication.

The model requires ordinary private/runtime integrity. Concurrent mutation, signals, tracing hooks or finalizers mutating the inspected graph/class/runtime during the callback-free phase are outside its guarantee. It is not a sandbox, atomic snapshot or general arbitrary-object copy validator. Existing inherited parser/copy/transform/map policies still apply to their own operations.

## Package and Path remain excluded, not atomic

The fourth authority `deepcopy(package)` is still outside this new count. Package default reduction traverses its state, dependencies and aliases. Path reduction reconstructs its concrete class and carries path components; no valid claim follows from counting a Path as one atomic leaf.

The version distinction is material: CPython 3.11 uses `tuple(self._parts)` in `PurePath.__reduce__` and eagerly parses constructor arguments, while CPython 3.12 uses `self.parts`, which can lazily parse internal raw paths, and its constructor stores raw paths. A future Package/Path profile needs version-specific exact-state and hook policy plus explicit admission/exclusion for parsing, component tuples and reconstruction. The current stage neither rejects ordinary valid package projects to manufacture a bound nor silently relabels excluded Path work as covered.

The independent audit includes concrete DAG, cycle and real-copy instrumentation; see `PACKAGE_PATH_COPY_AUDIT.md`. Do not treat equal-looking visit/call counts as proof: one measured DAG happens to have both 132 expanded terminal-Path visits and 132 actual deepcopy calls, but component-expanded visits are 220 and actual memo behavior differs.

## Verification

Core and independently written tests cover exact/cumulative boundaries, no real copy before refusal, identity-preserved shallow aliases/self/state cycles, hooks/slot metadata, cancellation, terminality, old profiles and finalizer/exception behavior. Full repository examples retain 68 graph outcomes and 12 diagnostics. Hosted Python 3.11 and 3.12 bind exact candidate and frozen #631 identities, compare the 99 direct parser outcomes and 80 normal-loader outcomes, then run every prior and new control without skips or duplicate identities. Local focused testing does not substitute for the native consumer gate.

The gate contains 53 new controls: 23 core, 27 independent review regressions and three durable read-only Package/Path audit tests. That yields 485 focused and 617 full consumer controls. Any skip, duplicate identity, expected failure or unexpected success fails the gate.
