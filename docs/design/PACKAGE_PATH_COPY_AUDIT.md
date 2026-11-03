# Package, Path, and shallow authority-copy audit

Audited the #631 source snapshot `2c2061366cf0c03c79fe305ac6f5787ebcbd42f5`. Local protocol probes ran CPython 3.12.14. Python 3.11 execution was unavailable during initial audit; the differences below were checked against official CPython 3.11.14 source. The new isolated profile's hosted workflow additionally runs durable call-formula, alias/cycle and cold-Path controls on both interpreter lines. A workflow declaration alone is not execution evidence; consult the exact-head run result.

## Decision

Approve a separately named, shallow-only authority-state-entry gate as the smallest next boundary. It may admit the 11 exact `LoadedProject.__dict__` entries before the existing `copy.copy`, without traversing field values. The fourth `Package` deepcopy and all `Path` reduction, parsing, reconstruction, and component work must remain explicitly excluded. This does not treat those values as atomic: they are outside this gate altogether.

## Actual ownership and protocol graph

`experiments/owned_loader/owner.py` first creates the public handle, shallow-copies `LoadedProject`, and then separately deepcopies `source_bytes`, `bindings`, `package_state`, and `package`, in that order. Every deepcopy receives one argument and has a fresh memo. Only after all four succeed is the `(handle, authority)` pair appended. A failure closes the owner and returns no new handle; earlier returned handles cannot reopen it.

`Package` has eight ordinary instance fields: root, name, version, entry, kind, source_root, dependencies, manifest_bytes. Canonical loader values are concrete paths, strings, an exact dependency dictionary, and bytes. The dataclass default also permits `manifest_bytes=None`. It has neither a custom deepcopy nor reducer. The inspected runtime reduces it as `(copyreg.__newobj__, (Package,), package.__dict__, None, None)`. `_reconstruct` recursively copies the class argument and state, creates the object through `__new__`, memoizes it before state copying, and updates its new dictionary. The generated dataclass `__init__` is not executed. Undeclared instance fields would also be copied by the ungated legacy operation.

The package loader caches by resolved root only after each package's dependencies have completed. Repeated dependency aliases therefore share the same Package. A root appearing in the active dependency stack rejects with `E_PACKAGE_CYCLE` before a graph returns. This source-level acyclicity is not a property of deepcopy: a synthetic Package self-cycle is copied successfully and points to the new Package. A future structural Package gate that rejects cycles intentionally admits a narrower class than the raw copier.

Aliases of Package objects, dependency dictionaries, and Path objects are memo-preserved within the fourth call. Equal but distinct Paths remain distinct objects after copying. Strings and bytes retain their original identities. Mutable aliases across different authority fields are not preserved across the separate deepcopy calls. The shallow copy initially aliases *all* eleven field values; its untouched public AST/report fields continue to do so after the four replacements.

## Measured cost, not heap bounds

The durable four-Package fixture has root aliases `a` and `c` to left, `b` to right, with left and right both referencing leaf. There are four unique Packages, five unique-package dependency edges, and seven Package occurrences when the DAG is unfolded.

For the fixture located immediately beneath `/tmp`, a profile of the genuine local `copy.deepcopy` function produced:

- 132 total deepcopy invocations: Package 6, type 4, dict 8, PosixPath 12, str 98, bytes 4.
- Two Package invocations are memo hits. Only four Packages and twelve Paths actually reconstruct.
- Expanded logical traversal counting Path as a terminal yields 132; expanded traversal additionally counting each Path component yields 220. The equality of the first number to actual invocations is accidental, not a copy-cost identity.
- Reusing root as source_root leaves twelve Path invocations but gives one Path memo hit, eleven Path reconstructions, and 129 total calls.
- Adding a synthetic Package self-edge preserves the cycle and yields 134 calls, with three Package memo hits.
- Sharing one dependency dictionary between left and right yields 130 calls, with one dictionary memo hit and one Package memo hit.

For canonical Package graphs whose state and dependency dictionaries are distinct per Package, actual deepcopy call count on this runtime is `1 + 18U + 2E + C`, where U is unique Package count, E is dependency-entry count summed over those unique Packages, and C is the total number of constructor component strings over distinct copied Path identities. This counts invocations including memo hits, not reducer, parsing, allocation, or native work. It also holds for a synthetic Package cycle under the stated shape, because memo prevents repeated state traversal.

For an unfolded, acyclic logical graph with Package-to-state-dictionary edges, each eight-field Package contributes 18 terminal-Path visits. The total is `18P + E_expanded`; adding components adds their unfolded occurrence count. A dependency descent adds three structural levels: Package, state dictionary, dependency dictionary. These logical units differ from Python call-stack frames, allocation counts, bytes, and CPU/time cost. An exponential alias DAG can have much larger unfolded cost than actual copying. Neither metric establishes a hard memory ceiling.

## Path is a protocol, not an atomic leaf

Local 3.12.14 `PurePath.__reduce__` returns its concrete class plus `self.parts`. Copy deepcopies each argument string and calls the concrete class. Its args tuple itself is not a separate deepcopy invocation. `parts` consults drive, root, and tail properties; missing parsed caches invoke `_load_parts`, which may join raw strings, split/normalize them, and intern components. The `Path` constructor allocates a fresh object and populates `_raw_paths`; it does not copy every cache.

A cold `Path('/a/b')` initially had only `_raw_paths`. Its deepcopy populated `_drv`, `_root`, and `_tail_cached` on the *input*, returned a distinct Path containing only `_raw_paths`, and performed four deepcopy calls (Path plus three strings). A fully parsed/hashed input also required four calls and returned the same cold shape. Equal call counts thus conceal different reducer work and input-cache effects.

Exact Path identity is not enough to validate this protocol. Writable slots may contain foreign objects or subclasses, and class properties/helpers are mutable. A foreign tail iterable can execute during tuple construction; foreign drive/root values can execute truthiness or addition. `_raw_paths` may contain strings whose sizes and count make lazy parsing substantial. Inspecting every slot without a version-specific consumption model overcounts unrelated caches and does not prove what reconstruction will execute.

The two supported interpreter lines require different policies. In official 3.11.14, reduction reads `tuple(self._parts)` directly, bypassing the public `parts` property and its `_pparts` cache. Path construction eagerly uses `_from_parts`, `_parse_args`, and the flavour parser; `_parts` is already normalized. In 3.12.14, reduction uses the public property and potentially lazy parsing, while reconstruction stores raw strings. The 3.11 source inspection is not a 3.11 test run. [CPython 3.11.14 pathlib source](https://github.com/python/cpython/blob/v3.11.14/Lib/pathlib.py).

## What a future Package gate would have to prove

An intentionally restricted first Package gate could accept only exact Package, exact eight-field state dictionaries, exact dependency dictionaries with string aliases and Package children, exact metadata strings, bytes/None manifest values, and the exact native concrete Path class. No dynamic reducers should be called to discover the graph.

It must separately pin Package copy/state/construction/attribute hooks, slot metadata, dispatch/reducer entries and reconstruction helpers, plus the concrete Path class and the precise reduction/property/constructor/helper chain used by its interpreter. For 3.12, one conservative candidate is to require already populated exact-string `_drv`/`_root` and exact-list-of-exact-string `_tail_cached`, so input lazy parsing is excluded rather than invisibly allowed. This still must account for component iteration/tuple creation and constructor work, and verify that actual normal-loader inputs satisfy the restricted state. For 3.11, validate the consumed `_parts` list and the eager constructor chain instead. Other platforms/interpreters fail closed until separately audited. This is a possible restricted design, not an implemented or validated complete policy.

String lengths, parsing/interning, temporary tuples/lists, memo bookkeeping, class/instance dictionary capacities, actual recursion, native resources and allocator behavior remain separate work unless expressly metered. Finite identity pins are not protection against arbitrary private function-code/global/class mutation, concurrent threads, tracing/signal callbacks, or garbage-collection finalizers. The already documented trusted-runtime stability assumption remains necessary.

## Shallow-only boundary review

For ordinary `LoadedProject`, observed reduction is `(copyreg.__newobj__, (LoadedProject,), graph.__dict__, None, None)`. Shallow `_reconstruct` does not deepcopy args/state. It creates a distinct object and dictionary, then transfers the exact original field pointers. It neither traverses nor normalizes the value graph. A self-reference remains a pointer to the *original* graph; a field pointing to `graph.__dict__` remains a pointer to the *original* dictionary. Neither becomes a reference to the clone.

Consequently, eleven admitted state entries per canonical graph is a truthful narrow unit. A huge list, cyclic AST, arbitrary object, Package, or Path stored as a field costs one transferred entry and receives no hook call merely from the shallow update. The gate must not recursively inspect those values or reject their cycles. State-root/type/schema and finite pin checks can be explicitly excluded from the entry metric. Invalid keys may reject before they are charged; charged entries need not be refunded.

Required finite pins: exact `modules.LoadedProject` identity; owned-loader copy-module/seam identity; original captured `copy.copy`; exact `_copy_dispatch` and reducer tables and their LoadedProject entries; `_reconstruct`; `copyreg.__newobj__`, `__newobj_ex__`, `_slotnames`; class `__copy__`, `__reduce__`, `__reduce_ex__`, `__getstate__`, `__setstate__`, `__getnewargs__`, `__getnewargs_ex__`, `__new__`, `__dict__`, `__getattribute__`, `__getattr__`, and `__setattr__`; no slots; only missing/None/empty exact-list slotnames. Instance state must be an exact dictionary with all eleven exact-string canonical field names and no extras. This rejects instance-level protocol shadows without invoking them.

The default object-reduction path also consults state/new-argument/slot metadata and can lazily create the empty slot-name cache. Validating just the eleven values or just `__copy__` would miss these surfaces. [CPython 3.12.14 object reduction implementation](https://github.com/python/cpython/blob/v3.12.14/Objects/typeobject.c).

## Legacy, callback, and terminal obligations

Keep an isolated legacy shallow seam calling the captured copier exactly once with one positional argument. Preserve callable capture before value evaluation, and explicitly delete captured callable then value in `finally`; test held exception tracebacks so the seam does not extend temporary lifetimes. Preserve copier/getter/setter exceptions and final append ordering. The new profile may add an entry checkpoint, finite pins, streamed charges, original copy call, and exit checkpoint, but no callback during inspection or between completed preflight and copy.

An entry checkpoint may mutate the input before inspection; that resulting graph must be the one validated. An exit checkpoint may fail after a successful shallow copy, with no handle returned and no refund. Direct private seam calls on a terminal context must reject too. This is not an arbitrary-injected-object API or an atomic snapshot guarantee.

Recommended regression cases include all eleven/below-eleven/cumulative budgets, negative/bool/non-int limits, bad root/state/key/hook/slot/reducer shapes, no unknown-object callbacks, original self/state aliases, huge payload invariance, before/after cancellation, captured-callable and argument cleanup under retained tracebacks, shallow-copy failure before map work, and the full existing 80-example/previous-profile gates.
