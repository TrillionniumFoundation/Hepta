# Nested default assembly scope candidate

The candidate changes two selection modules on exact source commit `4925e72d9f51f4dc3e8f4d1d2a7b24cce2f5772b` (tree `bc276bc832a7d6f04a21d63f55645859b75a01ee`). All 3,324 original paths, bytes, Git blob identities and modes were verified before the isolated hardlink copy. The two changed files were replaced before writing; the published source remains unchanged. The candidate tree is `aa867c45625e6b6e40961f0640eda5eeb3e664cb`.

## Change and boundary

`hia_assembly_front_selection.native_assembly_front_scope` still calls `_selected_admission()` and reads its prior scope at entry. The shortcut requires all of the following: the captured and prior assembly values are both `None`; the assembly ContextVar and its unscoped sentinel are their definition-time objects; the Core borrow callable is its original definition; the Core ContextVar and sentinel are original; and that Core ContextVar already contains a scope.

Under those conditions the original Core borrow contextmanager would only read the existing scope, yield, and return. The candidate omits that nested contextmanager and omits setting the already explicitly bound assembly `None` again. It retains the same outer `finally: _OWNER.set(previous)` on normal completion and errors. The new Core helper only observes its original ContextVar; it never resolves a lazy lease, reads an environment selector, or opens a source, image or manifest.

The first direct public call still performs admission and establishes the lazy Core lease. Internal calls made after assembly absence has been captured use the shortcut. A manual assembly `None` binding with no Core scope still takes the original path. Native assembly owners, a replaced provider, a replaced ContextVar or a replaced unscoped sentinel also take the original path.

The fixed assembly ContextVar defaults to `_UNSCOPED`, so `get() is None` proves that this original variable has an explicit binding. This matters because suppressing a first binding would change `copy_context()` membership. The actual controls cover a replacement ContextVar whose default is `None`, ensuring that it retains the original binding behavior.

All public facade and argument-carrier bytes remain unchanged. In particular, `carrier.pop()` still transfers arguments to the original callable before execution. No policy body, HIA source, image, ports module, shared continuation, error delivery code or public signature changed.

## Actual functional results

The local interpreter was CPython 3.12.14. Each reported result was executed against this candidate; prior pass records were not inherited.

| Group | Actual result |
| --- | --- |
| New public-call and scope observations on the original source | 14 methods passed |
| The same observations on the candidate | 14 methods passed; complete semantic observation payloads equal |
| Original capture and first-use controls | 9 methods passed, all 23 original observations retained |
| Original admission controls | 4 methods passed, all 7 observations retained, including the original one-second FIFO limits |
| Core-selected Program and Composite callers | 46 passed |
| Core-selected assembly callers | 18 passed |
| Assembly-selected assembly callers | 18 passed |
| Both selected, all three original caller modules | 64 passed |
| Neither selected, all three original caller modules | 64 passed |
| Original front registration source tests | 8 passed |

The four original caller/capture/admission scripts are byte-identical to the retained input scripts. The matrix and group supervisors keep the original 1,800-second limit. The original 3,273-file earlier front tree remained unchanged under its original guard. The new 3,324-file candidate remained byte- and mode-identical during the complete controls, and its 3,324-file published baseline was verified again at finalization.

The new observations cover selector changes during a captured `None` scope, capture at `__enter__` rather than contextmanager construction, unresolved Core leases, existing Core `None` and owner values, replaced borrow callables, replaced variable providers and their get/set effects, replacement sentinels, context membership, body mutations of both scopes, owner replacement and restoration, normal and exceptional exits under an outer handled error, and public argument finalization with a retained traceback and later explicit detach.

One structural count intentionally differs: a real `_parameters` call invokes `_items` internally. In that case the original enters the borrow contextmanager twice and sets the assembly ContextVar four times; the candidate enters it once and sets the assembly ContextVar three times. A direct public `_items` call retains one borrow entry and two assembly sets on both routes. These are call-count observations, not a throughput measurement.

## Inputs and qualification scope

The exact retained development images were used: Core verification 121,339 bytes and assembly front 216,532 bytes. Their complete bytes, manifests, HIA source bytes and identities are included in the evidence. Both HIA hashes still match the sources registered in the original front tests. This run did not compile new images and does not turn the retained compiler or images into current-source cold authority.

There was no second ABBA run, no cold run and no change to the original 180-second cold limit. No timing improvement is claimed. This candidate has not yet run on actual CPython 3.11 or 3.14. Its generated support metadata was not regenerated; the final source integration must regenerate its normal metadata and qualify that exact combined source independently.

The broader full-JSON provider, physical recursion and whole normalization boundaries remain open. This patch is limited to the already established default reference route and its nested selection scopes.

## Complete evidence custody

`evidence-r1/COMPLETE-RAW.zip` contains 212 members and 118,246,286 uncompressed bytes. Its complete ZIP size is 13,035,169 bytes and SHA-256 is `ee792b33b739abd5c57b6d44c5316f17f2e95322f6ca77b0a32ff1e26a670fd4`. Every ZIP member passed CRC, exact byte, size, SHA-256, Git blob and original mode checks. The complete original logs, reports, machine-entry traces, scripts, source delta and held inputs are retained.

The archive is preserved in 18 lossless Git parts, each independently created and fetched in full. The mount recipe points to those exact objects and to the source and result metadata. Unchanged baseline source bytes are recoverable from the published 4925 commit; both full source manifests and the exact two-file before/after delta are included. The original source-candidate packet is preserved with its authored-before-execution status, alongside the later actual result.
