# Explicit HIA UNPACK companion for Core lowering

This candidate moves the complete fixed-arity unpack decision sequence out of
the retained Python opcode-14 branch and into a separate HIA image. It is an
experimental, explicitly selected composition. It does not replace the CPython
object runtime, select a default backend, or establish current-source cold or
whole-stack qualification.

## Ordinary entry and identity

`HEPTA_HIA_CORE_LOWERING_MANIFEST` still selects the existing Core owner and its
unchanged 39 images. When that owner is admitted,
`HEPTA_HIA_CORE_UNPACK_MANIFEST` may select one additional companion. No Core
selection means there is no Core opcode-14 boundary to replace. A missing or
invalid explicitly selected companion raises at admission; it does not select
the old unpack branch as a fallback.

The existing Core ContextVar captures the selected companion, including an
explicitly absent companion, for the complete ordinary emit scope. Changing
either environment variable during that captured scope does not replace its
owner. This is the same scope boundary used by Function and Emitter selection.

The companion manifest binds its HIA source, ABI JSON, primitive bridge,
selection bridge, executable bytes, and compiler SHA. The compiler SHA must
match the admitted Core bundle. The implementation identity also binds the
transaction shim's exact literal bytes and the admitted interpreter ABI. The
backend's existing complete bridge dependency list retains all its previous
members and adds the two UNPACK Python modules.

Every selection re-reads the current HIA/ABI/bridge/selection inputs and the
manifest. A cached, immutable executable mapping is retained for the same
complete cache key, as with Core bundle selection. A new manifest key forces
image admission. This does not claim future filesystem immutability or make
private Python owner objects tamper proof.

## The policy owned by HIA

The outer Core protocol is still `HIALOW02`; its literal protocol is still
`HIALIT01`. Its 36 modes, 39 images, ABI bytes, and existing caller denominator
remain unchanged. Outer opcode 14 consumes its one observation permission
before it reaches either implementation. The companion performs all its
internal effects within that one outer observation. Only the final tuple's
items enter the outer Core handle registry.

The companion's `HIAUNP01` state machine chooses iterator acquisition and the
conditional rewrite of a noniterable TypeError; each requested next operation;
the exact n+1 cardinality probe; version-specific too-many-value diagnostics;
the construction and transfer of the result tuple; and normal/error cleanup.
The release plan drops the extra value, releases gathered values in reverse
order on failure, and releases the iterator at the original selected point.
There is no Python `list(iterator)`, complete host unpack loop, length hint, or
eager scan in this selected path. Supported arities remain one through four.

The image requests one leaf operation per continuation. The bridge reports
raw facts, executes that leaf, and moves an explicitly identified reference
cell. A small fixed transaction shim restores the already-owned raised-error
reference, executes exactly one HIA-selected C-API operation, captures the
resulting error reference, clears the error indicator, and returns to Python.
Its machine code contains no unpack loop, cardinality decision, cleanup plan,
or diagnostic-selection policy. GIL retention, ABI layout and exact shim
bytes are checked before the first operation.

The shim is nevertheless a **transitional CPython/C-API hosted dependency**.
The raw object model, iterator operations, tuple allocation/insertion, error
formatting, reference count effects, and foreign methods remain implemented by
CPython. Completing the whole HIA object runtime requires replacing these
primitives as well; moving their scheduling into HIA does not close that task.

## Runtime and boundary scope

The current explicit ABI admits CPython 3.12.14 and 3.14.4 on GIL-enabled Linux
x86_64 LP64 without `Py_TRACE_REFS`. The two versions have distinct HIA-chosen
too-many-value diagnostics. Other Python versions or object layouts refuse
this companion; the existing unselected backend remains independent.

The reference owner remains the complete, separately preserved pre-change
bridge. `_host_unpack` contains its original fixed-arity assignments and error
branch. Selected qualification poisons this complete helper and records any
entry as a failure. The ordinary Core and UNPACK implementations do not import
or execute the authoring policy to implement their selected decisions.

Still open are arbitrary private-state changes, C extensions that return an
invalid result/error combination, garbage-collection/allocation timing,
reference-count inspection, exact traceback-frame equality, interpreter
shutdown, and arbitrary concurrent scheduling. A failed native abort or an
unrecoverable infrastructure/resource error is retained as an open cleanup
failure; the bridge does not silently switch to a Python release loop.

## Build, installation, and qualification

`tools/build_hia_core_unpack.py` performs matching-source cold admission before
creating its output directory. All four runtime inputs must occur with exact
digests in that complete cold source closure. Compiler, source, cold report and
image bytes are checked again after the original bounded compile stage. This
strict builder must reject an old cold report for this new candidate.

The wheel contains two new resources, `core_unpack.hiaasm` and
`hia_core_unpack_abi.json`. The installed branch of the existing Core component
method retains its original ID and assertions and, when the companion is
explicitly supplied, adds a real `-I -S -B`, empty-PATH child. That child verifies
all installed Python and resource bytes, poisons the complete old unpack
helper, records actual companion returns, and refuses both changed and missing
HIA/ABI resources before restoring and rechecking their identities.

The new complete-callers driver delegates the unshortened original qualifier:
15 Core component methods, 51 machine callers, and 50 Core callers. It does not
offer development group splitting. The original whole 116 gate remains one
180-second owner with its original three-second termination grace. The original
39-image ledger stays separate from the companion's actual-return ledger.
Attempts, normal outer returns and propagated exceptions are distinct; a legal
semantic rejection is not required to return successfully. An admitted native
step is counted only after the actual image and output framing return.

Eight additional composition methods check retained/source independence,
ordinary output and metadata, once-only outer permission and foreign order,
scope capture, stale or mismatched admission, companion identity, and closure
after a real native return followed by an exception. These supplement rather
than replace any of the 116 original methods. The earlier four shim controls
and six finite native controls remain separate evidence with their own sources
and runtime version.

The first experimental source/caps, corrected shim and finite image results
are preserved under the experimental evidence history. They do not establish
that this ordinary overlay, its installed path, CPython 3.14.4, or the complete
116 gate passed. New execution reports must bind this exact candidate and keep
every first failure and every unchanged original budget.

## Source regeneration and interpreter scope

The source workflow keeps the original 59-generator order, bounded read at
position 60, and UNPACK at position 61. The UNPACK author's no-argument mode
regenerates only its canonical HIA source; explicit `--output` retains its
create-only behavior. The two existing source methods are included in the
source workflow without changing any of the 116 original caller methods.

Both Python selections in this candidate's `hia-core.yml` are fixed to
CPython 3.14.4. The bridge admits only its explicit 3.12.14 and 3.14.4 profiles;
3.14.10 remains unsupported. Earlier results from 3.14.10 keep their original
source and interpreter identities. The independent development capsule is
4 shim methods, 6 finite methods, 2 source methods and 6 ordinary native
composition methods, followed by the original complete 116 under a separate
180-second owner. It does not replace a future matching-cold UNPACK gate or
the full-harness owner requirement. The existing 30 compiler-owner gates remain.
