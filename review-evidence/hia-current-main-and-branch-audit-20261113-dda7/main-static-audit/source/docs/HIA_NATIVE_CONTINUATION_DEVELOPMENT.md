# Native multi-image continuation — development boundary

This is an unfrozen candidate, not a product default, a matching-source cold
result, or whole-runtime qualification. Source-bound build and installed
selection paths exist, but have not obtained their own full qualification.

## Implemented responsibilities

- `continuation_policy.hepta`: metadata admission, phase transitions, native
  status/frame checks, unit selection and internal multi-image handoffs.
- `continuation_packer.hepta`: exact input validation, ELF layout, embedded
  metadata/image placement and the relocations in the fixed transport template.
- `hia_continuation_syscalls.S`: fixed Linux x86-64 mapping/protection and
  stdin/stdout effects. The adapter does not choose a unit, mode, frame extent,
  arity, continuation or internal branch.
- `hia_native_continuation.py`: explicitly hosted object-effect peer. It invokes
  the existing eighteen primitive effects only when requested by HIA; neither
  `LoweringSession.step` nor `handoff` schedules the execution.

The HIA packer accepts at most 128 images and 1,024 modes, each with at most
four bound arguments. Each individual image, unit workspace and output remain
bounded to 1 MiB. Aggregate pack input/output are bounded to 64 MiB; that does
not enlarge the existing compiler or byte-observer 1 MiB profiles. A separate
bounded pack invocation must transport a larger aggregate input.

The executable itself uses no files, child processes, dynamic loader, libc,
runtime assembler or runtime Python. **Its external object peer still does.**
Python object semantics, exceptions, imports, arbitrary callbacks, SQL and all
ordinary product-default and installation responsibilities are not replaced by
this prototype.

## Execution identity correction

Ordinary-file descriptor pinning alone was insufficient: the same inode could
be rewritten after admission and before exec. The independent original failure
is retained outside the source tree. Post-run rejection did not undo execution
of those changed bytes and was not counted as a successful defence.

The current peer retains ordinary-file checks (type, owner, private mode, link
count, size, SHA and pre/post identity). It additionally copies the admitted
bytes into a private kernel memfd, fully seals write/grow/shrink/further-seal
changes, verifies its actual bytes and extent, and executes that immutable
descriptor. The original ordinary source is checked again after completion.
There is no mutable-file or unsealed-execution fallback.
Ordinary selected owners keep their original outer supervision, with no new
shorter implicit per-call wall limit. Explicit low-level test deadlines remain
optional and cannot enlarge the original outer caller/qualification limits.

## Actual development evidence

The external `continuation-development-build-01.json` records real compilation
with the explicitly older v86 compiler. It is not this source tree's cold
admission. The latest `continuation-native-development-04.log` records ten
executed tests and zero failures/errors/skips, including:

- Independent Core VM execution of the scheduling policy.
- All retained ledger differential cases with host scheduling forbidden.
- Real multi-image internal handoffs, not only one-image success.
- ELF packing, malformed input, buffer canaries and dirty 64-bit result refusal.
- Partial packet/EOF, extra arguments and closed-output handling.
- Empty PATH plus actual syscall tracing of no file opens or child launches.
- Ordinary-file mismatch, writable-mode and hardlink refusal.
- Actual same-inode source rewrite at exec time: only the original sealed bytes
  execute, all attempted sealed writes/truncation/growth fail, and changed
  ordinary source still rejects the invocation.

Pre-edit full source-byte/mode archives and the original execution-identity
failure remain external evidence. Existing product guards, caps, sources and
failed qualification reports were not rewritten as successes.

## Remaining integration

The candidate now adds an independent four-resource role and updates complete
package-copy fixtures without enlarging existing roles. A cold-admitted builder
and source-bound outer bundle reuse the existing execution-observation selector,
without a second ambient selector. Ordinary source, image, runtime and child
bundle drift reject before fallback. The current sixteen-test development gate
includes a real installed wheel, empty PATH, no authoring imports, the retained
ledger disabled and the old host scheduler forbidden. A missing test import in
the first installed-wheel run remains an original failed development attempt.

The unfiltered thirteen original runtime modules (132 tests) also passed with
native scheduling, all three modes and actual native handoffs observed, the old
ledger and host scheduler forbidden, and the original 180-second owner intact.
The first attempt correctly failed on two Cargo skips; real pinned Rust and
offline dependencies were supplied before the complete zero-skip run.

Before promotion, freeze and perform this
source's own cold, complete native workflow and full regression. Do not inherit
the older compiler's or v87 fixture repair's acceptance.

## In-process transport integration (unfrozen)

`continuation_inprocess_packer.hepta` reuses the identical HIA scheduling policy
but packs an immutable private RX container instead of an ELF process. A fixed
six-argument assembly adapter invokes the HIA-selected image; it does not choose
phases, modes or internal handoffs. The 1,118,208-byte aggregate workspace is
4 KiB event storage + 64 KiB policy state + the unchanged 1 MiB unit workspace.
The separate aggregate image bound is still 64 MiB. Neither existing byte nor
compiler inputs, outputs, primitive counts or bound arguments are widened.

`hia_native_continuation_inprocess.py` only transports primitive requests into
the same hosted foreign object semantics. Per-session input is a read-only
page between inaccessible pages; private output/work buffers have canaries.
The terminal HIA phase is committed before returning; an actual replay must
refuse. Sessions close on every allocation/protection/effect failure. The
source-bound in-process schema has a fixed image path and pins all four
resources and all three transport/selection runtime sources. Warm selection
rereads every original bundle/source/image identity before reusing an owner.
No runtime authoring imports or child launch are required. All foreign objects,
exceptions and primitive effects remain hosted; this is not a native object VM.

The public builder admits only this exact source tree's own cold and produces
both transports. Explicit older-v87 development compilation is not current cold
admission. Before any frozen qualification, run both the original 132 callers
and the original no-child/LLVM compiler caller scripts without changing their
bodies or weakening their process prohibitions. The original subprocess gate
is retained as well. No product default or production service is switched.


### Five-family composition and development status

The explicit in-process schema now supports Core Function, Emitter, byte-wrapper,
ELF object and execution-observation families through their original selectors.
Each kind admits only its own original source/ABI/image bundle; cross-family
outer manifests refuse. All original implementation identities remain prefixes
and additionally include the scheduling container identity. Cache bounds remain
three source-bound owners per family, not a shared unbounded namespace cache.

The development gate executed 24 component/resource checks and both complete
132-test runtime caller runs (subprocess and in-process). Both were zero-skip.
Four ordinary in-process owners also executed both unchanged original no-child,
no-LLVM compiler scripts under their original 20-second limits and the 180-second
outer owner, with all four old controls and host run/step/handoff forbidden.
The first newly added coverage suffix incorrectly required every minimal script
to hand off inside every family. That failed attempt is retained: the minimal
object script legitimately normalizes byte-wrapper policy without a handoff.
The corrected additional coverage requires all four owners to actually run in
each original script, and actual handoffs in every family across the two scripts.
No zero counter is converted into a fabricated handoff. The unchanged original
bodies and deadlines were never relaxed. Original reference CLI compatibility
is still tested, not described as a native CLI rewrite.

The aggregate development evidence remains external and explicitly uses an
older v87 compiler. Current source has not yet obtained its own cold/full
qualification. Native object semantics, persistence and defaults remain open.


## Worker custody correction (v89 successor)

The frozen v88 witness actually executed 26 native scheduler sessions / 348
unit calls inside an unselected worker scope before its original terminal pin
check rejected an added selector. Terminal refusal cannot undo that execution.
The original frozen source and failure evidence are retained, not rewritten.

Current v1/v2 worker capsules do not register the five scheduler families.
They now refuse before general loading, pool execution or foreign effects.
Captured owners, pre-created sessions and cached in-process/subprocess engines
cannot bypass that refusal. A refused held session is closed. Standalone
explicit scheduling outside worker scopes remains available. The already
registered v2 worker-report/wire pair keeps its original behavior and guards.
This is refusal closure for an unsupported scope, not an implementation of
five-family worker support. A separately specified, fully transitive pinned
worker capsule is still required before enabling those families in a worker.

The new outer runtime identity also pins the canonical worker authority and
primitive bridge sources (five runtime files total); no guard can be silently
swapped while retaining the former three-file identity. All 178 HIA sources
and all existing caps/primitive counts remain unchanged. A v88 source-workflow
failure also found a redundant production-module entry in bootstrap-only
SOURCE_FILES. Removing that redundant entry does not drop the module from
complete source custody: every production Python module is included by its
separate automatic inventory. The original release-inventory assertion remains.
No v88 cold/native/full was started after these findings; its 525-test failure
and childless-waiter retirement records are preserved externally.
