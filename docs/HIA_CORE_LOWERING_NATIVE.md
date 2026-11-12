# Complete Core function lowering: explicit HIA owner

## Boundary and retained implementation

The selected v2 owner implements the complete 22 methods of `_Function` and the
five shared `_reject`, `_words`, `_bounds`, `_normalize`, and `_prologue`
helpers. Six lazy generators, including their real foreign iterator behavior,
are part of that control graph. `_native_globals` is an additional diagnostic
entry. The original function/helper business AST is retained independently and
checked against the immutable `hia_program_native_608.py.txt` fixture.

This is a component boundary. `_Emitter`, module coordination, system linking,
publication and the external Python operations requested by the HIA controller
remain explicit dependencies. No whole-backend, default activation, global
safety, universal semantic-equivalence or legacy-deletion claim follows from a
selected component or its finite tests.

The original PR888 implementation at
`acffa9262f31d073f8f0a6f0201eae201039f619` used a literal pool and 31 HIA units.
Its original source and failures remain archived. The current v2 runtime does
not load that protocol, host-evaluate its policy, or inherit its historical
12-component results. A single HIA image emits and losslessly expands its own
complete control table; the runtime does not import the authoring policy or
supply a host-generated table.

## Continuation and physical object custody

HIA issues every foreign primitive, exact request identity, native claim and
acknowledgement. A callback permission is consumed before the fixed transport
executes that callback. Reply loss or other unknown completion cannot authorize
a duplicate effect. Real caught exceptions leave the capture handler before
HIA-authorized temporary retirement and delivery of the exact exception through
the shared CPython mechanism. An original error traceback retains the original
named locals; it is not replaced with a fabricated native error.

The observed transport profile admits exactly CPython 3.12, 3.13 and 3.14 on the
already required Linux x86-64 ABI. It does not guess the behavior of later
versions or another Python implementation. HIA latches that word and rejects
continuation drift. Live temporary operands retire in birth-order LIFO first;
then named slots retire forwards for 3.12/3.13 and backwards for 3.14. Cell
references are dropped without clearing a cell still held by a separate lazy
generator. Non-cell temporary holes are skipped only after all temporary births
are zero. Independent-VM controls compare every complete source, output and
workspace buffer and surrounding canaries for all three explicit ABI words;
this is not a claim to have run three actual interpreters.

Facades prepare a native frame, transfer their formal parameter references, and
only then drive it. The five default helper facades and four public Plan
facades use ordinary fixed-arity calls with individual carrier pops so they do
not retain another argument tuple across the original call. Actual controls
include success and held-error paths, outer handled exceptions, weak-reference
observations and later diagnostic traceback detachment. No garbage collection
is used to hide an extra reference.

## Selected identity and complete emission

Core lowering and machine Plan are ordinary checker selectors. They are
separate from the explicit service-held owner inventory. A reviewed captured
registry identifies each exact capability type and scope hook. A captured
absence is different from no scope; a serialized dictionary or caller-supplied
held tuple cannot override an ordinary ambient selector.

An emission captures Code encoding/state/instruction owners, ELF, Core lowering
and Plan before invoking foreign program verification. Plan and Core admission
freshly read the manifest, source and executable, retain the actual immutable
mapping, and check readback. The exact capture persists across callback selector
changes. After scope exit, a new proof consumer re-admits the current selector
and rejects evidence for the prior selection. Tests use two valid mapped images
with different bytes, not just changed digest metadata. The alternate NOP-suffix
image is an identity fault control, not qualified compiler output.

Actual composition controls forbid retained Code, ELF, Function/helper and
selected Plan bodies; all six owners return actual machine frames. Initial
Plan absence remains absence even if a callback enables another image. Real
native-return interruption and ContextVar-set acknowledgement loss restore the
previous scope; they do not recycle uncertain continuation permissions.

## Generation and limits

Run `python -B tools/generate_hia_machine_plan.py` for the shared Plan image and
`python -B tools/generate_hia_core_lowering.py` for Core. The latter writes
`examples/hia_bootstrap/core_lowering.hiaasm`. The v2 table uses authoring-only
back-reference compression and an HIA decoder; the runtime performs neither
policy generation nor host decompression.

The original compiler limits remain unchanged: 128 functions, 1536 total
blocks, 8192 operations including terminators, 256 blocks per function, 2048
values per function, 16 parameters/arguments, 1 MiB source and 16384 lines. One
R3 source attempt exceeded the 8192-operation bound at 8206 and is preserved as
a real failure. Increasing the authoring match-search history, without changing
the represented policy or decoder, brought the actual source to 8168 operations.
No public Core or original resource limit was reduced to fit the compiler.

## Selection, build and development evidence

The production selector is `HEPTA_HIA_CORE_LOWERING_MANIFEST`; it is opt-in.
The strict builder is `tools/build_hia_core_lowering.py --compiler IMAGE
--cold-report REPORT --output NEW_DIRECTORY`. It admits the matching current
source cold report before creating candidate artifacts.

Tests use `HEPTA_HIA_CORE_LOWERING_COLD_REPORT` or, separately,
`HEPTA_HIA_CORE_LOWERING_DEVELOPMENT_MANIFEST`, never both. The evidence root is
`HEPTA_HIA_CORE_LOWERING_FIXTURE_EVIDENCE`. The six-owner development control also
requires `HEPTA_HIA_CORE_LOWERING_COMPOSITION_MANIFESTS`, an explicit JSON map
with exactly `machine_encoding`, `machine_state`, `machine_instructions`,
`machine_elf`, and `machine_plan` manifest paths. With a cold report those five
inputs are built through their current-source strict builders; development
manifests cannot override them.

The complete caller command is `tools/qualify_hia_core_lowering_callers.py
--cold-report REPORT --evidence NEW_DIRECTORY`. Development uses
`--development-manifest CORE_MANIFEST --composition-manifests DEPENDENCIES
--evidence NEW_DIRECTORY`. It retains all 51 machine and 50 Core caller IDs and
all original test methods, alongside the current complete component module.
Every original anomaly category, duplicate or missing ID and source/input drift
is a failure. The original 1800-second external supervisor is unchanged.

R2's 17+51+50 result is preserved under its exact source and CPython 3.12.14
retained-compiler development scope. The first R3 component run retained two
errors: an external counter assumed an image field on an ordinary Core VM, and
an old fixture expected forged image metadata to produce a new identity rather
than the mapping guard's actual rejection. The latter now requires ValueError
before zero business entries; the ordinary VM is recorded with its exact
source identity, never a fabricated native hash. The corrected R3 54-control
panel passed with 1,188,143 returned native frames and 3891 ordinary-VM frames.
These are functional development results, not matching-current cold or whole
product qualification. Actual Python 3.14 and complete new caller results must
be recorded separately; older successes and original failures remain intact.
