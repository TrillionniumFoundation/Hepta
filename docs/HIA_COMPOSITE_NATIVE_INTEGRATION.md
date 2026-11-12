# Selected complete nominal elaboration

The v64 integration joins five explicit HIA owners at the public nominal
elaboration boundary. It is based on v63 commit
`31d81594997cfb6cce5ab62ea5aaba3bb7757af1`, including its public session cleanup.
It does not activate the native route by default, delete reference owners, or
qualify the entire HIA language, installation, compiler or Agent stack as native.

The generated support contract is a source identity and support declaration.
Actual source reproduction, cold compilation, retained tests and installed
execution remain separate evidence. A development build cannot satisfy the
matching-source cold gate.

## Ownership and selection

| Owner | Explicit production selector | HIA images | Complete semantic responsibility |
|---|---|---:|---|
| Types and signatures | `HEPTA_HIA_COMPOSITE_TYPES_MANIFEST` | 1 | Nominal declarations, resolution, layouts, partial records, parameter and task signatures, returned-loan origins |
| Task helpers | `HEPTA_HIA_TASK_HELPERS_MANIFEST` | 1 | Start, poll, cancel, join and close helper Core generation and associated counter/cache state |
| Functions | `HEPTA_HIA_COMPOSITE_FUNCTIONS_MANIFEST` | 5 | Ordered block and SSA admission, all instruction and terminator lowering, cleanup and complete Core function construction |
| Constructor | `HEPTA_HIA_COMPOSITE_CONSTRUCTOR_MANIFEST` | 2 | Document and function inventory, ordered signature construction, effects, returned loans and unused concrete task checks |
| Outer module | `HEPTA_HIA_COMPOSITE_OUTER_MANIFEST` | 2 | Ordered function requests, expanded inventories, late limits, exports, schema and complete Core module construction |

The selected constructor requires native types. The selected function owner
requires native types and helpers. The selected outer owner requires native
types, functions and helpers. Each manifest binds all its HIA sources and image
bytes, including declared dependency source identities. A selected invalid or
incomplete owner refuses; it cannot fall back to the Python reference method.

The complete ordinary route selects all five owners. The host retains bounded
input copying and snapshot custody, source/image binding, fixed typed service
forwarding, and materialization of HIA-issued output. It does not plan nominal
admission, choose lowerings or synthesize Core instructions on this route.
Final primitive Core verification, backends, build and installation, default
selection and durable Agent authority remain distinct owners.

The original constructor and outer method bodies remain available as
`_reference_initialize` and `_reference_lower`. Other reference methods retain
their bodies. This supports independent comparison and the unchanged default
route. Their existence is an explicit remaining deletion condition, not a
claim that an unused Python body has already been removed from production.

## Order, state and custody

Constructor HIA requests parameter admission, return resolution, origins and
task protocol checks in the original order. All return descriptors are resolved
before the stored-loan gate. It returns the committed registry, origins and
stage on semantic refusal as well as success. Types remain same-session issued
identities. Function HIA preserves both passes, fresh names, consumed values,
helper cache, and partial state on the first refusal.

Outer HIA requests complete functions in document order. It counts generated
helper functions and Core blocks, applies the original expanded-inventory gate
after lowering, then validates and sorts exports and chooses the Core schema.
Its typed lease borrows the completed function IR and issued helper metadata.
The actual helper response header is checked against the helper workspace's
error, serial, first name and payload extent, including reserved words and
capacity, before a result handle can be published. Opaque result handles and
source offsets occupy disjoint namespaces. Invalid protocol permanently poisons
the invocation.

The retained contract is the complete public-admitted, detached nominal
document. A direct private function call with a substituted or mutated member
is rejected by exact transport custody; arbitrary replacement of a private
function argument is not newly admitted language. The public JSON structure,
byte, node, depth and nominal limits are unchanged. The streamed output does
not add an expanded Core byte quota. Existing native type shape/name errors
retain their documented diagnostic category and ordering policy; their English
context is not claimed identical to every reference diagnostic.

The constructor and function workspaces are each 192 MiB, while the outer
workspace is 80 MiB. Constructor workspace cleanup precedes ordinary function
allocation. Types use their existing 128 MiB session and 64 MiB output. These
application arenas are separate from the unchanged native compiler child
limits, including 128 functions, 1536 blocks and 8192 instructions. The new
owners do not increase compiler, public-language or qualification time limits.
The detailed arena charges remain in the constructor and outer bounds documents.

## Public lifetime

The v63 `elaborate_program` cleanup is retained: a finally block closes native
function and type sessions after success or any exception, including failure
while initializing the elaborator. These closes are idempotent and do not
replace the original exception. Private method partial state is unchanged.

The new constructor closes its own temporary buffers even on partial allocation
or transport failure. If it created a type session but has not transferred it
to the owner by identity, it closes that unpublished session before propagating
the error. The outer invocation clears its borrowed function-workspace reference
as well as its own buffers on both ordinary completion and failure. It acquires
that reference only inside protected initialization.

The integrated lifecycle tests use real native images with all old semantic
owners disabled. They keep successful results or exceptions and tracebacks
alive while observing sessions and buffers through weak references. Controls
cover constructor shape/inventory, type initialization, function and delegated
refusal, final primitive admission, the outer late block limit, a real type
initialization followed by a malformed constructor response, and partial real
constructor/outer allocations. The observer records no strong session or native
buffer references. These are explicit lifecycle controls, not a universal claim
about arbitrary corrupted foreign function calls.

## Shared test fixture and provenance

`tests/hia_composite_function_fixture.py` keeps its existing import name and
provides one complete eleven-image fixture per process:

* Five nonempty `*_DEVELOPMENT_MANIFEST` values select a development fixture.
  Every nonempty proper subset refuses before construction.
* A `*_COLD_REPORT` selection requires one resolved report path for every
  supplied cold selector, the complete current source contract and all existing
  cold admission checks. All eleven images are built by the source-bound
  builders. Development and cold selections together refuse.
* With neither selection, one real B0/B1/B2 fixed point compiles all eleven
  images. Its scope is `BOOTSTRAP_DEVELOPMENT_ONLY`; it never becomes a cold
  receipt.

Complete provenance is checked before exposing a smaller owner view. The
original function tests still select their original seven-image semantic
component. Constructor-only, constructor-plus-function, and complete outer
tests select the appropriate views. Reference views clear all five production,
development and cold selectors. Every cache reuse checks source, manifest and
image pins; cold fixtures additionally pin the full admitted source closure,
both reports and the selected compiler. Disk image digests are checked before
and after possibly warm immutable mappings are used.

`HEPTA_HIA_COMPOSITE_FIXTURE_EVIDENCE` optionally names a new directory for
exact copied build outputs and all pinned inputs, including file modes. The copy includes actual
B0/B1/B2 artifacts when bootstrapped, the eleven images, original packets,
compiler receipts and logs. A final custody record is written only after every
copied member is read back and fixture pins are checked again. Scope remains
explicit in that record. A failed build can retain a separate
`BUILD_FAILED_RAW_ONLY` record and partial original files; it cannot publish a
usable fixture or successful custody record. Capture or cleanup failures do not
replace the original build exception. The evidence destination is fixed on the
first construction; changing it on a warm cache refuses instead of silently
discarding the new request. CI retains this directory, and the full qualification
runner uses a distinct directory per process.

## Installed and CI controls

All four new HIA sources are explicit package resources and sdist entries. The
joint installed test builds an actual source archive, builds a wheel from that
archive and runs the installed package with `-I -S`, an empty `PATH`, no authoring
tools and all old nominal semantic owners disabled. It checks all eleven source
bindings, public Core/structured bytes and real VM execution. Missing or changed
bytes in each of the four new sources, four new images and two new bundle
manifests refuse. The existing seven-image function component installation test
is preserved independently.

The complete installed-resource inventory resolves each source through its real
bridge: the five function sources share `hia_composite_functions_native.SOURCES`,
and constructor/outer source pairs use their respective `SOURCES`. Scalar source
bridges retain `SOURCE`. This corrects the v63 test's invalid assumption that
every source basename names a distinct Python module; no dummy modules or
reduced source inventory are introduced.

The native CI group retains all existing type, signature, helper, function and
public lifecycle modules and adds constructor, outer and combined lifecycle
modules. It rejects skips, expected failures, ordinary failures and unexpected
successes. Source CI runs only source, codec, adapter and frame classes for the
new owners. The external full runner includes the same native modules and full
retained discovery. The original 180-second cold deadline and two cold workers
remain unchanged.

Full exact-source qualification and default activation are separate steps. This
integration alone does not authorize removal of reference modules, Python
packaging, Rust components, primitive admission, backend or Agent owners.
