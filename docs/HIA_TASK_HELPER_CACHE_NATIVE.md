# Native task helper cache owner

`examples/hia_bootstrap/task_helper_cache.hiaasm` owns the complete cache
decision around the existing HIA task-helper generator. It performs the exact
lookup, requests dependencies and task protocol checks in order, selects the
poll and cancellation effect objects, admits the complete generator result,
commits its counter and optional name, and publishes a helper only after
successful admission. The cache belongs to the elaborator and is shared across
functions; a controller invocation does not create a function-local cache.

This is a bounded nominal compiler owner. It does not claim that every parser,
runtime, compiler transport, release tool or other project component is HIA.
The separately owned task generator still emits every helper instruction,
block, effect and cleanup operation. The separately owned native type session
still checks task protocols. This controller performs the complete surrounding
cache policy without a selected hosted fallback.

## Selection and integration

`HEPTA_HIA_TASK_HELPER_CACHE_MANIFEST` selects the image. Missing, changed or
invalid selected source, image or manifest refuses. The adapter exposes
`selected_task_helper_cache()`, `installed_task_helper_cache(manifest)` and
`NativeTaskHelperCache.lower(owner, typ, operation, require_native=False)`.

The elaborator's selected branch precedes its old hosted cache lookup. An
already admitted image can be supplied through the private `_native_cache`
keyword so that a continuation never reselects a different dependency. The
complete native function path requires this cache owner at the original task
helper continuation. A missing cache is an explicit dependency refusal even
if the old host dictionary happens to contain a name. Once the native cache
is admitted, a cache hit does not select or check the helper generator.

With no cache selected, ordinary callers retain the exact old wrapper in
`_reference_helper_cache`. Its body AST hash is
`9a2986d04df78f9c563504c9b9019808c8f728f3e22a5bfd71c300148af52947`.
The independent test copy retains every executable statement and branch;
only its relative import is made absolute for the test module and normalized
back for the AST check. The original pure helper generator remains a separate
reference control as well.

## Exact order and partial state

The HIA controller follows these original phases:

| Phase | HIA decision and requested observation | State visible afterward |
| --- | --- | --- |
| Cache lookup | Compare the native type identity and operation with every held cache row | On a hit, return the exact held name immediately |
| Generator selection | Request the generator selector only after a miss | Hold the returned native image for the entire continuation |
| Task protocol | Request the already owned native type session | Preserve its exact descriptor/observation changes or refusal |
| Effect lookup | Find poll and cancellation names in the held function inventory; request poll effects before cancellation effects | Hold the original complete effect objects |
| Generation | Request the held HIA generator with the current serial and complete descriptors/effects | Hold its complete result without admitting or publishing it |
| Prefix commit | Copy the generator's serial and cache its name when non-null | A failed generation can already have a cached name |
| Admission | Propagate the generator's exact error code/message | A refusal keeps the serial and name prefix |
| Publication | Append the complete held helper and return its held name | Successful name/helper objects preserve their identity |

The five operations are `start`, `poll`, `cancel`, `join` and `close`. The
generator owns fresh-name allocation. For example, when generation starts at
serial 8191, it can reserve `h2internal_8192` and then refuse further expansion;
that name remains cached without a helper. Starting at 8192 produces no new
name. A later hit returns an already cached name without another check,
generation, counter update or append, including when generator selection has
since become unavailable.

The old wrapper reads both effect objects before invoking the native
generator. The controller keeps that order for every operation. It does not
pre-read the effects of unrelated functions. A missing held function key is
reported through a dedicated native-chosen `KeyError` continuation; this
preserves direct private-call behavior when a function map has been altered
after protocol checking. Public task protocol admission remains a separate
owner and retains its existing errors.

On a generator miss with no generator selected, `require_native=True` retains
`E_HIA_TYPE: selected native function requires native task helper generation`.
An explicitly selected cache with `require_native=False` also refuses rather
than using a hosted generator, with the cache-specific dependency message.
The flag is a private controller option, not a source-language field.

## Issued graph integrity

The recovery audit retained three actual-image negative observations. On the
original cache bridge, changing a terminal empty serial array to contain 99
caused an unissued owner write. Changing the issued generator serial from 0
to 77 reached the actual helper image and generated `h2internal_78`. The
function bridge separately allowed an issued parameter path to be changed.
These are private transport correctness findings, not a claim about defending
against arbitrary code running in the same process. The original observations
and sources remain in the separately retained original-failure archive.

The corrected bridge uses `decode_bound_native_graph`. While decoding, it
captures immutable shallow edges for every newly created list and dictionary,
including decoded source references. It validates those edges before consuming
a callback or commit permission and before any owner write. Changed keys,
typed scalar identities, nested edges, inserted cycles and copied replacement
objects refuse. Terminal admission requires the exact issued result and its
unchanged header as well as the unchanged graph. A refusal closes the context
and releases the binding and both arenas without applying a new prefix.

Concatenations retain their source pieces and lengths rather than allocating
another expanded array. New scalar/string bytes are not copied. Binding space
follows wire-created edges and encoded piece references, not repeated logical
aliases. Existing node, depth, byte, expansion and public language limits are
unchanged.

Tags 10 and 11 preserve the exact identities of previously held external
helpers/Core objects. Their interiors are opaque and retain the existing
stable-pool custody contract. In particular, simultaneously changing a held
external list and the new concatenated outer list is outside this binding's
guarantee. The binding does not deep-copy or traverse opaque interiors to
invent an immutable history of another owner's objects. An outer list newly
materialized from an external tuple is bound; its children remain opaque.

## Transport and ownership

The bridge accepts only `_NativeTypeIdentity` keys already issued by HIA.
Each identity includes a session nonce and unsigned identifier. It transports
the identifier after checking that all held keys have the query's exact nonce;
it never projects, hashes, compares or reconstructs hosted structural type
keys. Repeated equal nominal descriptors are already interned by the native
type owner. A cache hit needs the held key, not a live type arena. A miss
requires the native type session for the requested task protocol check.

The input is a typed value packet:

```text
[metadata, sequence, current_serial, reply, function_inventory]
metadata = [type_id, operation, require_native, cache_rows, invocation_nonce]
cache_row = [type_id, operation, name, external_name_id]
function_inventory = [poll_name, cancel_name, function_names]
generator_reply = [serial, error, name, external_name_id, external_helper_id]
```

Metadata is captured byte for byte in the native workspace. Every continuation
must repeat it exactly. The function inventory is observed only when requested,
then similarly retained and compared by complete bytes. Invocation nonces
prevent swapping equal-looking metadata between independently owned contexts.
No user-supplied manifest or source field controls packet regions or limits.

Cache values and the generator's complete name/helper use the existing generic
`NativeValuePool`. HIA writes external references into a complete result graph;
the bridge does not rebuild Core or interpret a language-specific lowering
plan. The final result contains complete `serial`, `cache`, `helpers` update
arrays and the returned `name`. Each update array has zero or one element.
Materialization applies the first two arrays, performs admission, then appends
the helper array. There is no hosted branch deciding whether a key hit, which
name to generate, whether to cache a failed name or when to publish a helper.

The output header contains eight unsigned 64-bit words: magic, error, request,
payload size, sequence, and three reserved zeros. Requests are:

| Request | Fixed transport operation |
| --- | --- |
| 1 | Select and retain the native helper generator |
| 2 | Invoke the retained native task protocol owner |
| 3 | Hold the current complete function inventory |
| 4 | Fetch effects at the HIA-selected function ordinal and argument slot |
| 5 | Invoke the retained generator at the HIA-selected serial |
| 6 | Raise the missing key selected by HIA |
| 0 | Materialize the complete terminal result |

The bridge accepts only the exact current request/query pair. It consumes a
request permission before any external callback, accepts a new native step
only after the prior callback completes, and closes on interruption. Every
public `lower` invocation releases both arenas in `finally`. Partial
constructor allocations are released inside the constructor itself, before
that public `finally` has received a context. Retaining the original exception
and traceback must not retain an abandoned arena or make the callback
re-serviceable. Original owner/type/cache prefixes remain visible.

## Private capacity proof

Public limits are unchanged: 8 MiB source, 262,144 JSON nodes, depth 64, 1,024
functions, 128 nominal instances, 512 flat slots per type, 32,768 charged value
slots and serial at most 8192. This controller does not charge new public
slots, flatten values or change expansion limits.

At most 128 task instances can occupy the nominal-instance inventory. Each
has five helper keys, so 640 cache rows is conservative. At most 1,024 function
names are observed. Public names have at most 128 ASCII bytes; generated names
are shorter, but the private calculation allows 128 bytes for every cached
name too. The private limits are:

| Region | Capacity |
| --- | ---: |
| Input packet | 1,048,576 bytes |
| Typed decoded values | 8,192 nodes |
| Typed nesting | 128 |
| Output frame | 4,096 bytes |
| Workspace | 2,097,152 bytes |
| Captured metadata | 262,144 bytes |
| Captured function inventory | 262,144 bytes |

A cache row has five typed nodes including its array, and at most 235 bytes
using a ten-digit identifier, six-byte operation, 128-byte name and three-digit
pool index. All 640 rows therefore use at most 150,400 bytes and 3,200 nodes.
The row array and surrounding metadata contribute fewer than 512 further
bytes and 16 nodes. The function inventory uses at most 147,792 bytes and
1,028 nodes. The root, serial, sequence and largest generator reply keep the
whole packet below 310,000 bytes and 4,300 nodes. Its actual nesting is shallow;
the 128-level transport guard is conservative. The independent envelope test
uses 640 rows and 1,024 long names without asserting that those artificial
private IDs are newly admitted public task definitions.

Workspace regions are disjoint. Parser scratch ends below offset 4096; the
output writer uses offset 4096; controller state begins at 8192. The duplicate
key table occupies `[16384, 26624)`. Metadata occupies at most
`[32768, 294912)`, and the function inventory at most `[327680, 589824)`.
These remain below the two-MiB arena. Every region copy checks its extent.

The complete terminal graph needs fewer than 1,024 output bytes even with all
three updates present. The large helper is an external reference, not a
serialized or reconstructed copy. The existing generic graph quota charges
newly expanded elements only; retaining a helper does not impose a new whole
program limit or repeat-name wire limit. The controller has at most seven
native frames on a normal miss and one on a hit. The bridge's 16-frame bound
does not narrow the public protocol.

## Controls and qualification

The source test independently regenerates checked HIA, validates its complete
IR and retains the compiler's original function, block, instruction and block
parameter limits. Exact old-wrapper and pure old-generator controls compare
complete helpers, names, counters, type observations and failures. Public
fixtures cover all four nominal schemas, scalar/owned results, partial state,
loans permitted by the original profiles and resource cleanup.

Native controls include cache persistence, unavailable generators on hits,
real generator selection followed by selector rebinding, precise error order,
generator failures at the fresh limit, private unreachable loan-padding
refusals using the actual generator, malformed packets, byte/node capacities,
full independent VM/native frames and workspace, actual callback interruptions
and cache-prefix publication failure. Installation uses a wheel, empty `PATH`,
`-I -S -B`, blocked authoring imports and disabled hosted cache/generator/type
fallbacks. Retained native machine controls exercise allocator refusal, cleanup
and invalid task-state traps through the selected cache path.

`HEPTA_HIA_TASK_HELPER_CACHE_COLD_REPORT` selects a matching-source qualified
compiler fixture. `HEPTA_HIA_TASK_HELPER_CACHE_DEVELOPMENT_MANIFEST` selects an
explicit development fixture; setting both refuses. A local bootstrap fixture
is also development-only. Source or bridge changes need their own current
evidence. A retained compiler image and passing development controls do not
qualify a changed whole source tree or authorize retiring its reference paths.

### Recovery of the final terminal permission guard

The environment reset after the original 18-control development gate removed
the last adapter, test and documentation revision. The earlier complete
checkpoint, the checked HIA source and its generator were recovered byte for
byte. The original final adapter/test/doc hashes remain historical identifiers;
the terminal guard described here is a new reconstruction and requires new
qualification. The recorded 18-control result is not evidence for these new
three files, and its missing raw reports have not been recreated as originals.

The terminal native result grants one materialization permission to its exact
returned result object. A copied result, a result from another context, an
unissued result, a previously committed result and a result whose context has
been released all refuse before owner mutation. The bridge consumes this
permission before assigning the serial or writing the cache. An interruption
preserves any original prefix, closes the context and prevents the prefix or
helper append from being replayed. This transport guard does not decide cache
hits, generated names, admission errors or helper publication policy; those
remain complete decisions in the unchanged HIA source.

The reconstructed control keeps the original interruption exception and
traceback while checking released arenas and exact prefix state. Existing
actual native controls also attempt terminal replay after an interrupted cache
write. They supplement the independent VM/native, original-wrapper, boundary
and installed-wheel controls. Evidence for this revision must identify its
current input hashes and retain the new raw reports; the historical 18-control
result cannot qualify reconstructed source.
