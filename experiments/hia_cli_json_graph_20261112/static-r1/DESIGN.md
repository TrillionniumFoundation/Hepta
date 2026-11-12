# CLI graph JSON: isolated source candidate, revision 1

## Current result

There is no existing HIA entry that can replace the complete call in
`hepta.cli.output_json`. The reusable implementation is a composition of
existing algorithms, with a new graph continuation. The bounded wire entry
and the admitted-byte layout entry cannot serve as that continuation: they
have narrower domains and a different order of observations and errors.

This checkpoint adds one concrete source component,
`inputs/tools/generate_hia_cli_json_text.py`. It authors HIA for JSON scalar
text in Unicode code points: string escaping, arbitrary-size integer
magnitude conversion, the existing complete finite binary64 printer, and
NaN/infinity/null/boolean spellings. It has no graph traversal and performs
no printing. It does not import or select a replacement for `cli.output_json`.
The graph continuation, raw object ABI, and revised no-key TimSort binding
remain implementation work. The source has been parsed, but no HIA has been
generated, verified, compiled, loaded, or run for this candidate.

The repository reference is the exact CI source
`b7c2f79e04965e53a1c198703f20b1ff22df4765`, tree
`dc29b16468d5ae1e558f317c7ab360b31ac2a002`. Root's v88 tree and the default
selection are untouched. The accompanying manifests identify every source
actually read and distinguish reference code from new implementation.

## The original public call

The complete body is:

```python
def output_json(value):
    print(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True))
```

The corresponding ordinary HIA CLI effect is opcode 22. It looks up
`self.cli.output_json` at the effect and passes the current object. Existing
CLI tests replace this function with a callback that mutates the result; the
next result-truth operation must see that mutation. A graph encoder does not
authorize caching or bypassing this public callback lookup.

Inside the original function, the print callable is bound before evaluating
the dumps argument. Dumps produces a complete `str` before print is called.
The original print then chooses stdout, encoding/error policy, newline, and
write behavior. An encoding exception must not turn into partially streamed
stdout. The result of print is discarded and `output_json` returns `None`.
Replacing this with streamed JSON writes, or selecting stdout before dumps,
would change observable behavior.

The call keeps `allow_nan=True`, `skipkeys=False`, and circular checks. It has
no repository 8 MiB output budget, node count, or depth-128 admission policy.
CPython's actual recursion and integer conversion limits still apply. Unicode
text can contain isolated surrogates; eventual stdout encoding is a separate
operation. `publish_json_view` is a different API: it supplies
`allow_nan=False`, encodes bytes, and publishes a file. Its policy must not be
substituted for this one.

## Pinned runtime behavior

The three runtime versions already admitted by the current CLI source have
been read from the official CPython repository. These are source observations,
not new runtime test results. Original source files and their license are
retained; byte sizes, SHA-256, Git blob identities, and official URLs are in
`REFERENCE-PINS.json`.

| Behavior | CPython 3.12.14 | CPython 3.14.4 | CPython 3.14.10 |
| --- | --- | --- | --- |
| `indent=2` ordinary path | Python `_make_iterencode` | C `_json` encoder | C `_json` encoder |
| Root string fast path | Python `isinstance(o, str)` | Same | Same |
| Nested type dispatch | Python `isinstance`, with its observations | C type checks and singleton identity | Same C dispatch |
| List entry | Truth test, then iteration | `PySequence_Fast`, raw size, then marker | Same |
| Dict empty test | Truth test | Raw dictionary size | Same |
| Sorted entries | `sorted(dct.items())`, then unpack each iterable | `PyMapping_Items`, in-place `PyList_Sort`, then require a two-tuple | Same |
| Float subclass special checks | Python comparisons in `floatstr` | Raw IEEE value, base float repr | Same |
| Current list child / dict item reference | Python frame references | Borrowed C references at the relevant loop | Additional per-item INCREF/DECREF protection |
| Error notes in nested C encoding | Not this C path | `_PyErr_FormatNote` | Same mechanism with revised lifetime |

The 3.14.10 added references are visible to finalizers. Its source therefore
cannot be treated as an interchangeable lifetime protocol for 3.14.4. This
candidate does not reproduce undefined memory access from older CPython; the
defined mutation/lifetime behaviors and any unsafe old-runtime boundary need
an explicit runtime-specific decision before activation. No old runtime
result is inherited by a different source or version.

The root `isinstance` fast path also differs from nested C type checks. An
object whose `__class__` property claims to be `str` can be observed by the
root test, and still be rejected by the actual string encoder. It is not
valid to replace both operations with one exact-type observation.

## Reusable HIA components

| Existing component | Reuse | Boundary requiring new work |
| --- | --- | --- |
| `generate_hia_agent_binary64_format.py` through the existing `format_program()` composition | Complete finite IEEE-754 shortest decimal algorithm and existing scratch arrangement | Add HIA NaN and infinity selection. Do not use a host float printer. Preserve profile-specific foreign float comparisons where the original Python path makes them. |
| `generate_hia_json_wire.py` integer arithmetic | Magnitude-to-decimal arithmetic | Remove wire output budget from the new graph path. Reproduce the runtime's early/late digit-limit observations and error construction separately. |
| `generate_hia_cli_format.py` UTF-32 error-string escaping | JSON escapes while retaining raw non-ASCII and surrogate code points | General scalar text output and dynamically sized output storage. |
| `hia_json_pretty_native.py` / `json_pretty.hiaasm` | Existing layout rules and measurement discipline | Its admitted compact UTF-8, 8 MiB input and 129-entry stack are not the public graph domain. The new graph continuation should emit layout directly. |
| `hia_json_wire_native.py` | One-effect continuation and image/source-admission patterns | Its exact-builtin-only observer, reverse preflight, collisions policy, nonfinite/surrogate refusals and fixed bounds are incompatible with the original call. Do not wrap those refusals into the public CLI. |
| Frozen ELF TimSort authoring at `078d5213...` | Run detection, binary insertion, galloping, merge/power scheduling, comparator continuations | Bind actual item-list handles and no key function, preserve in-place list visibility and failure permutation. The original ELF key construction and key cleanup do not apply. Original authoring ACK and ingress remain UNKNOWN. |
| Numeric comparison source `6e530a59...` | Possible exact bool/int/float comparison leaves | It does not choose JSON sort order or supply float text. Its current source/VM evidence is not native sorting evidence. |
| Existing NativeHiaJsonImage loader | Source and image admission for a future installed component | No manifest, resource declaration, installed test or default selector is added by this checkpoint. |

The existing wire/worker-report numeric merge helpers must not be treated as
interchangeable strict less-than predicates. In particular, the wire's
`numeric_less` returns true for equality to select the left merge item. The
JSON no-key sort needs the exact strict predicate at each requested comparison.

## Why sorting needs its own adaptation

The original operation sorts whole mapping items, not a list of key projections.
For ordinary dictionaries, items are `(key, value)` tuples. A tuple comparison
first tests equality of elements, including identity shortcuts, and may compare
the values after equal keys. A dictionary subclass can return a separate or
aliased list of arbitrary objects from `items()`. On the C path, sorting occurs
before the encoder checks that each item is a two-tuple. On the Python path,
the later loop performs normal iterable unpacking instead.

CPython's actual `PyList_Sort` temporarily sets the item list's size to zero,
detaches its storage, and sets the mutation sentinel before comparisons. This
is visible if the items list is aliased. Sorting failures leave a permutation
of the original list; later mutations are disposed of after restoring the
original list storage. The error already in flight wins over the additional
"list modified during sort" condition. A separate HIA array followed by a
single final host replacement does not reproduce those observations.

The reusable algorithm must therefore operate on a raw detached-list storage
capability whose setup and restoration match the pinned runtime. HIA chooses
run detection, all comparisons, moves, merges, error continuation and restore
ordering. A small CPython ABI shim may observe or move pointers and manage
owned references; it must not call `sorted`, `list.sort`, or `PyList_Sort` as
an implementation shortcut. Cached comparator selection must retain exact
tuple/type/slot checks, fallback on `NotImplemented`, and truth-result release
with the correct ambient handled exception. The existing ELF observer creates
keys of ELF-specific shapes and is reference material, not the new observer.

## New scalar-text source and its exact scope

The new HIA entry consumes an immutable mechanical record, not JSON bytes.
Strings contain UTF-32 code points; integers contain little-endian magnitude
limbs and a sign; floats contain their original eight IEEE bytes. The host
must not call a text serializer to produce these records. Output consists of
UTF-32 code points with JSON quotes/escapes/spellings chosen by HIA.

The two entry modes measure a scalar and emit that same immutable scalar.
This is not permission to traverse a live object graph twice. The graph
continuation must request each object observation at the original point,
retain the necessary immutable scalar observation, and then run the two text
modes without calling user code again. Graph/layout output uses a private,
growable destination and is only converted to the final Python string after
successful completion.

The input/result layout is specified in `TEXT-PROTOCOL.json`. Failed output
and lengths are never admitted. The native return status must be checked
before a caller interprets the workspace count. Short workspace refusals do
not promise to clear an old workspace header. The scalar component's current
integer digit-limit check is only a late count check. It is not yet a substitute
for the runtime's full integer conversion policy and must not be presented as
one.

Official `longobject.c` shows an early bit/digit estimate check, a possible
large-integer `_pylong` path, allocation and signal-check sites, and a later
exact digit-limit check. The graph/ABI plan must preserve the relevant limit
read and exception order; a bound of 8 MiB or "exact builtins only" would not
resolve this obligation. Final allocation failure and asynchronous-exception
traces are also unverified. They are recorded as open work, not claimed as
equivalent merely because decimal text arithmetic is present.

## Proposed graph continuation

`GRAPH-PROTOCOL.json` defines the draft ownership split and ordered phases.
It is a design input, not generated executable code. The intended controller
uses an explicit HIA frame stack with runtime growth, rather than a graph
depth-128 or node-count admission gate. Buffer growth and pointer movement are
mechanical host operations; HIA selects when they occur and the exact data
that survives each transition.

The graph HIA owner must choose:

1. The versioned entry path and every singleton/type classification branch.
2. Container entry/iteration, marker membership and insertion/deletion order.
3. Sorting metadata selection, all comparator invocations, merge schedule,
   mutation/error checks, and failure restoration.
4. Key conversion, value traversal, quoting, separators, indentation, and
   output growth requirements.
5. Error type/message/note requests, cleanup order and terminal outcome.

The host ABI is limited to named raw object observations, a requested foreign
call, reference ownership transfer/release, storage allocation/movement, and
the final requested print invocation. It cannot select a traversal, normalize
a key, pre-sort, serialize a subtree, decide a circular reference, or precompute
a layout. No error must be swallowed and reclassified as bounded-wire refusal.

The existing raw raised-exception capsule work from Core UNPACK is relevant:
cleanup must preserve the pending raised exception and the caller's handled
exception independently. A Python `except` wrapper followed by arbitrary
reference release can expose the wrong `sys.exception()` to destructors.
The graph shim and HIA cleanup plan require actual trace controls, including
failures after a native return but before permission bookkeeping completes.

The dynamic public callback seam remains intact. Arbitrary replacements of
`cli.output_json`, `print`, `json.dumps`, JSON encoder methods or their observed
globals cannot silently be treated as the ordinary pinned implementation.
The exact binding points and any foreign extension dispatch remain explicit
implementation obligations; this checkpoint does not erase those objects or
claim their execution is HIA-owned.

## Validation plan, without inherited results

`TRACE-PLAN.json` fixes the proposed case identities and observations. It is
not a loaded/executed test ledger. Original CLI methods remain separate and
unchanged. The first authorized execution should generate the complete scalar
HIA with the existing authoring tool, verify Core/assembly round-trip and all
original compiler caps, then use the original 20-second wall/10-second CPU/
1 MiB compile bounds. No new execution is requested by this checkpoint.

The full graph candidate needs both positive output comparisons and traces
against the saved original function/environment for each actual runtime. Tests
must include whole sorted-item comparisons, opaque/default errors, cyclic and
shared graphs, string/integer/float/container subclasses, aliased item lists,
mutation at comparison/default/error-note points, and finalizers observing
the active exception. Unicode failures at stdout must be distinguished from
graph encoding failures. Large valid values and graphs beyond the old wire
bounds must be included rather than rejected by a new profile.

Root's installed pretty 43+9 results, the former ELF 55/51 results, numeric VM
results, and the original TimSort UNKNOWN authoring operation do not validate
this new source. No CLI/full/cold/installed/native PASS is asserted here.

## Next implementation order

1. Freeze and source-author the scalar text component; resolve integer limit
   and large-number observation ordering with actual pinned runtime controls.
2. Adapt the existing HIA TimSort to a no-key, detached actual-list capability;
   close full comparison/failure/finalizer traces before connecting it to JSON.
3. Implement the explicit graph frame controller and versioned primitive shim,
   including original traversal, circular markers and cleanup behavior.
4. Add an opt-in development selector and complete original CLI caller controls;
   keep default behavior unchanged until source, native and installation
   evidence match the exact candidate.

This order reuses the existing complete numerical and sort algorithms while
making the missing semantic control concrete. It does not introduce a new
standalone compiler or linker entry.
