# HIA bounded foreign-object JSON wire

This component replaces the graph admission and encoding decisions of
`bounded_json_wire` when `HEPTA_HIA_JSON_WIRE_MANIFEST` explicitly selects its
source-bound image, including ordinary `AgentStore.wire` and `digest` calls.
The unselected entry retains the original implementation. This component does
not replace SQLite or qualify later source using an earlier cold compiler.

## Ownership

The HIA program requests observations of actual objects through the versioned
`HIAWIR02` continuation protocol. It owns both traversals, node/depth/queued
budgets, active-container identity, exact object-key admission and converted-key
collisions, integer byte and runtime digit-limit policy, dictionary sorting,
Unicode escaping, arbitrary-precision integer decimal conversion, shortest
finite binary64 printing, and cumulative output budgets at JSON encoder fragment
boundaries. A hash-table hit is followed by an exact key-byte comparison; a hash
alone never decides equality.

The first traversal follows the retained reverse DFS order. Dictionary keys are
checked in insertion order before their values are visited. Each string has its
own preflight byte budget; the program does not impose an earlier aggregate
string or transport budget. Values containing nonfinite numbers or excessive
decimal integers are refused at the encoding stage, after the entire graph
preflight. A list prefix and scalar belong to one fragment, preserving the
retained error priority when a scalar conversion and an output limit compete.

The Python bridge transports exact builtin type, length, identity, children,
Unicode codepoints, unsigned integer magnitude words and IEEE binary64 bits.
Registration retains object identity without examining descendants. There is no
host JSON encoding, sorting, decimal integer conversion, recursion over the
graph, or table of precomputed replay results. SQLite/service/report policy is
outside this component.

The bridge reserves the complete output and workspace extents in fresh private
anonymous mappings. Their zero-filled pages are materialized only when used;
small ordinary calls no longer clear roughly 54 MiB on every invocation. The
ctypes export retains its mapping, including across callback exceptions and
reentrant calls, and no explicit close runs while exports remain live. The
bridge copies only the HIA-returned output length after checking that length
against the declared capacity. These changes leave all HIA graph, ordering and
budget decisions and the protocol's buffer capacities unchanged.

## Ordinary entry contract and remaining parameter domain

The source-defined `ORDINARY_PROFILE` is also recorded in each new build
receipt. It admits exact `NoneType`, `bool`, `int`, `float`, `str`, `bytes`,
`tuple` and `frozenset` options for `ensure_ascii` and `sort_keys`. The bridge
observes only exact type, bit length, IEEE bits or immutable length; HIA
determines truth. This preserves hook-free non-boolean inputs without calling
foreign `__bool__` or `__len__`. The 104-byte version 2 initialization packet
carries those two type/value pairs. HIA rejects an invalid output budget before
option or renderer profile admission. Version 1 evaluated options eagerly in
Python and did not preserve that order; original controls are retained.

Mutable option objects, subtypes and foreign truth hooks remain outside this
profile and receive an explicit native refusal. Full foreign truthiness would
need observations at every original DEL/non-ASCII string-preflight point,
encoder-start ASCII choice and nonempty-dictionary sorting choice. A single
eager truth value does not implement those callbacks. This work does not claim
the whole Python `bounded_json_wire` parameter domain is replaced, and the
retained implementation remains available through the unselected entry.

The ordinary selected entry accepts either no external float renderer or an
exact `SelectedBinary64Renderer`, whose constructor admits the explicitly
selected HIA binary64 manifest. Arbitrary callback functions are explicitly
refused before invocation; they cannot gain the pure-HIA label by returning
similar-looking bytes. `AgentStore.wire` still admits its binary64 selector
before entering the bounded-wire selector. Thus an invalid selected formatter
retains its original priority over graph encoding. Source-bound image/cache
semantics remain those of the existing native loaders.

The lower-level `encode`/`encode_observed` interface retains its previously
documented trusted pure-formatter seam for composed native owners such as the
worker report. This does not retroactively extend older evidence to arbitrary
callbacks or make the ordinary profile's refusals disappear.

## Foreign and virtual objects

`ForeignGraphObserver.register(value)` returns a stable nonzero handle and
retains the object. A compatible observer supplies four methods:

| Observation | Result |
| --- | --- |
| `summary(handle)` | Four unsigned 64-bit slots: kind, size, a, b |
| `child(handle, index, part)` | Child handle; sequence part 0, dictionary key/value parts 0/1 |
| `points(handle, start, count)` | Original Unicode codepoints, including isolated surrogates |
| `limbs(handle, start, count)` | Absolute integer magnitude, little endian 32-bit words |

Kinds are none=0, bool=1, int=2, float=3, string=4, list=5, tuple=6,
dict=7, opaque=8. Bool uses a=0/1; int uses size=bit length and a=negative;
float uses a=IEEE64 bits; string and containers use size=length. A dictionary
summary begins a fresh ordered traversal. The concrete observer only retains
dictionary pairs after HIA requests them. The second traversal observes the
actual objects again. An observer for HIA-generated virtual report nodes can
implement these same methods and forward references to the foreign graph.

The optional `float_renderer` seam has the existing selected HIA finite
binary64 printer's contract: a pure exact printer returning ASCII JSON-number
text of at most 32 bytes. The program requests it at the retained key/value
conversion points. It is not an implementation of arbitrary user-defined
Python `JSONEncoder` hooks or their side effects. A caller must capture and
admit the explicitly selected formatter at the same point as its retained wire
entry. Without this selection, the finite printer is composed directly into the
HIA executable. Exact builtin graph observations are trusted foreign facts;
fabricated virtual dictionaries must obey builtin dictionary key uniqueness and
identity semantics.

## Selection, build and validation scope

The manifest schema is `hepta.hia.json-wire-native.v1`. It binds the packaged HIA
source, executable and compiler hashes. `installed_json_wire(path)` refuses a
changed source or a newly selected invalid image; it never calls the retained
encoder as fallback. Existing immutable loaded-code cache behavior is shared
with the other native image owners.

`tools.build_hia_json_wire.build` requires a completed current-source cold report
and inclusion of this source in the current source closure before creating its
output. `build_development` is separately named and marks its result
`DEVELOPMENT_ONLY_NOT_MATCHING_SOURCE_COLD`. Compiler reuse for development is
not qualification of the changed program.

The dedicated test module has source/Core-VM and explicit native cases. Native
tests require either `HEPTA_HIA_JSON_WIRE_COLD_REPORT` or
`HEPTA_HIA_JSON_WIRE_DEVELOPMENT_MANIFEST`, never both. It compares original wire
bytes and refusal text, forbids retained serialization during native calls,
checks lazy observations and numeric error order, exercises exact 8 MiB extents,
and checks protocol sequence/extent refusals, output canaries and installed
wheel resource identity. Its results are evidence for the exercised controls,
not an all-input equivalence proof or whole-stack native completion.

`HEPTA_HIA_JSON_WIRE_FIXTURE_EVIDENCE` can name a new create-only directory for
the native test class. It retains the matching-source wire build when selected,
binary64 formatter build and wheel/source/extracted installation fixtures,
including partial files if setup or a test fails. Without that variable the
class uses an automatically cleaned temporary directory. Externally selected
development images are referenced, not copied, and the independent Core VM
child has no persistent workspace in this directory. Test stdout/stderr and
the external development bundle remain separate evidence inputs.

`tests.test_hia_json_wire_entry` exercises the ordinary entry, immutable option
facts, selected formatter ordering, fail-closed admission, ABI canaries and an
installed wheel with authoring and the retained encoder forbidden. It uses the
same cold/development selectors and an independent optional create-only
`HEPTA_HIA_JSON_WIRE_ENTRY_FIXTURE_EVIDENCE` directory.

`tools.qualify_hia_json_wire_native_callers` runs existing bounded-wire and ordinary
Agent suites with the selector set and the retained decision owner forbidden.
It records every loaded/chosen/executed test ID, all unittest anomalies,
actual native step returns and service-tool calls containing native wire work.
Qualified mode requires matching-source cold evidence, zero exclusions and all
eleven Agent tools. `--evidence-dir` retains the actual built image and fixture
directory. Explicit development exclusions remain visible and cannot turn a
development run into qualification.
