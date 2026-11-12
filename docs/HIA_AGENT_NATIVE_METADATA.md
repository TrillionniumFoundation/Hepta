# Native Agent metadata component

This component moves signature selection and borrowed-byte export policy into
the HIA source in examples/hia_bootstrap/agent_native_metadata.hepta. Its input
is the exact canonical primitive Core byte sequence from the complete original
verifier, a structured-provenance bit, and either a raw standard-JSON manifest or an
exact-type immutable-tuple snapshot. Its
output is the complete normalized export list and signature dictionary.

## Boundary and status

The component is independently developed. A generated source or a development
compiler witness does not qualify an installed production default. The ordinary
Agent service still owns full Core admission, canonical digest verification,
file custody, compilation, publication, and its default provider selection.
Whole-native delivery remains unqualified until these boundaries and the
matching source-complete cold and full retained suites close.

The adapter allocates three private byte buffers, invokes the source-bound
image once, checks input custody and result framing, maps its explicit refusal
code, and decodes the complete result. It does not compute signatures,
normalize export pairs, or call a reference fallback. An absent selector leaves
the component unselected. A present empty or invalid selector is an error.

## Preserved decisions

Scalar signatures follow the original scalar entrypoint set and preserve
function order. Parameters must be original native integer or boolean types.
There may be zero or one result; a unit result remains allowed. A unit parameter
and multiple results do not become scalar signatures.

A nonempty byte-export manifest cannot extend a nominal program or an explicit
scalar export contract. Each pair retains the original first-refusal order:
pair shape, integer extent, range and duplicate identity; then reserved names,
function existence, and the borrowed-byte signature. The native result sorts
valid export pairs by name and appends foreign signatures in original function
order. The public Agent ABI is hepta.hia.agent.borrowed-byte-snapshots.v1.

The original profile carries JSON bytes. JSON
fractions and exponents are retained as noninteger tags so that an invalid
extent is refused at its own pair, after earlier valid JSON pairs have been
considered. NaN, Infinity, Python tuple subclasses and arbitrary iterables are
outside this raw standard-JSON transport. That profile does not claim equivalence for the larger object domain;
the separate immutable-tuple profile below preserves the original object policy.

## Storage

The exact layout, capacity formulae, limits and refusal values are in
HIA_AGENT_NATIVE_METADATA_ABI.json. Both JSON spans retain the existing 8 MiB
bound. The input Core may contain 1,024 functions and more than 16 parameters;
the generated kernel's separate static profile does not narrow that public
input domain. A packed 64-bit source view keeps each decoder offset relative to
its own bounded JSON span and keeps the generated kernel within the original
16 block/edge argument limit.

Manifest capture lives beyond the JSON decoder arena. Decoder reuse cannot
overwrite it. At most 128 export rows and sort indices fit within the fixed
private auxiliary allocation. Raw JSON names retain their true byte length and a bounded prefix. The typed
snapshot retains the true codepoint length and up to 128 original codepoints;
valid Core identifiers are at most 128 ASCII bytes.

## Build and validation

tools/build_hia_agent_native_metadata.py requires a compiler admitted by the
matching current source-complete cold report. It rebinds the HIA source,
generator, builder and adapter before and after real compilation and refuses
any changed input. It preserves the original 1 MiB native-image limit.

The tests require exactly one explicit matching cold report or development
compiler. A development compile is recorded as
EXPLICIT_DEVELOPMENT_COMPILER_NOT_CURRENT_COLD. The tests compare actual native
policy results with the retained reference oracle, exercise installed image,
schema and source admission, poison reference policy during native calls,
inspect allocation canaries and input custody, and compare full native output
with actual VM buffers before their real destruction. VM execution retains the
original 3,000,000-step budget. No test skips or default fallback establish
success.

## Exact immutable-tuple entry

Input profile 2 captures the original immutable-tuple domain separately from
profile 1 JSON. The adapter observes exact built-in tuple, str and int types.
It copies a bounded name prefix as u32 codepoints, preserving unpaired
surrogates without attempting a UTF-8 conversion. It records the true tuple,
pair and name lengths, plus integer sign and bit length; a nonnegative value
is copied only when it fits the fixed u64 transport word. Unsupported subclasses
and objects receive a type tag and are not coerced or iterated.

HIA owns the same top-level count, empty/nonempty contract, pair, extent,
duplicate, reserved-name, missing-function and signature decisions. The prefix
is sufficient because valid Core names are at most 128 ASCII characters and
every earlier successfully accepted export name is therefore bounded. Non-ASCII
codepoints cannot compare equal to a valid identifier; the reserved ASCII
prefix is still examined first.

The ordinary hepta.hia_agent_service._signatures entry now selects an explicitly
installed metadata provider. Its original implementation remains under
_reference_signatures for the unselected route and independent tests. A selected
image's refusal or admission failure never falls back. Full program verification
remains with the original callers. This selected entry is not a production
default cutover or a statement that the other service, emitter, store and worker
owners are native.

## Registered source reproduction and acceptance

The component now has CI and retained-qualification registrations for
`tests.test_hia_agent_native_metadata` and
`tests.test_hia_agent_native_metadata_integration`. These declare 21 outer
test IDs; static discovery is recorded separately from execution. The native
and integration fixtures each use their own class-named evidence directory.

The generator requires explicit `--output` and `--inventory` paths that do
not exist. CI and qualification place both files outside the source tree, compare
the complete generated HIA bytes with the packaged source, and save the actual
source/generator/output/inventory identities. Its static profile check preserves
the existing limits. Generation does not compile or execute native code.

The exact installed helper entry is
`HEPTA_HIA_AGENT_NATIVE_METADATA_MANIFEST` with
`hia_agent_native_metadata_native.NativeAgentMetadata`. The HIA source is packaged as
a production input. This registration makes the explicit provider admissible;
the selected ordinary Agent `_signatures` route uses the immutable-tuple
transport. An absent selector retains `_reference_signatures`; registration
does not select a production default.

The separate M6 development observation recorded 16 passing outer IDs, 75 native
observations and three complete VM comparisons. Its two actual images were
292601 bytes, SHA-256
`a46e559207d2819f5919bc132c5b7c1ee59ff7bc5dcd11a629cbebade33825ad`.
Its result SHA-256 is
`9a6da9bf25392d0ffb8090a99606593a09c2c5454609fb76d5b12d8ce91d7523`.
That earlier HIA source was 200202 bytes, SHA-256
`d93cac026cc4a0da9d6a448daa716d48f9b868bb38fc56192ce7f8e7064423a6`.
Those earlier development bindings differ from this registered candidate.

The separate M7 development run added the typed object boundary and selected
ordinary entry. It passed 21 outer IDs with 172 actual native observations and
five complete VM comparisons, preserving the original 3,000,000-step VM limit
and 1800-second process owner (10.430918782 seconds). Its result SHA-256 is
`eab385d981249cd0ee1e5b63ebef72af67b58dcf868dca3ba8c91d0c307d8db1`.
The merged HIA remains byte-identical to that M7 source: 211073 bytes, SHA-256
`7bfae9ac24165a1c3602004bf2bb41f252c47685fc5c8a66bc9a719d19671940`.
The generated source retains the same 48 functions, 806 blocks and 3244
operations. The added CLI and static profile checks do not change these HIA
bytes. These source-specific development observations do not qualify the
combined registered tree. Matching final-source cold, the unchanged component
gates and full retained regression remain required. The current status is
indexed in [CURRENT](CURRENT.md).
