# Native Core byte prelude

This component moves the exact immutable byte input path through two HIA
images: the byte prelude publishes canonical JSON bytes, and the existing
Core admission image checks the primitive program. A Python object graph is
not created between those images. It does not replace the public typed Python
object snapshot, nominal elaborator, runtime plan construction, or all of
verify_program. No default provider is selected by this module.

## Order and input custody

The transport accepts only exact bytes. It captures the original byte length,
at most 8 MiB + 1 original bytes, and the actual sys.get_int_max_str_digits()
value. The latter is a mechanical input snapshot; zero means unlimited. No
host-approved validity flag is passed to HIA. A larger original object is
represented without copying its entire content: HIA rejects its original
length before inspecting UTF-8.

The HIA byte prelude performs these operations in order:

1. Validate the private transport and storage layout.
2. Apply the original 8 MiB input limit.
3. Scan the entire captured input for strict UTF-8.
4. Run the existing complete JSON preflight and decode into the native arena,
   preserving the original 262,144-node and depth-64 limits.
5. Check every integer lexeme against the captured integer-conversion limit,
   excluding a minus sign and treating zero as unlimited.
6. Run the unchanged canonical traversal, key sort and string writer.
7. Distinguish the four explicit composite namespaces and the historical
   primitive-v2/types collision.
8. Publish the complete header and canonical bytes, or the original complete
   error message.

The complete preflight precedes integer conversion. Thus a later depth failure
still precedes an earlier overlong integer, and invalid UTF-8 anywhere still
precedes both. Public failure strings are stored as fixed HIA constants; the
adapter reads those bytes and maps only the native error code to the existing
exception class. It does not choose or format an error message.

## Why the raw-byte path does not need a Python structure walk

The original text preflight admits only exact JSON null, booleans, integers,
strings, lists and string-keyed objects. It rejects duplicate decoded keys,
noninteger numeric syntax and unpaired Unicode surrogates. The native decoder
constructs a tree with the same node and depth counts; cycles, shared mutable
containers and subclass methods cannot arise from this immutable wire.

For admitted raw input, canonical UTF-8 output is no longer than the input:
whitespace disappears, escapes become equivalent shortest spellings, object
sorting preserves total byte length, and -0 becomes 0. Every partial positive
byte charge in the original structure walk is bounded by that final sum.
Queued nodes are a subset of the already bounded complete tree. A decimal
integer has fewer than four bits per input digit, so its bit length cannot
exceed the original four-times-byte limit. The actual decimal conversion
limit is checked separately before serialization. These arguments apply to
the exact-byte path only; they do not remove the caller-owned object walk.

The original canonicalizer's decoding prefix is separated at a strict AST
identity boundary. Its complete emission/sorting/escaping tail and every
decoder function retain their original AST. The new full-input UTF-8 scanner
uses the same scalar validity rules without JSON string syntax.

## Composition and remaining owners

NativeCoreBytesVerifier calls the byte image and then NativeCoreAdmission on
the exact returned canonical bytes. A successful primitive result constructs
VerifiedProgram from those bytes without a Python JSON decoder, encoder,
declaration walker or resource-flow policy. A composite namespace returns
CompositeCoreBytes: this is an explicit handoff, not a verification receipt.
The historical v2/types collision retains the original full error. No selected
native refusal falls back to a host checker.

The ordinary verify_program entry selects this byte owner only for exact
immutable bytes when HEPTA_HIA_CORE_BYTES_MANIFEST is explicitly present.
An absent selector retains the original path; an empty or invalid selection
refuses without fallback. A primitive native result returns VerifiedProgram
directly. A composite handoff continues the existing _decode on the original
input, then the nominal elaborator and independent derived-Core verification.
Its handoff bytes do not authorize the composite program. Structured
VerifiedProgram rechecks remain before this byte branch; other VerifiedProgram,
str, caller-owned dict/list and subclass paths retain their original owners.

Explicit installed selection uses two unchanged standard five-field manifests:
the front manifest and exactly adjacent admission-manifest.json. The matching
builder compiles both sources from the same admitted cold source map and
compiler, and records both compiler and source identities. The original Core
v4 single-image entry remains available independently.

An installed helper bundle must pin both CORE_BYTES and CORE_ADMISSION
selections at this exact adjacency before any selected factory is imported or
image mapped. The existing scope captures both complete manifests, source
files and image files; the composed verifier checks that original scope before
and after each call. The original binding object is also retained: a later
scope with the same bundle SHA is a different scope. A missing dependency,
different neighbor, changed bundle input or escaped scope refuses without fallback. Each image retains the
ordinary three-buffer ABI and its named factory. No extra fields or arbitrary
sidecars are admitted through the standard manifest schema.

This executable custody is distinct from a matching current-source cold
qualification. The typed-object and composite owners remain required. A
generated source or development run does not qualify the new complete source
against a matching cold compiler.

## Private buffers and publication

The image retains the ordinary three-buffer entry: source read view, output
mutable view and workspace mutable view. The source is the bounded original
prefix. The first workspace header contains the input capture parameters.
The original arena and key-table storage bounds are retained.

The output buffer is large enough for the original key scratch plus a
64-byte publication header, and for the captured input plus that header.
During decoding it is private key scratch; bytes beyond the published extent
are not claimed to be untouched. After canonical emission the payload moves
backward by 64 bytes in the same output buffer, preserving overlap safety.
Header magic is written after the payload and the remaining seven words.
Framing errors have no public diagnostic meaning and cannot authorize bytes.

See HIA_CORE_BYTES_ABI.json for exact frame words and diagnostic stages.
The declared test scope is separate from actual execution receipts. Original
Core diagnostic test IDs, inputs and budgets remain in the composed acceptance
plan; new byte-front-end controls add full reference messages, raw limits,
cross-error ordering, namespace handoff and actual VM/native byte equality.

## Ordinary entry qualification boundary

The ordinary controls add explicit primitive v1-v8 calls, complete reference
exception type/code/message comparisons, integer-limit and first-error cases,
eight valid composite factory/version combinations, unchanged typed/default
routes, selected configuration refusals, and before/after bundle drift. Their
presence or discovery is not a native execution receipt. The preceding D7
component development run executed all 55 original controls through 595 real
native entries; ordinary-entry results require the new independent D8 run.
No default provider, matching-current-source cold result, composite ownership
transfer or whole-verifier qualification is claimed here.
