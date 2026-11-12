# Native type first-error context, independent revision 1

## Status and purpose

This is new source with **0 AST, 0 HIA generation, 0 B3 and 0 native execution** at delivery. The CI driver performs all of those steps independently. It does not replace any published image or declare the whole Worker or P16 path complete.

FOLLOW44's fixed diagnostic route actually completed 177 passing cases and four failing public payload comparisons. Its separate 100-control private fixture group failed before its first native entry. Those original results remain distinct. The four public comparisons demonstrate that the native type adapter's generic enum table omits the original public location, including "nominal type", "field" and "type parameter".

This owner records the first relevant error at the actual native semantic call site. A second HIA image reads the actual type workspace and completed result header, then emits the original complete text. No Python formatter supplies the location.

## Exact retained owner and semantic change

The reference is commit 0ef9541b2fc12f4b01ab5078b05d0b304cfa90f5. Original type authoring is bcae24eb4bf540d05c80a42e5712983e4199cdae, 68,113 bytes, SHA256 8989302bfd890ca9fa43662413a27c88c740c0060cb7631b7c1e4ef332cfa3e7. The original HIA is 380,145 bytes, SHA256 33969ee0fdec37c27ebf017c52d01e20748118d643589cf280042a39f68e3d6b. Its fresh old-image compile must reproduce the original 541,021-byte image with SHA256 dbe484770638ac36b72fc5930eb03862e4ee27f1e532f3a3b7c30acc5cd78612.

The old public _name calls the complete _ident grammar before the h2internal_ namespace test. The old native name_ok tested that namespace before scanning the complete ASCII grammar. This revision moves only the namespace check after the complete native grammar. Thus h2internal_bad$ must change from old native error 6 to public-correct error 5. This is an explicit semantic correction, not a text-only equivalence claim. The corpus includes five independent contexts for this old/new difference.

The source adapter changes eight original functions and adds three context helpers. All other function ASTs are compared exactly. The descriptor rendering and commit functions, private task/origins admission functions, generic first-error register and shape validator remain AST-identical. Calls to the corrected name validator still inherit its deliberate first-error change; AST identity is not claimed to cancel that change.

## Actual owner state record

The existing 128 MiB type workspace reserves its final 32 MiB region at S = 96 MiB. Existing scalar state ends at S+184; DEFS begins at S+4096. The new 64-byte record is at S+192 and cannot overlap either.

| Byte offset in record | u64 value |
| --- | --- |
| 0 | HIATDX01 |
| 8 | Version 1 |
| 16 | Native error 1, 5 or 6 |
| 24 | Exact semantic location ID |
| 32 | Original required-field bit mask; zero for names |
| 40 | Actual private Q/D arena node offset, or existing missing-node sentinel for a shape error |
| 48, 56 | Zero |

The magic is written last. The record is written only when the existing first-error register was zero. It is reset after successful command decoding, before dispatch. Init additionally retains its existing full state reset. It does not add a command count, descriptor count or language limit.

The 18 location IDs are emitted only at their corresponding original semantic sites: nominal type, type parameter, enum variant, variant, task poll function, task cancellation function, nominal field, field, type reference, partial record type, initialized record field, generic type reference, generic type name, nominal parameter, parameter, nominal returned-loan origin, returned-loan parameter and returned-loan field.

There are 24 name messages (12 sites × errors 5/6) and nine exact required-field inventories. Their expected public text is independently produced by the unchanged original _Types/_Elaborator methods before any native entry.

## Reader ABI and lifetime

The new context reader is **R/R/W**:

1. The actual immutable 128 MiB type workspace from the just-completed semantic call.
2. A 128-byte immutable private command.
3. A writable output, initially 128 bytes for measurement.

The first 64 command bytes contain eight little-endian u64 words:

`[HIATDC01, 1, typeLease, commandSequence, callerRequest, typeOperation, actualFrameBytes, 0]`

The following 64 bytes are the actual returned native type header. Operations retain the existing numbering: init 1, parameters 2, resolve 3, partial 4, origins 5, task_protocol 6.

The reader validates the complete input extents, command version and nonzero correlations, actual header kind and extent, type-state marker/lifecycle state, error and cache/active/step counters, context version/reserved fields, legal node range/alignment and exact message tuple. It does not authenticate a caller merely because those integers match. The fixed coordinator must retain the actual immutable workspace and completed frame and call this reader before the next type command or cleanup.

A command/output shorter than the minimum framing is refused first. For a valid 128-byte output header, all semantic state/context checks precede payload capacity handling.

The output's first 128 bytes contain 16 u64 words:

`[HIATDE01, 1, typeLease, commandSequence, callerRequest, operation, error, location, expectedMask, nodeOffset, textBytes, 128+textBytes, cached, active, steps, 0]`

With insufficient payload capacity the return is 0xfffffffe and the complete header is written. With enough capacity, the return is the complete extent and the payload is the complete UTF-8 diagnostic. The fixed caller repeats the exact same immutable leases for a capacity retry and requires both result headers to match.

A malformed command returns 0xfffffffd. This stateless reader is not a session poison owner. The eventual coordinator must terminate the failed private lease. The protocol corpus explicitly includes private counterexamples showing that a different nonzero correlation, another valid context tuple, or another aligned in-range node can be accepted if the trusted issuer premise is violated. Those are not public-input authentication results.

## Independent actual qualification

Three images are freshly compiled with the original historical 0e09 compiler:

- Exact original type owner.
- New first-error-context type owner.
- New context reader.

The six semantic groups contain 54 scenarios. Old/new commands operate on two independent actual 128 MiB workspaces and 64 MiB outputs. Every full advertised input/output/workspace and canary is retained as ordered page CAS with full buffer hashes. The old/new comparison allows only the new 64-byte context; the five explicit mixed-prefix cases additionally permit only the native error word in output and state. All descriptor payloads, other state, counters and unused output bytes must remain identical.

The original public oracle is run before the native interval. During that interval the corresponding original Python semantic methods are replaced with a rejecting sentinel. Actual native text must equal the precomputed full public exception text byte for byte. Partial parameter resolution includes a descriptor committed before a later name failure and a subsequent command using that original ID. The lifecycle group exercises all six operations and context clearing after successful follow-up commands.

The seventh group has 64 malformed/framing/capacity/private-trust controls. It begins with an actual native context, then copies its exact bytes into a clearly private, unissued fixture. The original actual issuer workspace is not mutated. All source/command readonly checks, output canaries and restored clone bytes are retained.

Each group keeps 90 CPU seconds, 180 wall seconds and 1 GiB address space, with measured aggregate process-tree CPU strictly below 90. Each B3 retains 10 CPU seconds, 20 wall seconds and 256 MiB. HIA limits remain 128 functions, 1536 blocks, 8192 operations, 256 blocks per function, 16 block parameters and SSA numeric suffix below 2048.

All seven groups are attempted independently after a successful three-image build. A failed group remains failed. Successful sibling groups do not close the component as a whole.

## Remaining P16 integration

This delivery deliberately does not claim that the final fixed P16 process already consumes the new record. The subsequent integration must preserve the actual type workspace after validated REPLY and before initializer cleanup; call this reader; retain the complete immutable diagnostic capsule; carry it through actual constructor/service/ordinary/program child contexts; and replace the current generic public failure only after checking the complete native association.

The current role46 diagnostic-program author must be restored and proven to regenerate its actual frozen HIA before modification. An earlier author with a similar filename is not an acceptable replacement. Groups 6 and 9 and other public diagnostic context gaps remain separate work. A private Graph node, nonce or program record never becomes namespace authority.
