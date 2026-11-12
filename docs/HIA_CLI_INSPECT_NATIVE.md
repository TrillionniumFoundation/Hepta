# Native ordinary inspect owner

This component implements the existing `hia inspect INPUT` report after the
ordinary full Core verifier has admitted the input. Its explicit selector is
`HEPTA_HIA_CLI_INSPECT_MANIFEST`. An absent selector retains the existing route;
an empty or invalid selection refuses and does not fall back.

The image accepts an immutable framed capture of canonical primitive Core and,
when the verifier produced it, the canonical structured input. It contains the
original HIA integer JSON arena decoder and SHA-256 algorithm, both with bounded
read-only views. HIA computes both digests, chooses the exact schema/profile,
sorts public scalar entrypoints, copies every original signature and block,
adds each operation index, and publishes the complete original inspect report.
Python does not supply a digest, normalized report, selected fields, exported
name set, policy verdict, or result template.

The output keeps the original `hepta.hia.inspect.v1/v2` schema and every field,
including v8 return-loan defaults and `native_executed: false`: inspection does
not execute the inspected program. The ordinary CLI still performs its original
input reads, full verification and JSON formatting. Host object materialization,
structured elaboration, primitive checking, file custody, process management and
fourteen other CLI actions are outside this component's claimed ownership.

## Private protocol and bounds

The six-argument entry receives three byte buffers. The request starts with
8 little-endian u64 words: `HIAINSQ1`, version 1, Core byte count, structured
byte count, structured-present bit and three zero words. Exact Core bytes then
exact structured bytes follow. Each span retains the original 8 MiB ceiling.
The HIA decoder retains 262,144 nodes and depth 64. No caller-provided receipt
or serialized `VerifiedProgram` replaces ordinary verification.

A completed reply has an eight-word header: `HIAINSR1`, version 1, complete
JSON byte count, function count, block count, operation count, structured bit,
and zero. The magic is written last. Scratch and output exhaustion refuse;
the adapter rejects malformed headers and does not return partial JSON.

The arena bound is 64 + 56 times the source-derived node bound plus the largest
input span. An additional 32 KiB holds two digests, state and two 1,024-entry
sorting arrays. Output reserves the larger of 4 MiB and four times the largest
input plus 1 MiB. The first bound also covers the unchanged decoder's key table.
Every original Core field is copied at most once; operation indices add fewer
bytes than their original operation records. The remaining MiB covers duplicate
public names (at most 1,024 names of 128 bytes), default loan arrays and fixed
report syntax. These are private allocations, not smaller public input limits.

## Development and qualification

The strict builder requires a completed matching-source cold report and its
actual compiler image before creating output. It retains the existing image,
compiler child, resource-custody and manifest rules. An explicit development
compiler in the tests is separately labeled and cannot supply matching-source
qualification. Native execution, installed-package behavior and ordinary CLI
byte equality must be observed before integration. Neither static generation
nor a component test result establishes whole-CLI or whole-language closure.
