# Native cold descriptor and CLI binding

The cold entry can be assembled from HIA sources, a relative recipe, actual
source/toolchain manifests, and fresh native inventories of its plans. These
components replace runtime use of the development descriptor assembler. They
perform no compilation with the compiler under qualification, manufacture no
successful observations, and do not claim that the full 180-second cold replay
has passed.

## Production roles

| HIA source | Standalone role | Input | Output |
| --- | --- | --- | --- |
| `cold_plan_inventory.hepta` | `hia-cold-plan-inventory` | Actual `HIAQPL01` plan | `HIAQPS01` inventory |
| `cold_descriptor_compose.hepta` | `hia-cold-descriptor-compose` | `HIAQCA01` | Complete `HIAQBD01` descriptor |
| `cold_cli_bind.hepta` | `hia-cold-cli-bind` | `HIAQBC01` | `HIAQCP01` packet |
| `cold_descriptor_filter_packer.hepta` | Component transport packer | `HIAQPF01` plus flat image | Standalone component ELF |

All four sources are in `examples/hia_bootstrap`. The existing
`cold_cli_packer.hepta` consumes the final `HIAQCP01` packet and produces the
ordinary `hia-cold` executable. The existing generic filter packer wraps the
small component transport packer; that native packer then wraps the three
component policies. No development author or script is invoked by this graph.

The initial qualification built each component through the independently
pinned HIA assembly frontend, register projector and explicit seed div profile.
The report records source, Core, register-wire, flat and ELF identities. A
release construction graph must retain that independent construction provenance
and the original explicit seed profile. Using B3 to create an independent
reference would change the trust boundary and is not authorized here.

## Ownership and inputs

`cold_bundle_recipe.hiadat` is the `HIAQBT01` relative recipe for the complete
60-phase, 53-root, 907-binding graph. Its stable metadata owns the ordering,
family/label identities, dependencies, role assignments, relative source names,
node counts and publication bindings. It has no absolute QA paths, source
manifest, source hash, toolchain image hash or target compiler bytes.

The production owner must pin this recipe and obtain the two manifests from
its actual captured files. Every plan receipt must come from executing the
pinned native inventory on the same captured plan whose size and hash appear
in the source manifest. These receipts are transport records, not signatures;
accepting arbitrary externally supplied receipts as trusted facts would not
meet this contract.

The source manifest includes the relative recipe and all reconstruction
sources. The generated descriptor and bound CLI are runtime products. They
must not be added to their own input manifest. The generic CLI HIA source
contains no descriptor hash. Its packer binds the four actual images after
composition. This removes the hash cycle while keeping the generic CLI source
reconstructible and source-bound.

All integer fields below are little-endian unsigned 64-bit values unless
explicitly stated. Hashes are raw 32-byte SHA-256 digests. Names and paths are
ASCII; names admit letters, digits, underscore, hyphen and dot and cannot begin
with a dot. Relative paths admit the same characters plus slash and reject
empty, dot, parent, `.git` and `__pycache__` components.

## Plan inventory

The inventory consumes the actual `HIAQPL01` bytes. It checks the original
32-byte plan header, exact node extents, 1..65536 nodes, opcodes 1..17,
identifiers at most 4096, at most 128 arguments per node, and at most 1 MiB of
node data. It does not execute the plan or replace the driver's opcode-specific
semantic checks.

Import names are deduplicated in order of first occurrence, with at most 64
unique imports. Publications must be unique and are retained in plan order,
with at most 4096 publications. The entire actual plan is hashed by HIA.

`HIAQPS01` has an 80-byte header:

| Offset | Field |
| --- | --- |
| 0 | Eight-byte magic |
| 8 | Actual plan byte length |
| 16 | Actual node count |
| 24 | Unique import count |
| 32 | Publication count |
| 40 | Exact receipt byte length |
| 48 | SHA-256 of the entire plan |

The tail contains imports followed by publications, each as length then raw
name bytes. There is no tail padding.

## Descriptor composition

`HIAQCA01` has a 64-byte header. Offsets 8, 16, 24 and 32 are the lengths of
recipe, source manifest, tool manifest and receipt bundle. Bytes 40..63 must
be zero. The four corresponding byte sections follow in that order.

Both manifests use the existing `HIASXM01` format: magic, count, version 1,
reserved zero, then sorted rows of path length, actual file byte length,
SHA-256 and raw relative path. Each manifest is bounded by 1 MiB and has
1..16384 entries; each member is bounded by 64 MiB. Duplicate or unsorted paths,
invalid path components, zero digests and nonexact extents are rejected.

The receipt bundle is `HIAQPB01`, a phase count, then a length and full
`HIAQPS01` receipt for each phase in recipe order.

The recipe uses exactly the public descriptor's header and table layouts,
except for magic `HIAQBT01` and these required zero fields:

- Header manifest length, source count and manifest SHA are zero.
- Header manifest offset and total length both equal the table extent.
- Every root's size and digest are zero.
- Every phase's plan size and digest are zero.

The composer fills these fields from the actual manifests and inventories.
It verifies all source-class root and plan memberships; exact plan node counts
and hashes; actual imports versus binding names; actual earlier publications
versus publication bindings; all infrastructure root identities; unique IDs;
prior-only dependencies; one base following all references; and all 19 families
with exactly one original and one modified phase. Every qualification compiler
must be the current base's `B3.flat` or `M3.flat` publication for its own label.
No starting static root can substitute for that compiler binding.

The output is the complete existing `HIAQBD01` descriptor, at most 2 MiB,
including the original source manifest bytes and their actual HIA SHA-256.
The descriptor format and the 2 phase / 1 archive / 2 pending / 4 unsealed
scheduler limits remain unchanged.

## Four-pin CLI binding

`HIAQBC01` has a 64-byte header. Offsets 8 through 48 contain six lengths:
descriptor, master ELF, process-owner ELF, source-exporter ELF, generic CLI
policy flat, and SHA companion flat. Offset 56 must be zero. The six byte
sections follow in that order.

The binder revalidates the complete descriptor, including actual manifest
hash, table structure, source memberships and topology. It checks the three
ELF headers and requires the actual process-owner ELF hash to equal the
descriptor's fixed cold-owner root hash. The descriptor and three ELF digests
are calculated over the actual supplied bytes. The output is the existing
`HIAQCP01` packet: magic, policy length, SHA length, four digests in the same
order, policy flat, SHA flat.

ELF header checks establish the supported container shape; they are not proof
of executable semantics. The construction owner must supply the independently
pinned role images. The binder intentionally binds actual bytes rather than
substituting a previously successful image hash. The following native CLI
packer and the runtime entry retain their existing validation gates.

## Capacity and transport

The pure entry for each component has the existing six-word buffer ABI:
input pointer/length, output pointer/capacity, workspace pointer/capacity.
Input, output and workspace are disjoint caller-owned buffers. Output capacity
must be exactly 8 MiB and workspace must be at least 2 MiB. Inventory and
composition inputs are bounded by 64 MiB; binding input is bounded by 8 MiB.
Return values are a successful byte count or `0xfffffffd` for ABI capacity
rejection and `0xffffffff` for malformed input. Failure output is not a
published product.

The component transport reads at most 64 MiB, uses an 8 MiB output and a
16 MiB private workspace, and invokes only its embedded HIA policy. Its
`HIAQPF01` pack input is magic, flat length, flat bytes. It accepts no arguments.
The transport emits only successful output; policy refusal exits 2, input
capacity refusal exits 3, I/O failure exits 4, and argument misuse exits 64.
This component transport does not alter any compiler observer, phase import,
process-owner pass-FD, VM, or cold wall-clock budget.

## Qualification boundary

The recorded positive qualification freshly inventoried all 60 actual plans,
then produced a 595547-byte descriptor byte-for-byte equal to the existing
frozen descriptor. Native binding plus native CLI packing produced the exact
456640-byte CLI used in the second real full run. That full run reached its
original 180-second deadline and failed; its failure remains separate from
component qualification.

The component tests cover malformed headers, extents, names, paths, manifests,
role identities, dependency direction, source/inventory mismatch, missing
imports and publications, compiler provenance, duplicate family/label pairs,
actual owner-image mismatch, the exact 64 MiB boundary and 64 MiB plus one,
4096/4097 publications, 64/65 imports, all six-word ABI capacity boundaries,
input preservation, and output/workspace guard bytes. The first oversized-input
fixture incorrectly expected policy exit 2; the existing mechanical transport
correctly returned its documented capacity exit 3. That development failure
was preserved, and the corrected fixture requires exactly exit 3 for that one
case. It does not broaden any production refusal rule.

Machine-readable construction identities and qualification counts are in
`HIA_COLD_DESCRIPTOR_NATIVE.json`. Full cold closure, source-only retirement,
public installation and installed self-rebuild remain separate integration
gates owned by the final native release graph.
