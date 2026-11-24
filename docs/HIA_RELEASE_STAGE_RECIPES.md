# Native special-stage release recipes

The two `HIASTD01` resources describe the complete invocation order for the eight nonuniform release stages already listed in `release_stage_sources.tsv`. A HIA release owner interprets them using captured, source-pinned bytes and sealed native programs. The development generator derives source groups, component order, adapter bytes, expected Store pins and output names from the retained current declarations. It is not part of the runtime release path.

Execution order is Safe proof, `release_stage_constructor.hiastd`, Core products, then `release_stage_additional.hiastd`. The constructor fragment publishes one product. The additional fragment publishes the other 39 products from stages 4 through 10. Safe proof and Core remain separately owned fragments; these two files do not claim to describe their 26 outputs. New ordinary members do not change the meaning of an import or any node handle.

Each fragment resets its local view table. The published-product registry persists across fragments. `IMPORT` resolves an exact, unique product name in the current invocation's admitted registry, including its sealed bytes and provenance. It must not accept an arbitrary external file with the same name. In particular, `selfhost.image.bin` is the independently admitted compiler image, and `hia-catalog` is available only after the Core fragment has published it.

## Wire format

The header is `HIASTD01` followed by little-endian u64 node count and publication count. Each node is four u64 values `(operation, handle, argument_count, payload_bytes)`, then its u64 arguments, then the exact payload. There is no padding or trailing data. Producing nodes have unique handles from 1 through 2048. Every view reference must name a preceding producing node. Effects and checks (operations 7 through 10) have handle zero and produce no reusable byte view. The declared publication count must equal actual `PUBLISH` nodes.

| Operation | Arguments | Payload and result |
| --- | --- | --- |
| 1 CAPTURE | output tag as little-endian u64 | Payload is u64 count, then repeated `(alias_bytes, path_bytes)` u64 lengths followed by alias and repository-relative path. The owner binds independent source pins and the repository directory FD into `HIACAP02`, then invokes the native capture ELF with no argv. |
| 2 COMPILE | capture handle | Invoke the admitted source seed's `sources` entry. Retain captured source and compiled-image metadata. |
| 3 KIT | capture handle | Invoke the native kit composer with `HIAKOBJ1`; retain the checked `HIAKIMG1` object footer and source association. |
| 4 PICK | group handle, zero-based ordinal, source/image | `source/image` is 0 for the declared source and 1 for its compiled image. Source order always follows CAPTURE alias order. |
| 5 FRAME | stage, operation, ordinal, auxiliary, piece handles... | Submit the pieces to the HIA `HIASTF01` framer. Auxiliary is zero for these recipes. |
| 6 RUN | executable handle, operation, stdin handle | Operation 0 uses no argv; 1 is `sources`, 2 `pack`, 3 `build`, and 4 `compile`. A kit's checked footer is removed before executing its ELF extent. The result is exact stdout from a successful child. |
| 7 PUBLISH | result handle, expected digest handle or zero | Payload is the flat product name. A nonzero expected handle must be exactly 32 raw SHA256 bytes. Publish the complete result; no implicit footer removal. |
| 8 EQUAL | two view handles | Require identical lengths and bytes. |
| 9 SHA | view handle | Payload is an independent 32-byte expected SHA256 digest. |
| 10 CHECK | mode, calls/role, piece handles... | Invoke the native `HIASTC01` checker and require its exact success frame. |
| 11 IMPORT | none | Payload is an exact product name in the invocation's checked sealed registry. |
| 12 DATA | none | Return literal payload bytes, including a possible empty extent. |
| 13 DIGEST | view handle | Return its 32 raw SHA256 bytes. |
| 14 CATALOG | catalog executable handle, version | Invoke the actual catalog with `--schema hepta.hia.program.vN`, for versions 1 through 9. |
| 15 SLICE | view handle, offset, length | Return a bounded range. Length `2**64-1` means the remainder after the checked offset. |

CAPTURE has three uses. Compilable source groups use `HIANAM01`. Kits use `HIAKOBJ1` and alias order `source_build_policy.hepta`, `selfhost.hepta`, `source_build_packer.hepta`; their policy and application paths are specific to each kit. Standalone adapter, plan or other resource captures use `HIARAW01` with one row. A RAW result has no named header; `PICK(group, 0, 0)` is the complete captured byte extent. The capture owner parses the root FD, checks pins, refuses symlinks, and verifies source stability. The recipe never supplies an unverified dynamic FD or manufactures a success receipt.

## Preserved product checks

The constructor, SQLite units and migrations use the existing source-admission and static-object HIA owners, followed by real native linking and exact embedded-image checks. Migration children are imported from the current sealed registry, hashed into their embedding frames, and checked again in the linked executable. This replaces temporary mutable `build.json` transport with the current owner's provenance-bound registry; it does not permit files imported only by name.

The helper stage checks every generated manifest against its actual source, compiled image, compiler and declared helper protocol. The Store stage checks its bundle-packer image pin, module and root pins, complete adapter placement, and recaptures its plan and adapter before publication. The Read carrier checks each inner ELF and its complete outer placement; the four adapter resources are exact derivations of the original flow/ports declarations. Owned-reference construction keeps its exact private-entry and adapter checks. Agent stdio obtains all nine catalogs by invoking the real native catalog program.

`HIASTC01` mode 5 uses the calls field as helper role 1 through 8, with pieces `(manifest, source, image, compiler)`. The manifest must contain exactly the five expected string fields; field order and JSON whitespace may vary. The native producer's unescaped ASCII string representation is admitted; duplicates, unknown or missing keys, malformed strings and trailing data are refused. All three SHA256 values are computed in HIA from the supplied views. Schema and image path derive from the declared helper role.

Mode 6 uses calls zero and one piece containing the public artifact publisher. It preserves `control_descriptor` semantics: the complete ELF header, all three program headers, delivery note and all fixed descriptor words must match, and the public/private entry relationship must be valid. The original host's private/public round trip changes only the validated entry word. No object hash alone grants identity or substitutes for checking actual bytes.

## Verification scope

`tests/test_hia_release_stage_recipes.py` independently decodes the binary graph, checks source and adapter derivation, and exercises modes 5 and 6 against independent retained observations. A development driver can execute every node through the real native capture, source compiler, kit composer, framer, checker and linked children. Such component execution remains separate from the full HIA owner loop, complete matching cold qualification, whole-product behavior gates and final repository cleanup.
