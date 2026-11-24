# Native release stage plans and request framing

The retained release builder has 191 ordinary source recipes and ten additional
stages. This component moves the additional stages' source-group declarations,
dependency ordering, output inventory, and thirty binary request constructors
into HIA. It does not claim that the whole release coordinator is native.

The authoritative runtime sources are:

- `examples/hia_bootstrap/release_stage_sources.tsv`
- `examples/hia_bootstrap/source_release_stage_plan.hepta`

The table was derived from the declarations used by
`tools/build_hia_native_store_release.py`, including the Core, constructor,
Store, helper, Read, and SQLite builders. Source aliases and groups are ordered;
paths are relative to `examples/hia_bootstrap` unless a resource record says
otherwise. The ordinary member count is not encoded in the protocol. A
coordinator may add ordinary tools without changing the additional-stage ABI.

## Declared stages

| Stage | Owner | Final members |
| --- | --- | ---: |
| 1 | Safe Core proof | 1 |
| 2 | Nominal constructor | 1 |
| 3 | Core applications and scalar implementation | 25 |
| 4 | Flat helper images and manifests | 16 |
| 5 | Store modules and root | 5 |
| 6 | Agent stdio | 1 |
| 7 | Read carrier | 1 |
| 8 | Owned reference | 1 |
| 9 | SQLite units, projection and pager | 13 |
| 10 | SQLite migration publisher and coordinator | 2 |
| | Total | 66 |

The legacy 267-member inventory also contains the separately admitted bootstrap
resources, source seed and compiler manifest. The 66 additional names do not by
themselves prove that a 267-member release has been built.

## Invocation and plan ABI

Compile this policy with the admitted selfhost and the existing
`source_build_packer.hepta` under the source seed's ordinary three-object ABI.
The resulting ELF accepts one argument, `build`, and a stdin request.
All integers below are unsigned little-endian 64-bit integers.

A table starts with the ASCII line `HIASTG01<TAB>10<TAB>66<LF>`.
Subsequent tab-separated lines have a kind, a decimal stage number, and the
fields below. Every line, including the last, must end with LF. Empty fields,
non-ASCII bytes, invalid counts and trailing data are rejected.

The result starts with `HIASTP01`, followed by stage count, record count and
output count. Each record is `kind, stage, field_count`, followed by that many
`length, bytes` pairs. There is no terminator or padding.

| Kind | Table spelling | Fields |
| ---: | --- | --- |
| 1 | stage | label |
| 2 | need | producer stage in decimal, product name |
| 3 | compile | group, alias, relative HIA source path |
| 4 | kit | policy source, application/packer source |
| 5 | resource | repository-relative captured resource path |
| 6 | output | final flat member name |
| 7 | framing | operation in decimal, eight-byte magic, status |

For example, the constructor source record is kind 3, stage 2, and the three
fields `constructor`, `composite_constructor_owner.hepta`, and
`composite_constructor_owner.hepta`. A consumer groups adjacent compile rows
by stage and group while preserving their order. A kit has the existing
`NativeReleaseSources` meaning: admitted selfhost plus the named policy and
application/packer, with the existing source-builder aliases.

HIA requires contiguous stage declarations, complete stage categories, unique
output names across the entire plan, and unique aliases within each stage's
source group. A positive dependency producer must be earlier and must already
have declared that exact output. Producer zero means an independently admitted
input from the base inventory; the coordinator must resolve and authenticate it.
The planner does not authorize missing or unpinned external products.

Paths cannot be absolute or contain empty or dot-leading components. Source
aliases have no separators and end in `.hepta`. Source groups are bounded to
128 aliases, the plan to 16 stages, 128 outputs, 1,024 compile rows and 256 KiB
of input. The policy uses 64 KiB of workspace, within the existing seed limits.

## Native binary request constructors

A framed request starts with `HIASTF01`, then five integers:
`stage, operation, ordinal, auxiliary, piece_count`.
Each piece is `length, bytes`. Auxiliary is currently zero. Pieces must be
nonempty; their exact number and the allowed ordinal are checked by HIA.
No padding or trailing bytes are accepted.

The output is the original stage policy's exact binary request. The caller
supplies captured bytes and references; HIA selects the magic, validates role
ranges, and constructs the specialized header and body. The existing semantic
owner must still consume and authenticate that request.

| Stage | Operation | Output magic | Ordinal and input pieces |
| ---: | ---: | --- | --- |
| 2 | 1 | HIACTPT1 | Part 0 or 1; adapter source |
| 2 | 2 | HIACTAD1 | 0; adapter source, first object, tail object |
| 2 | 3 | HIASQAD1 | Publication transport 1 or 2; adapter source |
| 2 | 4 | HIACTIM1 | Component 39 through 58; HIA source |
| 2 | 5 | HIACTLK1 | 0; 3 transport objects and 20 component objects |
| 4 | 1 | HIAHLM01 | Helper 1 through 8; source, image, selfhost source, compiler |
| 5 | 1 | HIAAWFL1 | Unit 0 through 24; plan, compiled unit |
| 5 | 2 | HIAAWBN1 | Module 0 through 3; plan and its 6/5/5/6 ordered units |
| 5 | 3 | HIAAWMF1 | 0; plan and four ordered modules |
| 5 | 4 | HIAAWR01 | 0; plan, loader, owner, manifest, JSON hub |
| 6 | 1 | HIAAGS01 | 0; three sources, their three images, nine ordered catalogs |
| 7 | 1 | HIARDIN1 | Entry 1 through 4; HIA source |
| 7 | 2 | HIARDLK1 | 0; four alternating source/entry-ELF pairs |
| 8 | 1 | HIAOCM01 | 0; five alternating source/image pairs |
| 8 | 2 | HIAORUN1 | 0; owned-reference source |
| 9 | 1 | HIASQAD1 | Adapter 0 through 4; adapter source |
| 9 | 2 | HIASQUN1 | Unit 1 through 9; HIA source |
| 9 | 3 | HIASQCP1 | 32; capture HIA source |
| 9 | 4 | HIANMPK1 | 33; nominal JSON HIA source |
| 9 | 5 | HIASQPR1 | Projection component 1 through 11; HIA source |
| 9 | 6 | HIAPGIM1 | 34 or 35; pager or stream HIA source |
| 9 | 7 | HIASQLK1 | 0; two adapter objects and an image object |
| 9 | 8 | HIANMLK1 | 0; nominal adapter and image object |
| 9 | 9 | HIASQPL1 | 0; projection adapter and eleven component objects |
| 9 | 10 | HIAPGLK3 | 0; two pager adapters and two image objects |
| 10 | 1 | HIASQAD1 | Adapter 0 or 1; adapter source |
| 10 | 2 | HIAMGIS1 | Source role 36 through 38; HIA source |
| 10 | 3 | HIAMGEL1 | Child role 17/18 or 20 through 23; child and 32-byte digest |
| 10 | 4 | HIAMGPL1 | 0; adapter, two source objects and two child objects |
| 10 | 5 | HIAMGCL1 | 0; adapter, source object and four child objects |

The pinned-child constructor places the digest before the child exactly as the
existing embedding ABI requires. It checks the digest's length; the HIA semantic
consumer and the owning publication path must verify the digest's content. The
constructor cannot establish the truth of a caller-supplied fingerprint.

## Remaining coordination and semantic checks

Stage 1's nested proof records, children, outer proof frame and placement checks
remain to be scheduled. Stage 3's adapter relocation records, compressed nested
images, nominal links, dependency pins and source overrides remain to be
scheduled. Requests to frame unsupported stage/operation pairs fail closed.

The eight other stages have native wire constructors, but that fact alone does
not replace their complete stage functions. Their executable DAG must still
capture and authenticate inputs, compile declared groups, build kits, execute
the ordered calls, compare the admitted compiler, validate embedded-image and
adapter placement claims, and publish only verified products. Store module/root
pins, helper image pins, Read placement, owned-reference private-entry checks,
and migration dependency provenance are required checks.

No GC, timeout, source admission, compiler capability or old acceptance
condition is altered by this component. The separate Slot observation gate
remains HOLD; this release-stage work does not change that result.

## Verification

`tests/test_hia_release_stage_plan.py` checks the HIA program and all source
paths, compares all 66 outputs with current stage declarations, and compares
ordered constructor/helper groups with their declarations.

Set `HIA_TEST_RELEASE_STAGE_PLANNER` to the source-compiled ELF to exercise the
complete binary plan, malformed-table rejection, all thirty framing operations,
and invalid role/count/length rejection with an empty PATH.

Also set `HIA_TEST_NATIVE_SOURCE_SEED` to run the actual existing HIA helper
manifest, SQLite embedding, and Store word-filter consumers. The word-filter
result must match the declared image size and SHA-256 in the admitted Store
plan. These tests execute native compilation and consumers; they do not replace
any complete release qualification.
