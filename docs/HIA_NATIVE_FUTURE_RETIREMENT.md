# Native Future retirement integration

The current nine-role capsule combines the inherited Future and complete Value
kind baseline at commit 369aa8d5deadd4334efa59836379902dcf284f95 with the explicit
retirement producer at ebfa9864b0c56cfb265dba4cd2e82083aead90ba. The older offline
producer records remain historical evidence for their captured sources.

## Constructed and tested scope

HIA compiler 494833999e25ac74ea6ad1de41235c01bfa036951f212604026cb8be686c78af
compiled all 22 required source modules twice with identical results. The actual
native HIA packer produced both the relocatable object and the flat image; both
matched the independent byte-layout oracle. Its original admission limits remain
4 MiB per role and 16 MiB combined text.

The current component gate passed all 62 retained original Value-kind comparisons,
50 native packer layout/admission/capacity controls, and four normal lifetime
groups. These groups exercise exact consumption of independent Future and factory
references, a live Future surviving the last factory lease followed by retirement
using the real factory identity, two public owners sharing one Value arena, and
new-profile framing plus copied-context refusal.

The public image is 3,481,833 bytes with SHA256
94c527cadd669dae70e19ef90ed0ddc8e3c2066d18706bde68f3026a3b9158fe.
Its embedded Value image is 1,943,959 bytes with SHA256
6aa48162de9636fd9a3a4552efce0cfa789e007db36aa261a1f3291134ea27b4.
Every actual source and compiled role is bound in
HIA_NATIVE_FUTURE_RETIREMENT_QUALIFICATION.json.

All five retained offline producer probes also pass against the merged author
policies. Those probes remain explicitly modeled source evidence; the native
component qualification comes from the actual compiled gate above.

The original 27-group inherited campaign and the full syscall-failure campaign
must be rerun against this exact nine-role image before a complete Future release
claim. The four original custom truth-method cases remain in the oracle as
pending native callable dispatch. This component does not claim whole Future,
whole BackgroundOptimizer, or whole runtime closure.

## One shared continuation, two fixed policies

Combining both authors without partitioning yields 106 functions, 1,712 blocks,
and 9,187 operations, exceeding the preserved 1,536-block and 8,192-operation
limits. The current generator partitions only by reachable calls:

| Policy | Functions | Blocks | Operations |
| --- | ---: | ---: | ---: |
| Public owner | 85 | 1,241 | 7,037 |
| Callback carrier | 57 | 623 | 2,908 |
| Future cell | 43 | 672 | 3,049 |
| Cleanup and public continuation | 85 | 1,042 | 4,694 |

The public owner uses action 11 to select the fixed cleanup policy for phases
1500 through 1791. The cleanup policy uses action 12 to return to the fixed
public owner when that continuation leaves its phase range. Both policies use
the same input, output and actual context; no state is serialized through a
host callback. The mechanical bridge only selects those two fixed HIA addresses.

The cleanup role retains its private HIABFC01 request domain. Its first HIA
function distinguishes that request from the public continuation by the admitted
magic. A private cleanup frame still requires 32,768 output bytes; the shared
public continuation requires 65,536.

## Preserved identity and persistent custody

The public 256-byte context now assigns its last words as follows:

| Offset | Meaning |
| --- | --- |
| 200 | Count of outstanding authenticated type/name recovery records |
| 208 | Actual context address captured during initialization |
| 216 | Fixed cleanup entry installed by the mechanical bridge |
| 224 | Global temporary-reference cleanup chain |
| 232 through 255 | Unused by this integration |

The independent type/name recovery chain remains at factory offsets 200 through
231 with its original nonce and extent checks. Producer temporary records remain
at factory offset 152; they do not overwrite the recovery chain. Producer guard
phases moved from 1600–1691 to 1700–1791 to preserve the type/name retry phases.

The cleanup owner verifies the actual context address before acquiring its
registry mutex. An idempotent public close also verifies that address. Global
close keeps the Value context token while either cleanup chain remains present.
No old drop status is treated as proof that a capability was consumed.

HIABFP03 operations 26–29 expose Future drop, factory-lease drop, factory
retirement retry and global close. HIABFQ04 operation 21 observes the actual
retirement list under the cell mutex. The old HIABFP01/02 and HIABFQ01/02/03
request domains and reply layouts remain available in this capsule.

## Packing and reproduction

The current pack request is HIABFPP3, exactly 96 header bytes, count 9 at offset
8, nine role lengths at offsets 16 through 80, and mode 0 or 1 at offset 88.
Mode 0 emits the relocatable object; mode 1 emits the complete flat image.
The role order is owner, carrier, timeout, log, cell, kernel, value, notify,
cleanup. The older eight-role packer remains a separate profile and cannot
construct this partitioned owner.

Run from the source root with a fresh external output directory:

    python3 -m tools.qualify_hia_future_retirement \
      --compiler /absolute/path/to/the/pinned/hia-source-build \
      --output /absolute/path/to/fresh/retirement-evidence \
      --receipt docs/HIA_NATIVE_FUTURE_RETIREMENT_QUALIFICATION.json

The actual current run is background-future-retirement-v3 under the external
followthrough evidence root. It preserves source and product hashes throughout
the build and executes every retained Value-kind comparison on the newly packed
image. It does not rewrite the earlier inherited or Value-kind qualification
records to make them claim this later product.
