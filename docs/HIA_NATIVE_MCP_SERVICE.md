# Native HIA MCP service components

These sources are components of the standalone HIA service. A successful component qualification does not qualify a complete MCP server, configuration capture, durable job bridge, production activation or deletion of a predecessor runtime.

## Component interfaces

| Source | Native interface | Qualification |
| --- | --- | --- |
| `mcp_service_session.hepta` | Existing six-argument buffer ABI; preserves initialization state and raw IDs; returns `HIAMSQ01` dispatch descriptors for all 11 tools and HIA resource reads | 67 cases, original protocol phases and exact 8 MiB input boundary |
| `mcp_service_reply.hepta` | Private JSON `{id,kind,modern,payload,uri}` to one JSON-RPC reply; typed tool results and resources keep their original response distinctions | 73 cases, all statuses, escaped IDs, Unicode, primitive resource results and output expansion refusal |
| `mcp_canonical.hepta` | JSON bytes to sorted canonical JSON under pinned serde_json 1.0.151 with `float_roundtrip`, without `arbitrary_precision` | 572 cases against an independently pinned Rust oracle, including binary64, signed/unsigned boundaries, negative zero, long decimals and Unicode |
| `mcp_service_config.hepta` | Private `{configuration,default_state_dir,catalog_sha256}` to the admitted HIA profile, selected host, controller state path and alias identities | 82 cases covering profile defaults, native job pins, Operator/Isolated administrative distinctions, component path containment and refusal boundaries |
| `mcp_service_admission.hepta` | Preserve canonical arguments, admit the current catalog, apply the original SSH/SFTP artifact-path normalization and strict HIA resource URI rules | 95 cases, including alias collisions, explicit identity refusal, path containment and byte-preserving nonpath fields |

The canonicalizer requires the duplicate-free JSON already admitted by the session component. It does not claim to reproduce serde_json's acceptance of duplicate object members. It preserves the current 8 MiB JSON input bound, 262,144 nodes and depth 128. The private reply frame reserves 9 MiB for a maximum-size request ID plus an independently bounded domain response; the public request bound remains 8 MiB.

The service configuration component validates the HIA administrative slice. Unrelated runtime providers are outside its interface. A configuration result is not an authenticity proof: the effect owner must first capture the administrator-selected file, compare its independent SHA256, admit the controller manifest against its supplied trusted pin, capture the complete fixed role inventory and retain immutable descriptors. Native Job entries must be complete and have the original exact role basenames and lowercase SHA256 pins. Isolated administrative acceptance is not evidence that the durable bridge's system-jobctl migration is complete.

## Dispatch descriptor

`HIAMSQ01` is 96 bytes, little-endian: magic followed by eleven u64 words. The fields are action, raw ID offset/size, tool ordinal, argument offset/size, modern-protocol flag, parameter offset/size, and two reserved zeros. Actions are tools/list=1, tools/call=2, resources/list=3, resources/templates/list=4 and resources/read=5. Public tool ordinals are the catalog's original 1..11; resource read is private ordinal 12. Empty argument spans become `{}` in the owner. A dispatch descriptor grants no filesystem or execution authority.

## Required complete-server gates

The actual owner still needs authenticated stable configuration and controller capture, canonical argument and original schema admission, original URI/path normalization, the durable Job bridge, complete stdio framing and fragmented-input handling, terminal/response/proof admission, and fresh Direct/MCP public-client qualification from the matching final installation. Missing gates remain missing; none is replaced by component counts.

## Reproduction

The five `generate_hia_mcp_*` authoring modules emit checked-in HIA sources. Their matching `qualify_hia_mcp_*` programs invoke independently compiled flat images on the CPU. The canonical qualifier additionally requires a separately compiled, explicitly SHA256-pinned serde_json oracle. Python and Rust in these qualification drivers are independent development-time references, not the native component's runtime implementation.
