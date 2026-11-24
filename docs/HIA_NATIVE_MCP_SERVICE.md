# Native HIA MCP service components

All semantic components below execute as HIA-compiled native images. The complete
owner is described in `HIA_NATIVE_MCP_OWNER.md`; component tests do not substitute
for the installed service's actual business, audit and lifecycle gates.

## Interfaces

| Source | Native responsibility |
| --- | --- |
| `mcp_sdk_request.hepta` | Full SDK JSON Value scanning, typed structs/sequences, request/notification/response classification, normalized request-ID identity and SDK transport compatibility |
| `mcp_service_session.hepta` | Negotiation, initialization lifetime, supported SDK controls and HIA dispatch descriptors |
| `mcp_service_reply.hepta` | Exact JSON-RPC tool/resource response shape, errors, IDs and protocol metadata |
| `mcp_canonical.hepta` | Pinned serde_json-compatible canonical Values, sorted keys, last-value-wins maps, binary64 formatting and signed/unsigned boundaries |
| `mcp_input_diagnostic.hepta` | Original raw HIA schema diagnostics and error priority before canonicalization and canonical argument-budget admission |
| `mcp_service_config.hepta` | HIA profile, selected host, optional native-job transport, controller state path and alias identities |
| `mcp_service_admission.hepta` | Current catalog admission, original artifact-path normalization and HIA resource URI rules |
| `mcp_job_bridge_*.hepta` | Persistent job admission, publication, supervision transport, terminal capture and same-job replay |
| `mcp_request_audit_*.hepta` | Durable request-ticket ownership, records, retention, recovery and terminal response publication |

SDK transport framing admits 16 MiB including LF. HIA business admission retains
its separate 8 MiB raw domain, 262,144 nodes and depth 128. The SDK scanner does not
consume the smaller business canonicalizer's tree budget for unrelated opaque
Value fields. Invalid UTF-8, nonfinite numbers and malformed typed known fields
retain the frozen SDK's classifications. Compatibility handling of unknown
notifications is a transport rule, distinct from serde's typed model result.

## Private SDK projection

`HIASDK01` is twenty little-endian u64 words. It carries message kind and method
role; original ID, method, parameter and argument/URI spans; HIA tool ordinal;
normalized numeric ID and kind; protocol metadata; missing-field flags; negotiated
version ordinal; and cancellation target span/kind/value. Span low 24 bits store
start+1, the next 24 store the exclusive end, and bit 63 marks a duplicate. The
SDK component returns the 160-byte projection in its private output mode and
canonical ID text in its distinct output mode. These are owner-to-component ABIs,
not user-selectable public request fields.

## Dispatch descriptor

`HIAMSQ01` is 96 bytes: magic followed by eleven little-endian u64 words. Its
fields are action, raw ID offset/size, tool ordinal, argument offset/size,
modern-protocol flag, parameter offset/size, normalized numeric ID and ID kind.
The last two words are used; they are not reserved zeros.

Actions are tools/list=1, tools/call=2, resources/list=3,
resources/templates/list=4 and resources/read=5. Public HIA tool ordinals remain
1..11; HIA resource read uses private ordinal 12. SDK default controls such as
prompts/list, subscribe/unsubscribe and completion are handled in the session
without granting filesystem or job authority. Empty argument spans become `{}`
before original schema admission.

## Complete executable inventory

`HIAMSP03` consists of magic, 24 u64 component sizes, the bridge and audit SHA256
values, then the ordered component bodies. Its 264-byte header binds ten owner
components, ten pure components, JSON scanning, streaming SHA256, the complete
job bridge and the complete request-audit executable. Component flat images keep
the existing 1 MiB compiler bound; the two embedded executables have separate
bounded extents. The native packer checks full packet exhaustion.

Authoring tools emit the checked HIA sources. Independent qualification may use
Python, frozen Rust/serde or a host assembler as an explicit development oracle.
Ordinary native release executes the checked HIA DAG, compiler, packers and fixed
syscall transport; those development oracles are not service continuations.
