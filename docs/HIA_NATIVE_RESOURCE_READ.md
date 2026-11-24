# Native resource reads through the HIA Worker

The native Worker now accepts the existing private `hia_resource_read`
operation used by MCP `resources/read`. This is internal ordinal 12; the
advertised catalog still has eleven public tools.

## Preserved request and journal identity

The original private tool name and arguments enter the existing journal
before URI resolution. The request digest is therefore the same digest used
by the previous Worker. The existing phase 7 / action 7 transition performs
resolution; the existing stage 4 transition changes the execution tool to
public `hia_read` only after successful resolution. No journal-core gate or
request-key algorithm was changed.

A successful resolution retains the sealed Store row and uses its artifact
ID and SHA256 to construct an ordinary Read plan. That plan is compared
byte for byte with the original public Read planner. The resulting public
arguments pass the original Read input schema, catalog, installation and
metadata checks before the normal Read effect runs.

An unknown URI returns `E_HIA_ARTIFACT_IDENTITY` with the original message
`resource URI was not issued in this runtime namespace`. Its rejected
journal record retains the private resource operation. A successfully
resolved request uses the existing public Read cost and terminal path.

## Native frames and custody

* The resource request is admitted as an `HIAARD01` plan with flag 4
  identifying URI resolution and flag 1 identifying the explicit byte
  limit. The default byte limit is 65,536; the supported interval remains
  512 through 65,536.
* The first sealed Store query selects the issued resource URI. It does not
  interpret the caller's URI as a filesystem path.
* `HIAURB01` binds the admitted resource plan to the ID and digest spans of
  that retained row. It returns an ordinary `HIAARD01` Read plan. The
  immutable catalog and limit are checked again across this boundary.
* `HIAURJ01` renders that ordinary plan as length-prefixed public Read
  arguments for the existing input-schema and journal transition.
* The resource preflight closes its Store and effect capabilities before
  the normal Read execution continues. The installed role order and role
  count remain unchanged.

The route and resource logic are authored in HIA. Python files in this
change are development generators and qualification drivers; they are not
selected by the installed Worker.

## Qualification

`tools/qualify_hia_worker_resource_lowering.py` executes the native
sealed-input ELF request planner. It compiles the supplied original Read
source with the supplied native source builder and packs that reference
with the native packer. Eighteen positive cases cover three artifact
identities and default / boundary byte limits; all returned plans match the
original planner exactly. Nine malformed inputs are refused. The driver
records and rechecks all supplied input hashes.

The matching-v95 component qualification passed all 27 cases. Its original
receipt SHA256 is
`480e24ee23c774c07370de950386510245f1c162d57ef215caf4a8e8c799d003`.

A private complete installation containing these components passed actual
MCP execution and same-job replay against the frozen Rust runtime:

| Case | Verified behavior |
| --- | --- |
| Short text | Identical resource envelope and serialized Read result |
| Unicode | Identical UTF-8 content through the 65,536-byte read bound |
| Paged text | An 80,000-byte artifact returns the first 65,536 bytes and a cursor |
| Unknown issued-resource namespace URI | Identical rejected error code and message |
| Exact replay | Eight public call responses and four resource responses match; job files are unchanged |

The successful actual-transport receipt SHA256 is
`8c84d9f8d05bddfa62962b60b66cc6ac5319ad3d361e7e7b26a6c8087f8fbde3`.
The oracle executable SHA256 is
`beb253af13ab729bd8c25c96f2d4b80a2c931c905ad33559ef8997f4cabf43c7`.
That comparison also exposed and verified a separate MCP framing fix:
completed resource content includes `mimeType: text/plain`.

These are component and actual-transport qualifications. A complete fresh
cold build, ordinary package, installed rebuild, and combined release
qualification remain required after aggregation. Malformed private
resource arguments are not claimed to have full diagnostic equivalence
beyond the documented refusal cases.
