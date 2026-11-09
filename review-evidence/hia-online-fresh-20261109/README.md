# Fresh read-only installation and freeze preflight

The public metadata source was read at main
`74063163ad19d096a4ff9a66a6f25728e6ce0d8f`. Its exact public release lock
remains 37,527 bytes, SHA256
`9000d6eaa089f6bed92ea07a6561d91381a6f913263f0b1016d4f99e8789c1d3`.
It selects Hepta `2598f4309791d3a023cd5df585ad26810b20c744`, runtime
`4cd85c99c5f5a480832c48fbde8561bb365f67a9`.

Fresh formal `hia_describe(manifest)` and `hia_read` completed under their
original request identities. The newly described manifest reference was passed
directly to the read tool; it was not constructed or substituted. The complete
manifest SHA256 is
`d05cf5c78bed8da1cb9486f307097e4a2303780dd76da1c7ee44bafbee08969c`.
The unchanged existing checker, source SHA256
`ff9669c365b4056de643129376a3e4868396745f542adf90ef1fb4c114014542`,
was executed on these new captures and returned
**PASS_CURRENT_INSTALLATION_READBACK**, all three identities matching.
`verification.json` contains its exact result. This confirms the currently
selected 2598 installation only; it neither publishes nor attests a new v16
source, a running controller binary, continuous uptime or subsequent state.

The controller configuration was inspected only by `file_info`; its content
and credentials were not read. Observed SHA256 remains
`0e74611087fd297c5f1e4631656573242107b3d9d38e924762cc97e6b2e6ff2d`,
4,306 bytes, mode0600, one link, uid501/gid20. No configuration writes,
freeze/drain calls, process signals, restarts, rollback or CAS apply occurred.

## Freeze and owner gates remain open

- `process_list_page(host=main, limit=1)` still refuses with INVALID_ARGUMENT,
  `durable inventory total source byte bound exceeded`. This is not an empty
  or complete inventory.
- The private owner archive read returned `archive index preparing or
  validation unavailable`. This observation cannot certify absence of other
  in-flight operations or a parallel owner.
- `service_status` only examined the system launchd domain, returned113 and
  explicitly `observation_complete=false`. It cannot establish the state of
  the user-domain controller.
- The currently exposed tool inventory has no admission freeze/drain API.
  A compiler-context freeze or immutable read snapshot does not freeze runtime
  admission. Zero configured named privileged actions is also not a freeze.

These are read-only observations. The source runtime repository main lookup
through the connected GitHub fetch returned404; no source-runtime integrity
fix is claimed from unavailable source. The concrete next controller work is
an owner-authenticated, durable admission barrier and a bounded, complete
registry snapshot taken under that barrier, followed by drain/active-lease
readback before any CAS transition. A fabricated `admission_frozen=true`
statement cannot satisfy that contract. The obsolete 321 CAS plan must not be
applied. Existing state, journal and artifacts remain intact.
