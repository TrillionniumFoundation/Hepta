# Online HIA identity readback, 2026-11-08

The current conversation completed `h.hia_describe(section="manifest")` and
read the exact immutable artifact with `h.hia_read`. The artifact's worker,
backend and catalog identities all equal the public release lock from
`TrillionniumFoundation/Hepta` entry commit
`b4080858698e1b0f26d87f185b847ff9e1133fd1` (merged PR #805).

The artifact bytes hash to their server-issued SHA256. The saved public lock
hashes to the original CI lock digest
`1c4b747721bfc215549512287d62febbadfaf7bce3cd2b6baafeed3d67a10c18`.

This closes the narrow missing-online-installation-readback obligation for the
named release. It does not close transport stability: an independent second
`hia_describe` call with identical arguments returned MCP `-32603 Internal error`.
Both observations are preserved. The second call began at
`2026-11-08T16:56:27.863Z`, completed at `2026-11-08T16:56:28.620Z`, and took
0.757 seconds. Start/end timing was not captured for the first describe/read;
no latency estimate for those calls is asserted.

## Evidence

- `describe-manifest-01.*.json`: successful discovery request and exact response.
- `read-manifest-01.*.json`: retained-artifact read request and exact response.
- `retained-manifest-01.json`: exact UTF-8 artifact bytes, with no added newline.
- `describe-manifest-02.*.json`: independent repeat, including failure and timing.
- `public-release-lock.json` and `.source.json`: immutable lock and retrieval identity.
- `identity-comparison.json`: three installation fields and bounded gate conclusions.
- `evidence-index.json`: file digests and publication scope.

Recheck the evidence offline with `python3 verify_identity.py`.

No live configuration, worker source, service process, slot or adoption state
was changed by this capture. No runtime-binary digest, full lifecycle acceptance,
longitudinal availability, unfamiliar-Agent adoption, stable NDU benefit or
general correctness claim is established here. A later selected release needs
its own readback.

## Reconstruction after environment replacement

The local execution environment was replaced during the follow-up diagnosis.
Raw responses and immutable artifact bytes were recovered from retained
in-session tool results. This reconstruction introduces no observation times.
The later index timestamp marks reconstruction only.
