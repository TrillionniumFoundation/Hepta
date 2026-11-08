# Independent online installation readback — 2026-11-08

## Result and scope

The independent adf1 connector observation matches all three installation
digests in the public release lock selected by entry commit
`b4080858698e1b0f26d87f185b847ff9e1133fd1`.
It corroborates the point-in-time gate closed by [PR #806](https://github.com/TrillionniumFoundation/Hepta/pull/806).
This update adds a second retained observation and reuses the existing
`tools/check_hia_online_readback.py` checker and its fourteen adversarial tests.

The retained capture was recorded at **2026-11-08 16:56:08 UTC**. This is its
recording timestamp, not a claim of continuous service availability or a
transport-signed observation time.

| Field actually returned by the live installation | Observed SHA-256 |
| --- | --- |
| worker_sha256 | 1183286165c276737e1d25acb47b982134db2a7150df23887186bac34ca53c4f |
| backend_sha256 | 929d12c5e99c8df5cc8c138aad7e9d527560b31dd8953126beec0a2920f0febe |
| catalog_sha256 | 61325aadc2fa6740c84037227c9410f5e299267d908cfbbd0be6b05eedfbfbf8 |

The release-lock SHA-256 is
`1c4b747721bfc215549512287d62febbadfaf7bce3cd2b6baafeed3d67a10c18`.
The live manifest does **not** return a Hepta Git commit, runtime Git commit,
release-lock digest, or runtime executable digest. The source commit
`321daf28ef230a532f0f382469a9f6fc4f4fa249` and runtime commit
`4cd85c99c5f5a480832c48fbde8561bb365f67a9` are mappings from that exact lock.
The reader performed no deployment, configuration change, or service restart.
Loaded-code attestation, running-runtime binary provenance, subsequent releases,
Core completeness, general machine correctness, Agent adoption, provider costs
and NDU benefit are outside this readback result.

## Retained evidence

The directory
[hia-online-readback-20261108-adf1](../review-evidence/hia-online-readback-20261108-adf1)
contains the original combined tool observation, the evidence-specific replay,
its result, and the existing checker's test log.

The original combined observation SHA-256 is
`3e8b34564c97b65142e1d0a7144785a76ad573e965560e55ab1facf80d4867d7`.
The original describe and read response objects are retained together with their
arguments, including the unmodified text payloads and structured payloads.
The manifest bytes are checked against the server-issued artifact digest
`5bf8e9071d5905da4814f3a952b831f238fc721967ba0e5b707648066f13ae1d`.

The replay reads the already retained exact lock from the PR806 evidence
directory. It canonically serializes the two response objects for the existing
checker; those serialization hashes do not claim to hash transport framing.
The complete original capture remains independently pinned.

## Reproduce

From the repository root:

```bash
python3 -B review-evidence/hia-online-readback-20261108-adf1/replay.py
python3 -B -m unittest tests.test_hia_online_readback -v
```

The shared readback workflow executes both retained captures and all fourteen
existing negative controls. Its second replay must reproduce the committed
result exactly. The existing public release workflow also runs for the
`codex/hia-sixgap-entry-*` branch family.

The offline checker confirms byte consistency and the declared bindings. It
cannot authenticate the historical endpoint or establish freshness by itself;
those facts remain attached to the actual connector observation.
