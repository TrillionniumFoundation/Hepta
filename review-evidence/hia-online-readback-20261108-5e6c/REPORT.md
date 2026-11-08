# P0: current installation identity read back and matched

**PASS for the point-in-time installation-readback gate of public entry
`b4080858698e1b0f26d87f185b847ff9e1133fd1`, selecting Hepta
`321daf28ef230a532f0f382469a9f6fc4f4fa249`.**

The initial formal `hia_describe` and `effective_config` calls returned
`Internal error -32603`. Their original results are preserved in
`evidence/initial-tool-observations.json`; that file gives their recording time,
not exact invocation start times. A later `hia_describe` succeeded and returned
a server-issued immutable manifest reference. Its matching `hia_read` completed
within **2026-11-08 16:51:34.149–16:52:27.896 UTC**. No cause for the initial
failures is asserted.

The verifier independently rehashed the exact content and found:

| Subject | SHA256 |
| --- | --- |
| Original public release lock | `1c4b747721bfc215549512287d62febbadfaf7bce3cd2b6baafeed3d67a10c18` |
| Exact returned manifest content | `5bf8e9071d5905da4814f3a952b831f238fc721967ba0e5b707648066f13ae1d` |
| Worker, identical live and locked | `1183286165c276737e1d25acb47b982134db2a7150df23887186bac34ca53c4f` |
| Backend, identical live and locked | `929d12c5e99c8df5cc8c138aad7e9d527560b31dd8953126beec0a2920f0febe` |
| Catalog, identical live and locked | `61325aadc2fa6740c84037227c9410f5e299267d908cfbbd0be6b05eedfbfbf8` |

Replay from the repository root:

```sh
python -B tools/check_hia_online_readback.py \
  --lock review-evidence/hia-online-readback-20261108-5e6c/evidence/public-release-lock-b408085.json \
  --lock-sha256 1c4b747721bfc215549512287d62febbadfaf7bce3cd2b6baafeed3d67a10c18 \
  --describe review-evidence/hia-online-readback-20261108-5e6c/evidence/formal-hia-describe-result.json \
  --read review-evidence/hia-online-readback-20261108-5e6c/evidence/formal-hia-read-result.json
python -B -m unittest discover -s tests -p test_hia_online_readback.py -v
```

Actual results: `PASS_CURRENT_INSTALLATION_READBACK`; **14 tests passed**.
Negative controls cover worker-only drift, artifact rebinding, content
tampering, incomplete pages, nonterminal/rejected results, connector errors,
conflicting text/structured results, missing identities, incorrect lock digest,
duplicate JSON members and nonfinite numbers.

**No deployment, configuration change or service restart was performed by this
reader.** The captured endpoint identity is not proof of a deployment action,
runtime executable identity/build provenance, source-only Python loading,
continuous availability or future state. The lock names runtime
`4cd85c99c5f5a480832c48fbde8561bb365f67a9`, but this manifest read alone does not
attest that runtime binary. Later releases, including Selfhost-Core v10, require
their own new exact-lock readback. The remaining Core/proof/Agent/NDU gates are
not changed by this result.

For public evidence, retain the two original formal connector envelopes, exact
manifest bytes, public release lock, readback observation, verification result,
test log and initial error observations. Private host/path inventory probes are
not part of the publication package. The offline verifier checks these retained
captures under their recorded tool provenance; it does not itself authenticate
an endpoint or manufacture a fresh observation.
