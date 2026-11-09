# Runtime PR111: existing Linux CI qualification

[Runtime PR111](https://github.com/TrillionniumFoundation/hepta-runtime/pull/111) remains a draft source candidate at `82de085a0223a6a3a3bf9573902bf252c4a0c8bf`, tree `bfc93c575fd30131f0ce3462009ebb00b247495d`, based on the fixed runtime `4cd85c99c5f5a480832c48fbde8561bb365f67a9`.

Both original runs completed successfully on attempt 1:

- [Pull-request run 42568198837](https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/42568198837).
- [Push run 42568171207](https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/42568171207).

The three executed jobs bind the exact head or the actual prospective merge `3f4ed70beb991ca4e9d159a19e967fdb5859ebdf`, whose official tree is the same `bfc93c57`. In each job the all-feature suite records **2,389 passing and 40 skipped tests**; the no-default-feature suite records **2,360 passing and 28 skipped tests**. These are repeated configurations, not 14,247 distinct tests. The push event's prospective-merge job is conditionally skipped.

The new Python helper's **42 pure-fake tests are separate earlier local evidence**. This existing Rust workflow does not invoke that Python suite. CI success does not turn fake activation into a real Mac deployment.

The package retains all 13 frozen original observation files plus their original manifest (14 files, 7,511,361 original bytes) in `original-ci-records.tar.xz`. Its 372,604 bytes have SHA256 `51dbfc16ef9dd0860c0c8ff9629bd99306ed09560831996032fa5f905fd57b63`. This includes complete original decoded job logs, their tool envelopes, actual checkout metadata and terminal summaries. Root independently re-read both public run statuses; those additional responses are separate files.

Run `python -I -B verify.py` to check the retained archive and every original file without extraction or execution. The actual invocation and output are included.

This result establishes the existing Linux CI qualification for the source candidate. Real Mac build/load identity, trusted loaded-configuration evidence, private state/lease compatibility, independent operational admission and actual activation remain outside this result. No live service, formal HIA call, operator action or default release change was performed by this qualification.

