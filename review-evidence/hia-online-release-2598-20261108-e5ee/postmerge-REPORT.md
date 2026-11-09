# Post-merge public installation and formal manifest readback

**Result: PASS_CURRENT_INSTALLATION_READBACK for the recorded public v9 selection. Overall six-item acceptance remains HOLD.**

This follow-up binds main merge commit `bd4b846359a7f3200593750304aa744422221793` (tree `7d82ae7e6072e0e33b002f9ab1791c9fe18828d2`) to its own successful public-installation CI and a separately recorded post-merge formal connector observation. The selected source remains `2598f4309791d3a023cd5df585ad26810b20c744`, profile `selfhost-core-linux-x86_64-v9`. The release lock remains the original source-CI bytes: 37,527 bytes, SHA256 `9000d6eaa089f6bed92ea07a6561d91381a6f913263f0b1016d4f99e8789c1d3`.

## Main's public installation gate

- [Public installation run 42552762057](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42552762057) and [retained online-readback run 42552762051](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42552762051) both completed successfully for that exact main commit before the formal calls below.
- Public artifact `13645358721` is 95,427 bytes. GitHub's digest and the actual downloaded ZIP hash both equal `c40ae57156623ff949c71d9be78ced12ad6415c11ad9ca99fb3a8ba70d7d8952`. Its nine member hashes are retained in [the artifact inventory](postmerge-ci-artifact-files.json).
- The installed manifest's worker/backend/catalog identities match the lock. The artifact's native qualification reports 173 tests, zero failures/errors/skips/unexpected successes, complete inventory, clean source, and unchanged source `2598f430…` / tree `4c073a29…`.
- [Complete captured CI metadata](postmerge-ci-raw-metadata.json), [provenance and decoded job-log hashes](postmerge-ci-provenance.json), and both [public-install](postmerge-public-install-ci.log) and [retained-readback](postmerge-online-readback-ci.log) decoded logs preserve these observations. The source lock's qualification flags were not edited; its `production_deployed` flag remains false.

## Formal connector observations

All times below are UTC observations from the session clock, not a server execution attestation.

| Invocation | Observed interval | Outcome |
| --- | --- | --- |
| New `hia_describe`, `section=manifest`, `max_bytes=4096` | 02:49:24–02:50:48 on 2026-11-09 | completed; server-issued immutable manifest reference |
| Read attempt 1, `max_bytes=16384` | 02:51:14–02:53:14 | MCP transport timeout `-32603`; original failure retained |
| Independent read attempt 2, `max_bytes=8192` | 03:01:50–03:03:18 | completed; 7048 UTF-8 bytes, explicit `next_cursor: null` |

The second read used the exact artifact reference returned by this describe. Its server request ID is `r-4e303025817e2d0f35dae5e8964af7b1732e190fb813d2792903f5f0bbb7b720`. The manifest is artifact `a-7f9b7e5f5bb041c2aa4977e6cdc4b8db`, URI `hia://artifacts/55e2e5105fec409f842905c2cbf9272e`, SHA256 `d05cf5c78bed8da1cb9486f307097e4a2303780dd76da1c7ee44bafbee08969c`.

The complete [describe envelope](postmerge-formal-hia-describe-result.json), [initial timeout envelope](postmerge-formal-hia-read-timeout.json), [successful independent read envelope](postmerge-formal-hia-read-result.json), [exact manifest bytes](postmerge-formal-manifest.json), and [call parameters/times](postmerge-call-observations.json) remain separate. The successful read did not relabel or replace attempt 1.

The unchanged main checker has SHA256 `ff9669c365b4056de643129376a3e4868396745f542adf90ef1fb4c114014542`. It exited 0 with [PASS_CURRENT_INSTALLATION_READBACK](postmerge-readback-verification.json); [execution hashes and exit code](postmerge-checker-execution.json) bind its exact inputs and output. The successful envelope file hashes are `a0d2c526ee0801b6b40beec3bb143b073a22d78e927e72c1cdbe2d7b3792bdc5` (describe) and `1c10958704d76fd758a4abcf07c6851508188bcccc7488e379b81c06fe4af09b` (read). These are wrapper-file hashes, not canonical payload hashes.

| Installation identity | Lock, public CI install and formal manifest |
| --- | --- |
| worker | `7f767953145e722f4cf62cbb4e3617fa2f9b388f3940ad926b5bb9a7309ae642` |
| backend | `929d12c5e99c8df5cc8c138aad7e9d527560b31dd8953126beec0a2920f0febe` |
| catalog | `61325aadc2fa6740c84037227c9410f5e299267d908cfbbd0be6b05eedfbfbf8` |

The [main-selection guard](postmerge-main-guard.json) observed main still at `bd4b846…` after the successful read. The default `main` lock was fetched again and equalled the exact-commit lock and original source-CI bytes. This publication adds evidence without changing that release selection. Publishing these observations does not require an endless cycle of new live reads after commits that only retain evidence and preserve the same source selection.

## Recovery, idempotency and limits

The original 16384-byte request was matched to historical job `1a1bc68b35c-138b0-249` using its full WorkerRequest and selected-profile digest, the durable idempotency key, and the complete process-request digest reconstructed from original arguments, environment and stdin including its final newline. The exact controller and native request digests agree. A formal status read confirmed the historical job had succeeded with complete durable output. [The public recovery projection](postmerge-operation-recovery.json) retains necessary hashes and identities; private paths and configuration records are excluded. [The original status envelope](postmerge-original-operation-status.json) is unchanged. This recovers the historical operation's identity, not the missing transport response for attempt 1.

The [pinned runtime provider source](https://github.com/TrillionniumFoundation/hepta-runtime/blob/4cd85c99c5f5a480832c48fbde8561bb365f67a9/src/mcp/hia_provider.rs) derives a stable key for the same read-only arguments and profile, and an existing binding observes the retained job instead of executing again. The service `r-` request ID omits the runtime profile and cannot by itself bind an operation. The matching manifest reference and identical describe bytes are therefore expected to be stable. The bounded examination of the newest 40 native records found no newly executed worker corresponding to the successful 8192-byte request. **New native worker execution is not established or required by this manifest-readback result.** The positive claim is that a new formal tool invocation successfully reread the server-issued immutable artifact after main's CI gates.

One read-only controller-registry diagnostic stopped at its explicit 10,000-entry preflight bound, before reading records. Its exact failure/status observations remain in [preserved diagnostics](postmerge-preserved-diagnostics.json); an exact known record was read instead. Static inspection of the [pinned durable job implementation](https://github.com/TrillionniumFoundation/hepta-runtime/blob/4cd85c99c5f5a480832c48fbde8561bb365f67a9/src/mcp/runtime/jobs.rs) identified full metadata scans on a non-Linux controller. No segment timings uniquely attribute the transport timeout to that path or to the separate SSH observations. The original worker process budget is not the total wall-time bound of a reused MCP readback. No budgets, online configuration, virtual environment or services were changed for this follow-up.

The source-lock runtime commit is a release mapping. This record does not attest the loaded controller executable or its build provenance, source-only runtime loading, new worker execution, endpoint uptime, later installation state, or a deployment by the reader. The earlier 69-test diagnostic remains **68 pass / 1 fail**, with its redaction provenance, and was not rerun here. All prior preparation-time and historical-source reports retain their original scopes. Complete Core self-hosting, general machine/ABI/resource/FFI/ISA/loader proof, full unfamiliar-Agent lifecycle and costs, and stable NDU benefit remain separate open acceptance items; no later candidate publication is claimed.

## Deterministic replay

```sh
python -B review-evidence/hia-online-release-2598-20261108-e5ee/postmerge-replay.py
```

The replay checks the current lock, unchanged checker, complete successful formal envelopes, retained timeout, original-operation status, main/CI metadata, included CI artifact-member bytes and documented chronology. It reproduces the committed output without making a fresh network call or claiming that local replay authenticates the original capture. The existing three historical/preparation replay steps remain unchanged; the workflow adds this independent post-merge replay.
