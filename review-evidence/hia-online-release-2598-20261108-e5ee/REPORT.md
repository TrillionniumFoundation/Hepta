# Align the public v9 selection with the observed worker

The retained formal connector capture matches the original successful
`2598f430` source-CI lock in all three installation fields. The unchanged main
checker returns **PASS_CURRENT_INSTALLATION_READBACK** for that lock and
**HOLD_INSTALLATION_MISMATCH** for the preceding public `321daf28` lock.
This publication selects the observed, independently source-checked v9 release.

The capture was obtained **before this metadata publication**. Public
installation CI on the actual metadata commit and a fresh formal readback after
its merge are separate acceptance records. This replay does not perform a new
endpoint call. Whole-project acceptance remains **HOLD**.

## Exact source and original CI evidence

| Item | Recorded identity |
| --- | --- |
| Source commit | `2598f4309791d3a023cd5df585ad26810b20c744` |
| Source tree | `4c073a29839eff1e75fbcc6dd28db4108c04160c` |
| Profile | `selfhost-core-linux-x86_64-v9` |
| Runtime source in the lock | `4cd85c99c5f5a480832c48fbde8561bb365f67a9` |
| Runtime tree in the lock | `6b78d53b53d51a6c070bb37e8e9f6a15ad26d0e8` |
| Original release-lock bytes | 37,527 |
| Original release-lock SHA256 | `9000d6eaa089f6bed92ea07a6561d91381a6f913263f0b1016d4f99e8789c1d3` |
| Original CI artifact | `13626118637`, 14,730,386 bytes |
| Original artifact SHA256 | `e05ffacd052fd71de606457afd3c19d89cb514c346a7b8431085274fb54e353e` |

[Exact source CI 42503095942](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42503095942)
completed successfully on that precise source. Job `128799870089` includes
freeze/check of the release lock, direct native and proof qualification, cold
selfhost replay and declared language coverage. Its original Agent native log
records **83 tests passed in 56.347 seconds**. The same source's
[NDU scalar integration run](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42503095787)
also succeeded; integration success does not establish economic benefit.

The artifact digest and size returned by
[GitHub's artifact metadata](https://api.github.com/repos/TrillionniumFoundation/Hepta/actions/artifacts/13626118637)
match the independently downloaded ZIP. The archived `release-lock.json`,
`release-lock.sha256`, source identity and successful freeze/check logs were
read from that ZIP. [source-ci-provenance.json](source-ci-provenance.json)
retains their identities. The selected lock is copied without reformatting or
changing its qualification flags. The default public entry and preflight
helper are byte-identical to the corresponding selected source files.

## Retained formal observation and independent checking

| Installation field | Observed and selected v9 lock |
| --- | --- |
| Worker | `7f767953145e722f4cf62cbb4e3617fa2f9b388f3940ad926b5bb9a7309ae642` |
| Backend | `929d12c5e99c8df5cc8c138aad7e9d527560b31dd8953126beec0a2920f0febe` |
| Catalog | `61325aadc2fa6740c84037227c9410f5e299267d908cfbbd0be6b05eedfbfbf8` |

The two original connector envelopes, including both text and structured
payloads, are retained. Their artifact descriptors agree. The complete,
one-page UTF-8 content has 7,048 bytes and SHA256
`d05cf5c78bed8da1cb9486f307097e4a2303780dd76da1c7ee44bafbee08969c`,
equal to the server-issued artifact digest. The exact content is preserved in
[formal-manifest.json](formal-manifest.json).

The checker is the unchanged `tools/check_hia_online_readback.py` from main
`725956474ff6fe6a592e4516d395cc23d065c6c3`, SHA256
`ff9669c365b4056de643129376a3e4868396745f542adf90ef1fb4c114014542`.
The actual CLI executions returned exit **0** for the original v9 CI lock and
exit **1** for the old public lock. Both full conclusions remain:
[matching v9 readback](readback-verification.json) and
[old-lock mismatch](prior-public-lock-mismatch.json).

Independent read-only observations checked 219 Python/discovery inventory
members for each of the old and selected workers. Both inventories matched
their respective Git path sets and Git blob bytes, and both working trees were
clean. The current worker's independently calculated inventory digest equals
`7f767953...`. No mixed source was established.
[source-inventory-observation.json](source-inventory-observation.json)
is the public projection; private process paths and configuration remain outside
this package. Full canonical response-payload hashes were used to compare
native observations because the same response request ID appeared in older
records. Payload hashes are distinguished from raw connector-envelope file
hashes.

The observed source selection already existed. This publication changes no
online configuration, service, executable or virtual environment. The manifest
does not attest the loaded runtime executable, its build provenance or a
source-only Python loader, and it does not establish continuous availability.
Its runtime commit is a mapping from the source-CI lock. All current source and
installation statements are limited to the recorded observations.

## Preserved recovery diagnostic and limitations

The first manifest request in this session failed because its selected Python
path was absent; the authoritative original process record returned exit 127.
The original job was observed rather than replayed. Six missing qualification
fixtures in the preceding `321daf28` checkout were restored create-only from
their exact Git blobs, and its 32 bytecode-cache files were moved intact into a
separate recovery record. These actions did not change the selected v9 source.

A virtual environment appeared concurrently. Its creation is **UNKNOWN** to
this reader, who did not create or overwrite it. Its seven recorded HIA
dependency versions matched the previous dependency record, and the active
jsonschema/Z3 dependency closure checked successfully. The separate
environment-wide `pip check` failed because an inherited PyNaCl distribution
lacked cffi; that failure was not replaced by the narrower closure check.

A diagnostic on the preceding `321daf28` checkout then ran **69 tests**:
**68 passed and one failed**, with no skips, in **112.388 seconds**. The failing
test was
`NativeLifecycleTests.test_reference_loop_cannot_restart_or_overrun_frozen_context_deadline`.
It deliberately left 100 ms of its original 3,000 ms context budget before
evaluation. The observed result was admission rejection
`E_HIA_BUDGET: context total wall budget has expired`. That is consistent with
admission or scheduling consuming the remaining interval; no passing retry or
production-deadline extension is claimed.

The full [69-test log](old-source-native-diagnostic.log) is retained with only
its private source-root prefix replaced. The original complete raw log remains
preserved separately; its exact digest and the redaction rule are in
[old-source-native-diagnostic.json](old-source-native-diagnostic.json).
This prior-source diagnostic does not replace or requalify the selected v9
source's own successful CI.

General Core support, a universal compiler/ABI/resource/FFI/ISA/loader theorem,
the unfamiliar Agent's complete lifecycle and provider costs, and stable NDU
incremental or economic value remain open. The later v13 candidate retains
separate qualification and publication requirements. Historical `321daf28`
records remain attached to that source.

## Replay and remaining publication gate

From the repository root:

```sh
python -B review-evidence/hia-online-release-2598-20261108-e5ee/replay.py
```

The replay uses the unchanged main checker. It requires the current public
lock to equal the retained original source-CI lock, checks both public helper
hashes, reproduces the matching v9 result and the old-lock negative control,
and verifies the exact separate manifest bytes. It does not retrieve a new
manifest or reauthenticate GitHub. The online-readback workflow retains both
older historical replay steps and adds this check, including triggers for
changes to `releases/hia-current.json`.

After publication, retain the actual main public-installation CI and obtain a
new formal describe/read pair against the then-current main lock. Record that
pair separately from this preparation-time capture.

## Later post-merge record — 2026-11-09

The preparation-time gate above is retained as it was recorded. [The separate post-merge record](postmerge-REPORT.md) binds main `bd4b846359a7f3200593750304aa744422221793`, its successful public installation and retained-readback CI, the initial formal-read transport timeout, and a later successful independent formal read against the unchanged original v9 lock. It does not reclassify this earlier capture as post-merge or transfer historical qualification to a new source.
