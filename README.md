# Original HIA artifact byte custody

This minimal standalone workflow transports the fixed original GitHub artifact
named by `target.json`. The target is the failed d994 push Native run's original
569,518,893-byte ZIP, artifact `14063457563`, with SHA-256
`6a15a6a432e99b2213ff706898f2acb4630fedfe9e49e493fbe0ea6e72508dfe`.
It does not checkout product source, rerun the original workflow or tests,
change a budget, or change the original failure classification.

The original `github_download_workflow_artifact` response reported
`InvalidInputException` because this ZIP exceeds its 536,870,912-byte transport
limit. `original-download-refusal.json` preserves that exact original request
and response; its bytes are pinned in `target.json`. That tool is not retried.
The new workflow changes only how the existing original bytes are transferred.

## Publish the minimal tree

Publish exactly five files as a new Git tree without a product base tree:

- `.github/workflows/custody.yml`
- `custody.py`
- `target.json`
- `original-download-refusal.json`
- `README.md`

A new `audit/hia-artifact-custody-<unique-suffix>` branch push starts this
workflow. The checkout explicitly uses `github.sha`; no product workflow is
present. The job uses only `contents: read` and `actions: read`. The 30-minute
job ceiling is a transport bound and does not alter the original product's
60-second, cold or full-suite gates. Keep the original custody attempt and any
failure instead of relabelling or overwriting them.

## Transfer and identity checks

The script fetches the original artifact and run metadata from the fixed
repository's GitHub API. It checks the artifact ID/name, exact size and digest,
run ID, source SHA, original run attempt and completed failure classification.
The raw API response bodies are retained without JSON normalization.

The first archive request carries the step-scoped read token to
`api.github.com` and **does not follow redirects**. It requires the documented
HTTP 302. The returned signed storage URL is used only in memory for a second
GET made with a new opener and no Authorization, proxy-authorization or Cookie
header. Redirect following and inherited proxy credentials are disabled for
both openers. No signed URL or token is written to a log, manifest or artifact;
network exceptions are recorded by fixed phase/type/status without printing
URL-bearing exception text.

The original ZIP is streamed once, with an exact size bound, and its entire
SHA-256 must match GitHub's original digest. It is then read again and split
into three contiguous byte ranges:

| Part | Offset | Bytes | End offset, exclusive |
| --- | ---: | ---: | ---: |
| 1 | 0 | 239,000,000 | 239,000,000 |
| 2 | 239,000,000 | 239,000,000 | 478,000,000 |
| 3 | 478,000,000 | 91,518,893 | 569,518,893 |

The 239 MB part size leaves room below 240 MB for the small metadata and the
outer artifact ZIP. Every part is independently read back and hashed. Reading
all parts in order must reproduce the original whole-ZIP byte count and SHA.
The original ZIP is neither unpacked, rewritten nor recompressed.

Each part is independently uploaded by `actions/upload-artifact@v4` with
`compression-level: 0`, alongside its original metadata, exact offsets, length,
SHA-256, pinned target and original oversized-download refusal. Three separate
artifacts keep each connector transfer below its size limit. Part uploads
require successful complete identity/readback verification; the later uploads
still run if an earlier part-upload action fails. The always-run metadata
upload preserves the executed five-file harness, raw API metadata, split
manifest, transfer logs and any controlled custody failure. It does not upload
the whole large ZIP, caches, source trees, tokens or signed URLs.

A successful custody result means only that the original bytes were retained
and split correctly. It grants no product qualification and changes no test
result. The original d994 Native failure remains a failure.

## Download and restore the exact original ZIP

Download each part artifact separately. Extract them to distinct directories
such as `part-1`, `part-2` and `part-3`, so their identically named metadata files
cannot overwrite one another. Keep the metadata artifact and original refusal.
Then use the same script locally, without a token or network request:

```bash
python3 -B custody.py --target target.json \
  --parts part-1 part-2 part-3 --output HIA_d994_push_native_original.zip
```

The script checks the common original target, distinct ordered indexes,
contiguous offsets, individual part bytes/digests, then the entire reassembled
ZIP size/digest. It publishes the final output pathname only after that match.
No archive member is executed or changed. The resulting ZIP must again be
569,518,893 bytes with the exact original SHA-256 printed above; its member
contents and any inner tar permissions are original bytes.

A later oversized artifact requires its own explicitly frozen target metadata,
original transport refusal, updated workflow artifact labels and independent
custody run. The current target and original attempt are never moved to another
product source or artifact.
