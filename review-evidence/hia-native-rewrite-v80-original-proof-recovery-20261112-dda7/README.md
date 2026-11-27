# Original Proof bytes recovered after environment restoration

This evidence-only revision preserves the original files that were inaccessible during the environment interruption. It does not rerun the old tests, transfer qualification to a successor source, activate a native default, or change product commit `4b19af89a766593f7d5f1cc2db256e81aba7afcb`.

## Independently observed recovery

The complete original 3,202-file source was read again and matched its pre-interruption checkpoint in bytes, SHA-256, Git blob identities, and Git executable modes. Its independently reconstructed Git tree is `7a9bfd37447827801a1493fc922a8e373673882c`. All 62 cumulative source deltas match the actual recovered files. The original compressed cumulative packet has Git blob `97c1542bd4d8a35a389168dc6e76273dbd575de7`; this revision obtained its first actual Git create acknowledgement and full byte-for-byte readback after that identity had previously only been computed locally.

The original 64-test report is a CPython 3.12.14 local result, with zero recorded failures, errors, skips, expected failures, or unexpected successes. Its original before/after snapshots equal the reappeared source. The separate original 40-caller attempt stopped at the missing-Z3 import preflight and executed no business tests. Both original outcomes are retained unchanged. Neither result qualifies the later independently rebuilt Proof R2 or the current joint source.

## Complete original records

`INDEX.json` describes 70 independently created and fully reread Git chunks (`part-000.json` through `part-069.json`). Together they preserve 1,006 complete files from the original checkpoint, original component records, original caller-preflight records, and the new read-only recovery scripts/report. Both text and all six binary files are included. Each member has its complete bytes, SHA-256, Git blob identity, and an explicitly labelled newly observed recovery permission mode. Historical complete POSIX permission equality is not inferred from snapshots that originally bound only Git executable modes.

Concatenate the chunks' `payload` fields in `part` order, base64-decode, then zlib-decompress. Verify all compressed/raw identities in `INDEX.json`, then each member before use. The complete decoded JSON is 72,475,496 bytes and the compressed stream is 18,189,346 bytes. This is preservation of the original evidence, including repeated installed-source and wheel bytes, not an abbreviated summary.

The directly readable original 64-test report/process/stdout/stderr and original 40-caller preflight summary/stderr are also included beside the complete packet. `CUMULATIVE-OVERLAY.zlib.json` is the unchanged original complete 62-path source packet.

## Transport history and limits

One create request for `part-007.json` returned a server disconnect. The subsequent read observed 404. Those exact responses are retained in `GIT-CUSTODY-RECEIPT.json`; only then was the same idempotent blob creation repeated, acknowledged, and fully reread. All 70 final chunk identities were verified. No unknown request outcome was silently counted as success.

Earlier audit statements that the old originals could not be read or uploaded were true when recorded and remain in the previous commit. Recovery is a new observation appended here. Whole-stack HIA closure, current-source cold qualification, default activation, and readiness to remove the old production implementation remain false.
