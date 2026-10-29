# Offline artifact auditor input-admission supplement

This supplement fixes an input ambiguity in the offline auditor. It does not
change Hepta production source or any original hosted artifact. The frozen
`ci-current-699de39/` directory remains unchanged.

**The same 18 original artifacts pass the corrected offline audit, and all 18
result files are byte-identical to their previously frozen audit results.**
The current original observations remain valid. The repair strengthens refusal
of malformed auditor inputs that were not present in those originals.

## Concrete defects and repairs

The original Windows C++ source-map reader normalized backslashes to slashes
while inserting records into an intermediate dictionary. Two different raw
keys could therefore collapse to one name before the later duplicate-name
check. The CRLF branch also compared a set, which could hide repeated entries.
The repair rejects normalized collisions before creating either collection,
preserves the original input count, and requires exactly seven declared CRLF
reconstructions for this Windows profile.

The original JSON decoder silently retained the last value of a repeated
decoded object key. The corrected auditor rejects those duplicates at its JSON
read boundaries. An imported legacy ABI validator also parsed two execution
stdout strings as JSON internally. The supplement now strictly parses and
binds those two strings before calling that unchanged validator. No production
validator source is modified.

Artifact and run IDs must also be positive exact integers before they are used
to construct input paths or failed-result output paths. Inputs are read from
the frozen directory; all new output goes to this supplement directory.

## Raw-input controls

The controls preserve complete raw JSON payloads and ZIP fixtures derived from
actual original report members. They invoke the original and corrected
`Audit.read` / `Audit.report` reader stages, followed by their exact C++ source
admission methods or the original ABI validator and corrected strict stdout
guard. They do not start from an already collapsed source dictionary.

| Synthetic malformed input | Original admission stage | Corrected admission stage |
| --- | --- | --- |
| Two spellings of one exact source path, same SHA | Accepted | Rejected before normalization projection |
| Two spellings of one CRLF source path, same SHA | Accepted | Rejected before normalization projection |
| Two spellings of one path, conflicting valid LF/CRLF SHA values | Accepted | Rejected before normalization projection |
| Same JSON key repeated with the same value | Accepted | Rejected during JSON decoding |
| Same JSON key with an earlier conflicting value later overwritten | Accepted | Rejected during JSON decoding |
| ABI stdout `status` repeated with the same value | Accepted | Rejected during embedded JSON decoding |
| ABI stdout `status` with an earlier conflicting value | Accepted | Rejected during embedded JSON decoding |
| ABI stdout `foreign_calls` with an earlier conflicting value | Accepted | Rejected during embedded JSON decoding |

All eight original acceptances and all eight corrected refusals were actually
observed and recorded. Two unmodified real Windows report members and one
unmodified real ABI report pass both versions. These are **eight synthetic
auditor controls plus three original-input controls**, not language or host
tests. No native compiler or artifact was executed; child process creation was
prohibited while the existing ABI frontend validator ran with `native=False`.

The original official ZIP digests remain intact. Synthetic fixture ZIPs are
clearly identified and do not claim to be official hosted artifacts or complete
new host qualifications.

## Current Windows and ABI evidence

Both original Windows C++ reports, artifact IDs `12891623518` and `12891739355`,
were read directly from the original ZIP bytes. Each contains **157 raw source
entries and 157 unique normalized paths**, with zero duplicate decoded JSON
keys. Each still checks as **150 exact Git-blob byte identities plus seven exact
LF-to-CRLF reconstructions**. The old acceptance results for these original
inputs are therefore unaffected by the malformed-input defect.

The seven ABI artifact audits explicitly retain their existing limitation:
temporary matrix object files and executables were not uploaded by that
workflow. This supplement does not claim to recompute their digests from
missing original binaries. Retained `stb_divide` outputs remain separately
byte-audited.

## Native NDU scope review

The recursive, finite, stream and ranking receipts keep four separate source
pins. Neither original NDU artifact relabels those sources as Hepta `699de39`.
External upstream raw source blobs were not independently reacquired here.

The adaptive negative control is narrowly bound: the one declared candidate
publication path contains the exact 23 bytes `not the loaded artifact`; the
original candidate's digest, size, image token and admitted loaded mapping
agree with the retained sealed-descriptor snapshot. The before-load tamper
file is exactly that snapshot plus `changed`. Both the final path bytes and the
original sealed bytes were independently rechecked in both original NDU ZIPs.
The reference remap applies only to that exact path and original digest. It is
not a general exemption from artifact hash checks.

## Retained records and scope

- `audit_artifact_contents.original.py`: unchanged original implementation.
- `audit_artifact_contents.py` and `auditor-fix.diff`: corrected implementation
  and complete delta, including read/output-root separation.
- `raw-json-controls/`: original raw report members, synthetic JSON and ZIP
  payloads, original/corrected observations and exact Git-blob identities.
- `offline-reaudit-execution.json`, `content-audits/`, and original process
  logs: corrected offline verification of the same 18 original artifacts.
- `frozen-inputs-before.json` and `frozen-inputs-after.json`: 47 selected frozen
  inputs are identical before and after the work.
- `scope-peer-review.json`: focused ABI and NDU scope checks.
- `independent-peer-review/`: a second agent's read-only review of the repair,
  raw Windows maps and resulting records; it did not rerun the controls.

The corrected implementation SHA-256 is
`ed41e04e590bb81d6e7f3c9832b439678736d83ae4e0a24eeef8a3815fff9c76`.
The controls report SHA-256 is
`2e89d2d76fa892fb5be4afbd16486ffb42a09fdcaa114deef7d407dc3e888c7b`.

The preliminary source-reference discovery pass may skip malformed JSON that
is not a selected report. This supplement does not claim universal validity of
every JSON fixture in every ZIP. It validates the selected reports and explicit
observation parsing boundaries.

No package was downloaded, no host test was rerun, and no source or original
ZIP was changed. This supplement does not evaluate the separate second local
full-eight-gate attempt, establish a production-authority switch, or close all
P0–P7 obligations.
