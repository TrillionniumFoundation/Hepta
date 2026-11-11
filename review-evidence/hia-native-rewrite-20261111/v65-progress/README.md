# HIA recovery checkpoint: v64 failed CI and v65 development

This checkpoint preserves evidence and frozen development source. It does not
activate new production defaults or retire production/reference owners.

## Published main remains v64

Main is `5831f52fada45e076f8f68f198a15c0585e6104f`, tree
`72084752441a61f879dbbcf363a8cade3ef2d6b1`. GitHub HIA run `42986320732`
failed its unchanged 180 second cold gate. Source tests passed (307 tests),
and the separate four-language CodeQL run `42986321133` passed.

The actual cold wall time was 180.141377508 seconds. All 34 completed phase
reports contain passing checks (3,758 checks). Both names phases were
unfinished and neither exports phase began. The final qualification report
does not exist. All later native workflow groups were skipped. These facts
remain FAIL/HOLD, not a partial qualification pass.

The independent byte audit replayed all 4,394 outer ZIP members, all 614 source
files against the published commit, and 36,669 sealed raw members (2,120,559,025
bytes) from the 34 current phase archives. It confirmed process-tree cleanup.
The historical ZIP carried as source is not counted as a current phase.
The full original GitHub artifact is retained separately; its exact SHA256,
artifact metadata, and persistent file receipt are inside the CI capsule.

The separate timing diagnosis matches 5,154 original v63/v64 receipts, including
4,536 native clocks, without changing cases, images, inputs, limits or results.
Much of the increase is inside native wall clocks. Hardware/scheduling cause
is unestablished. Proposed observer copy/hash reductions are not in this
checkpoint's main or frozen state source and are not measured savings here.

## Frozen v65 state-owner integration, stage 3

The state draft is based on v64 main and preserves all v64 generators,
ownership gates and native tests. Its frozen source closure has 635 files.
It adds explicit HIA request admission, release installation, and Agent journal
selection, including exact preflight diagnostics and 14 regenerated consumers.
Original three-way merge inputs and conflict resolutions are retained.

Source generation completed for all 46 generators. After correcting the local
order of coverage-inventory generation and support-contract generation, all
43 focused source/independent-VM checks passed. The initial stale-contract
failure and its logs remain in the checkpoint; no assertion was weakened.

The first retained local cold replay of this frozen source also FAILED at
180.170136349 seconds, after 34 phases and zero phase exceptions. Source hashes
were preserved and owned-process cleanup completed. Its full original raw
archive has 3,216 files, 290,338,784 raw bytes, and SHA256
`99b78b0edd96c0d155d748f83d02dbd6f4c70bfb6382a7cb0261bc85396a2027`.
The archive was read back byte-for-byte, including modes, and saved separately;
the receipt and failed report are included here. It is never admitted as a
passing cold report. The new native suite controllers are retained source for
future execution, not test evidence. A separately named development controller
does not run or claim the cold-required composition module.

Release root documentation now matches the implemented policy: an owned
directory without group/other write is admitted; actual kernel write/search
authority is required for installation. Read-only verification may use 0500.
Development bootstrap fixtures freeze and recheck the exact source bytes used
by compilation. These corrections do not alter the HIA request/journal/release
production images from the imported source.

## Standalone composite-driver development

Stage 4 binds integer JSON decoding and typed-packet conversion in one native
process using private read-only input and arena mappings. Six tests cover 76
actual processes, including write faults and refusal boundaries. Stage 5 adds
typed-packet to ordered integer JSON and offset-index conversion: seven tests,
229 actual entries, exact 64 MiB source/service boundary, +1 refusal, deep
structures, Unicode, malformed packets and output-capacity ordering.

This remains a prefix and service codec. The whole 11-image composite driver,
complete Core streaming, canonical snapshot ownership and native authoring
remain open. The 64 MiB service-packet ABI is not imposed on expanded Core.
The decoder/arena pair is private issued state; the codec is not an authenticator
for arbitrary external pairs. Original failures and fixture revisions are kept.

An independent codec review found and corrected two development binding holes
(wrong component and reread image mismatch). The review archives distinguish
author results from independent executions. Root independently replayed every
archived member's bytes, size and mode before publishing this checkpoint.

## Retirement scope

Only four completed local development copies were removed after their unique
bytes, modes, inventories and Git identities were archived and verified in
the prior recovery commit `7a581ca47f102db6dda1b6ddcc1b594edb4e193f`.
This checkpoint adds the actual removal receipt. No production/reference
implementation was removed. Whole-stack native closure remains OPEN.
