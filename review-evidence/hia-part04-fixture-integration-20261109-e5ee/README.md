# Part04 fixture integration evidence

The complete source parents are PR817 `164e462e6098f3a31790b8987705e7fe6592b230`
and PR816 `39ae467a5806a9c969133e6e8801f83c96f246aa`, on baseline
`ffa64c93dd4c51190fda8c0f647481a31ffbcf07`.

The mechanical-union preoutput red is retained (`11 != 0`, 30.114 seconds).
The first full local attempt remains **107/108, FAIL**, 260.525956 seconds.
The original descendant assertion observed `R`, expected `Z`; its original
PID/terminal were not retained, and the unique sample cause remains unresolved.
Only the corrected method was checked afterwards: two positive scenarios and
two expected deadline rejections. Injected reads are labelled. This is not a
second full green run. All 709 old IDs remain; 712 existing-shard IDs plus 11
independent IDs form 723 unique controls. Inventory collection executes none.

Exact-parent CI is separate: PR817 8/8 workflows, PR816 19/19, attempt 1.
The integration head requires fresh CI. Production v2 collector/readers,
limits and byte budgets are unchanged. Cleanup records the owned leader and
captured streams; it is not a general all-descendant termination proof.

See `docs/HIA_PART04_FIXTURE_INTEGRATION_20261109.md` for complete reasoning,
source provenance, observed outcomes and limits.

## Contents

- `validation.json`: exact sources, separate result classes, scope and parent CI.
- `archive-manifest.json`: every decompressed member's exact bytes and SHA-256.
- `raw-evidence.tar.xz`: all retained local logs, receipts, observation sequences,
  scripts, source maps, reviews, red cases and original PR817 CI readback.

The archive uses `local/` and `github-pr817/` prefixes. Initial observations are
preserved alongside final records. Expected negative cases keep actual failure
tracebacks. Inherited PR816 raw log whitespace remains unchanged.

Archive: **78064 bytes**, SHA-256 `a482f25b8e7beba575a45f2cbdc283f1662cbc2fca77c7c95164a32d7e674dd0`.

All **64 members / 1777819 decompressed bytes** were re-read and rehashed after creation.
