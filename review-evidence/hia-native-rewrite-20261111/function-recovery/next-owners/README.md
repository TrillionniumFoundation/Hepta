# Next-owner checkpoint before constructor/outer integration

This extends recovery commit `4259f427de29ebc940ed5bb5d4049ae9cc7cf98e`
with the exact separate constructor replay, the initial outer implementation,
and the public lifetime witness/fix review. It does not move `main`, replace a
qualification gate, or declare the whole stack native.

The constructor's independent 134-case replay passes with 82 accepted and 52
refused. Every public decode gate admits its input. Full constructor state,
source aliases, first error class/code/text and type-command sequences agree
with the same real native type dependency. The original 1,721,352-byte archive
has SHA-256 `d04cdfeb0e28046d0230a344fa40f375c508991b7f9d0ed64ca9a9bcf8e840b5`;
all 53 members were replayed. It records 3,535 real native entries and unchanged
source/image pins. This separate constructor source predates the subsequent
public lifetime follow-up; the audit explicitly closes its own sessions.

The outer stage2 archive preserves all six original production source files,
two actual B3-compiled images and their compiler inputs/receipts/logs, and the
two scalar/task smoke cases. It is 76,612 bytes, SHA-256
`d3b72944a16ceb391e876a0bfce6d698dd45be66ecc8e1c64a67bdcf7ce9711f`;
all 36 members / 630,471 raw bytes were read back. It is initial development,
not full outer acceptance.

Independent stage2 review runs 21 frame and nine opaque-reference controls
without loading any native image. Its semantic ownership review finds the HIA
owner performs source-function order, helper aggregation, late inventory gates,
export eligibility/sorting and schema choice. A specific protocol discrepancy
remains: a helper's output header and workspace final serial are not required
to agree exactly. Actual native fault injection reproduces acceptance after
changing the first header from 44 to 45, with subsequent helper names and Core
bytes affected. The original source inputs and six stage2 source pins remain
unchanged. The witness records only its stated workspace prefix; it is not
described as a full raw arena snapshot or a public-source semantic counterexample.
The author is implementing exact HIA-owned header/workspace correlation in r2.

A separate private frame control finds that r1's `_frame` can accept a valid
frame after an earlier bad frame has set the session's broken flag. That is a
synthetic, zero-image/zero-native-entry observation; it is not represented as
an ordinary public lower reuse failure. Its original control and the real
helper fault readback are retained without rewriting the initial review.

The public-lifetime archive preserves three exact production changes, their
original sources, the original approximately 384 MiB held-exception allocation
witness and the independent replay of that same public input after the fix.
The replay performs six actual native entries, preserves exact error text and
code, and observes all four buffer weak references collected while the exception
remains held. Its first entry observer targeted separately loaded images and
failed its counter assertion; that observer failure and original script remain.
The corrected observer targets the actual session image objects. No production
source changed between those two observer runs. This archive predates the later
complete lifecycle/retained test packaging and does not relabel it as complete.

All failures, development-only scope and remaining acceptance gates stay visible.
No remaining hosted production owner has been removed by this checkpoint.
