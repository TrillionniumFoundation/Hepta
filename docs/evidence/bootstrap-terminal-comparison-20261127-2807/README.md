# Candidate: compare complete raw business output after natural exit

This is a development checkpoint, not a passing Source or whole-stack
qualification. It follows the preserved late-lifetime counterexamples under
`docs/evidence/bootstrap-late-lifetime-20261127-2807/`.

The original observer produced raw business output without consuming expected
JSON rows; the candidate consumed expected JSON inside that same lifetime.
Actual C post-write stack observation reproduced all old bytes and located the
eight finalizer differences inside the candidate's expected-row JSON parser.
This patch removes that extra live parser/comparer from the candidate process.

## Kept gates

The original case and test bodies, ordered 15,830 business calls, complete raw
observations, exception fields, raw traceback channel, late channel, fault
injection, original 232-case base, original helper images and original negative
controls are unchanged. No garbage collection operation or normalization is
added. All three original Source/fixed-word test files remain whole-byte pinned.

The parent fully admits authority before starting candidate effects. The
original v2 child checkpoint remains a completed original observation. The
candidate v3 checkpoint explicitly records `PENDING_PARENT_PROCESS_TERMINAL`
and has no successful difference count. Both the producer and independent
reader reject treating that checkpoint as PASS.

After natural process exit, the parent compares every full business row and
every full late row, retaining all differences. PASS requires complete-byte
equality, zero differences on both channels, current-public dispatch admission,
source custody and the final unchanged readbacks. The independent reader repeats
these checks and verifies that comparison happened after the sealed child exit
in the terminal-sealing parent process.

The original 600 + 3 seconds for each original and 1800 + 3 seconds for a
candidate remain unchanged. The preliminary outer owned process has an
additional unchanged **1800 + 3 second overall bound covering original authority
creation, full admission, candidate business, terminal business/late comparison,
current-public checks and independent reader**. No comparison or admission work
is excluded from this outer bound.

## Actual checks so far

The exact new source passed 22 tests, zero skipped: nine new terminal-comparison
controls, the original five static Source controls, the original three
fixed-word Source controls, and five supplemental word Source controls.
Complete command, stdout and stderr are preserved alongside this file.
The nine new controls include same-length AttributeError field changes,
late active-exception changes, missing/extra/reordered rows, equal parsed JSON
with different bytes, wrong pins, duplicate/incomplete rows, pending-as-PASS
refusal, and full original test-source pins.

Job `1a21ecb8bfb-ffbe-5677` is running the complete fresh original and unselected
preliminary observation on this source. Its result is **pending** at this
checkpoint. It has not passed the original Source runtime class. The separate
old-source VM job is also a distinct observation; no authority or result is
borrowed across these source tuples.
