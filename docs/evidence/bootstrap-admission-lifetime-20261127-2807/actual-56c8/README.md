# Admission metadata lifetime: actual terminal result

Status: **HOLD. The complete original 1800-second gate timed out.**

The original durable job was `1a21efd09b2-ffbe-56c8` on the Mac controller, executing the owned ROG source snapshot. Its request digest was `a683fcf3f4f8b1d92b8e8e14904f39dcab130aeab504d1036c834a4870f33e90`. The source and payload were published in the parent evidence directory before this terminal readback.

The 22 existing component controls passed with zero skips. Four fresh original lanes completed. The unselected candidate naturally exited 0 after 397.692476091 seconds, completed all 15,830 cases in order, and produced no unraisable exceptions. The complete 3,396-byte late stream was independently read from both originals and the candidate; all three byte strings are identical, including the eight active exception-context records. Their SHA256 is `d8c87bd5cd5e6404839baffc22f35c2fe4dd8e8cf6b4514e7d8bdf9ccbdb9b16`. The candidate's terminal business channel was 760,288,413 bytes with the same recorded SHA256 as the original: `83b60bf1953d9b54afb8243b9d3d2df3341ce3b5b131897f13ff58a748fa8e72`.

This is not complete finite qualification: the parent did not finish its full business/late comparison and independent reader. It reached the unchanged 1800-second gate after 1800.283277767 seconds. Its child was in kernel D state before the original SIGKILL cleanup; cleanup reaped it and left no owned members. The parent spent 533.93015153 seconds after the candidate terminal seal before that timeout. No final finite PASS report was produced.

The original physical evidence remains under:
`/run/media/qian-qi/TOSHIBA_DEV_1TB/hia-bootstrap-admission-lifetime-20261127-2807`.

The subsequent read-only IO observation in the sibling Bootstrap source-custody evidence records a bounded 64 MiB external read at 30.227 MiB/s and a 58,037,687-byte home read at 436.679 MiB/s, with physical read counters and no forced cache state. Those samples explain the choice of a new home output directory for the next original Source8 execution; they do not prove historical whole-phase throughput or replace the failed gate. No old evidence was moved, normalized, or replaced.
