# Single original artifact inspection

This independent harness reads only original run 43367645642, native job
131695719079, artifact 14011985720, at product head
016f00bbbafddec8112ef6762eb799e83c8e5d00. It verifies run/head/attempt and
the recorded 67,917,447-byte ZIP digest, reads every outer member to check
CRC and SHA256, and retains exact caller report/log bytes only if present.
It does not execute, compile, test, or change the product or any ref.

The original job remains failed. An inspection success means custody
inspection completed, not that the 130 original caller tests passed.
Nested ZIPs are identified as ordinary outer bytes and are not recursively
qualified. The original outer ZIP is not redundantly uploaded by this job.
