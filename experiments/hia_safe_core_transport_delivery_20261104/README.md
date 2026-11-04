# Independent Safe Core evidence delivery

Source draft PR: https://github.com/TrillionniumFoundation/Hepta/pull/648
Measured source: ce1dd749ffaf7b0905e55473164f79741facb08c.
App projection: cbc3925ecfae120b1dd471a60499416e139db2e6 (same source tree).
Latest full fresh acceptance r5 FAILED at CertPart03 after 60.000790060 seconds.
Full wall time: 339.817342764 seconds, including preparation.
Four stages passed; later six stages and final independent replay were not reached.
All twelve wider obligations remain unproved; all production/native/performance
and initialization-elision authority remains DENY_ALL.

The review archive contains all actual receipts and raw diagnostics from 23
preserved roots (409 evidence files), 77 deduplicated actual generated Lean
source objects and 7 durable source-test jobs. It includes the original
55,776-byte source-history git bundle. Thirty-seven .olean payload copies are
omitted from this small package; their original paths, sizes and SHA256 are
in the complete review inventory and the full evidence roots are preserved.
This package is review material, not a standalone successful binary replay.

The combined bbd+ce1 and adf+ce1 source compositions have not been qualified.
The original measurement base remains 958d475. See the upstream-boundary sidecar.

Download every file in this directory together. Reconstruct and verify with:

    python restore_review.py --output /absolute/path/to/a/new-directory

The restore script verifies all six parts, the exact archive, all included
evidence/source/job payload hashes, all supporting inventories and the exact
original git bundle before writing to the fresh output directory. It does not
compile Lean or promote any failed/nonaccepting run to proof acceptance.
