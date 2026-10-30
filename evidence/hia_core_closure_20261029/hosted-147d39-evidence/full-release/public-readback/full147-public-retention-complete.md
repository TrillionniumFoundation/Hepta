# Official 147 release: content audit and public retention complete

This addendum records the completed public-byte readback on 2026-10-30. It supplements the earlier frozen audit and publication map; their observations at the time of freezing remain unchanged.

## Exact source and original execution

- Source: `147d39c4a9d3ded00fb5d22439493bc006a8b76d`.
- Source tree: `2050ec5e447ae5191ac2e685ba463292b2d2d3fe`.
- Official run: [40989068148](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40989068148), job `123846823216`, artifact `12952846418`.
- Original ZIP: **370,966,739 bytes**, SHA-256 `515b2166e3b47c0b51b46421f67531eb053ac21266a8202cba8ba0ba8dc95c6c`, Git blob `06b6f777afa7fca5f5eb9faf21c7d6083289ec66`.

The independent original-content audit read all 7,724 ZIP members and checked their CRCs. Its 8,521 read-only conditions passed. The original candidate, standalone, NDU and integrated producers respectively reported 50/50, 37/37, 9/9 and 8/8 completed gates. The full Python population was 3,659; the NDU population of 201 was a subset. Each of the three full Rust producers reported 96 tests in 19 harnesses with no nonordinary outcome. The audited safety subset contained 126 selectors across 17 capabilities. These overlapping populations must not be added together as independent tests.

## Actual remote-byte verification

The immutable [published directory at `156dbba842999b1165e0964146decf58b3fc64a7`](https://github.com/TrillionniumFoundation/Hepta/tree/156dbba842999b1165e0964146decf58b3fc64a7/evidence/hia_core_closure_20261029/hosted-147d39-evidence/full-release) contains all **89 raw ZIP parts and 21 metadata files** from the frozen publication map.

`full147-final-tree-readback.json` verifies the exact 110-file set, path, Git mode, Git blob and byte size. `full147-actual-remote-stream-readback.json` records an additional real HTTPS download of all 89 parts from that immutable commit, every part's SHA-256 and Git blob verification, and the ordered whole-stream reconstruction. The reconstructed 370,966,739-byte stream matched both original whole-archive identities above. All 89 download attempts succeeded. The verifier streamed the parts without writing another whole ZIP, and ran no native executable or test.

The unchanged original `publication-metadata.json` has SHA-256 `00d7be16715a62d81895a590ac94420601b316041f1c2f66a54582a55492a85e`. Its earlier pending-publication statements describe that earlier snapshot. This dated addendum and its two actual readback receipts establish completion afterward. The original `restore_official_zip.py` and `raw-parts.json` remain alongside the parts for restoration. The exact coordinator verifier used for this readback is retained as `verify-remote-full147.py`; its local manifest path is an execution input, not an assertion about another machine's filesystem.

## Scope retained

This establishes source-bound official execution, an independent audit of its original contents, and durable restoration of the exact original artifact. The audit distinguished 5,241 current selected members from 2,483 historical or other members. Of 440 external identities, eight had retained bytes and one had a public Git verification; the remaining 431 were original reported identities. These scopes are preserved in the original audit.

This release belongs only to source `147d39c4`. It does not qualify later `e0b9012a`, `b121c9b4` or subsequent Core changes. Production authority remains Python and optimization policy remains `no_change`. All 27 original strict P0–P7 obligations remain open. Seven-host ABI and C++ results are separate finite reports; the ABI path is frontend to Rust object.
