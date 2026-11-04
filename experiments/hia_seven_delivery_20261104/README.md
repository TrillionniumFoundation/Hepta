# Hepta seven-track delivery — 2026-11-04

This directory records completed execution and measured acceptance boundaries for the frozen implementation. It does not declare that all seven research goals are solved.

- [Chinese delivery report](DELIVERY_REPORT_ZH.md)
- [Machine-readable results](RESULTS.json)
- [Evidence and restoration index](EVIDENCE_INDEX.md)
- [Original-source and publication provenance](PROVENANCE.json)

## Final acceptance

| Track | Actual outcome |
|---|---|
| P0 fixed implementation composition | Pass for the declared combination: 31 commands, 29 flags, 462 core tests, no failures, errors or skips |
| Exact-tree CI | All 8 workflows succeed; full regression 1781/1781, six-outcome qualification 562/562 |
| P0 sequential Safe Core proof chain | Open: abstract-model results and selected scalar translation checks remain scoped; independent transport acceptance times out at Part03 |
| P0 AOT performance | Final r3 passes 293/372 frozen Rust comparison gates; 79 remain unmet |
| P0 NDU net benefit | 0/3 application scenarios win; modeled plan gaps are zero for the 9 registered finite-model requests, while measured cost does not improve |
| P1 C/C++ migration | Declared owner profile and GSL upgrade expanded; SQLite codec coverage rechecked; arbitrary translation and complete human cost unestablished |
| P1 Agent factorial | Completed 32/32 cells and 63 attempts; HIA-full0/8, Rust-full0/8, HIA-patch0/8, Rust-patch1/8; no HIA productivity benefit established |
| P2 hardware and concurrency | Actual declared host/ABI/bridge execution retained; DMA/MMIO/general async and full concurrent memory-model guarantees remain open |

## Source identity

The original measured implementation is `3707b871ecbe563233ee9a3b69299fc627408936`. GitHub App publication `e3b380bdb4d52e3d65c77356a3c09a4c6e3cfbf4` has the identical tree `9530e9feccf0077696d2e94746fda6bfb6854417`, but a different commit identity. Original Git history is retained in a verified bundle with explicit prerequisites.

Implementation: [draft PR #644](https://github.com/TrillionniumFoundation/Hepta/pull/644).

Independent proof research: [draft PR #648](https://github.com/TrillionniumFoundation/Hepta/pull/648), original source `ce1dd749ffaf7b0905e55473164f79741facb08c`, publication `cbc3925ecfae120b1dd471a60499416e139db2e6`, tree `92fe27daac9d2b2e2c76d0fa7a79362445b7fc4b`. It is not silently included in the qualified implementation.

All evidence additions are confined to `experiments/`. Source, tools, tests, workflows and the root README remain identical to the measured publication tree. No main merge is proposed.

## Reading boundaries

The evidence keeps earlier failures and all r1/r2/r3 measurements. The final result is not selected from whichever earlier run looked best. Every capsule specifies included bytes versus hash-only inventory items; the proof archive is review material rather than a complete successful replay environment.

Timing units, sample denominators, original versus canonical protocol hashes and alternative per-arm cost allocations are explicit. Unknown human work, historical acquisition, energy and long-term lifecycle cost remain unknown. Registered finite-model optimality, finite native execution and general safety proofs are distinct claims.
