# Final 953 scoped logical cleanup evidence

Read `DELIVERY.md` and `SUMMARY.json` for the result, finite scope and unknown costs. The final implementation is `953fa62dee5aa563551d57b1374ab95b6d548b45`; 3533 is historical only.

This directory contains the exact final archive, external manifest and bounded stdlib verifier, original post-model launch/capture records, independent peer review, prepared revisions and the completed delivery summary. Preserve the entire directory as `final-953/` together with the complete `p1-p2-scoped-cleanup-3533-evidence-20261030` directory as sibling `history-3533/`. The historical archive already contains the full scoped-cleanup development records and exact old/new Rust executable bytes; no original workspace is required to verify either archive.

Final archive: 2,095,396 bytes; SHA256 `c1a84262caf2babcf7625982e59cb2e3fda46f37a820123048cbe164a351a949`.
Final external manifest SHA256: `85c3d67347f3b4f755f73798e5fd5b244bca2af546dd1d3194af5af6a84a51e1`.

```sh
python -B verify_archive.py evidence.tar.xz MANIFEST.json 85c3d67347f3b4f755f73798e5fd5b244bca2af546dd1d3194af5af6a84a51e1
```

The command verifies 43 regular members / 17,526,658 payload bytes without extraction, archived code, native execution or inference. Exact recorded counts are 20 focused Python tests, 121 Rust tests, 260 observations, 314 direct processes, 37 refusals, 58 stops with payload and 18 stops with call-formal witnesses. These sets overlap. Cache reuse is not a clean rebuild. Correctness observations are not a performance qualification or language-wide/native safety proof. Source, journal and before/after evidence are bound; past execution is not cryptographically authenticated.

The copied peer review is outside the frozen archive, so its publication does not silently change archive identity. `DELIVERY_FILES.json` inventories all delivered files other than itself. Archived absolute paths are original provenance, not a runtime dependency of the verifier. Full human/agent development and review cost remains unknown.
