# Independent readback of the original 970 CI evidence

This checkpoint preserves an independent read of existing evidence. It does not execute Hepta code, rerun CI, or run the retained 5,400-second qualification suite.

## Verified physical bytes

The existing artifact 13913382201 was read at its externally bound 22,390,611-byte size and SHA-256. All 17 members, all 15 original captured-file bindings, and the original FINAL were checked. Its selected-originals.zip was checked against the external 8,316,154-byte / d72ca1e53539f1cab6ab836c20a02c39b6700025e62890f0e5a1cfeaea700a5e seal. All 356 inner members were fully inflated and independently checked for length, CRC-32 and SHA-256: 354 selected originals totaling 112,639,137 bytes, plus the original DIRECTORY and SELECTED inventories, totaling 126,634,528 bytes. This includes all 53,341,583 bytes of the nested qualification JSON. Local headers, ZIP64 sizes, unique fixed members and contiguous local layout were checked. A second full CRC read also completed.

The independent 19-partition decoder separately recovered 114 raw files / 440 frames / 9,252,841 raw bytes and the same complete 8,316,154-byte ZIP. The resulting ZIP was byte-equal to the artifact member. This aggregate has a narrower scope than the subsequent container audit and correctly retains its own `inner_members_decompressed: false` field.

## Verified report and receipt relationships

The successful semantic audit performed 2,799 explicit checks. It joined the 787-entry source-map identity, the 11-check cold report, the complete 5,051-check nested report, all 38 original phase reports and their worker/request/owner records, the six B/M generation receipts, the original B0 record, and 17 reference-worker records. It checked the five compiler gates, exact original ordered IDs (12+51, 12+51, 12+51+50, 20, and 51), all five anomaly categories, native-return matrices and preserved attempt ledgers. Cold and the five compiler command owners retain their original 180-second qualification / 3-second cleanup settings and natural completed cleanup. The recorded cold result is COLD_SELFHOST_REPLAY_PASS at 137,407,936,075 ns; this is an observation of the original run.

## Physical evidence not independently read by this audit

The 1,025 entries below are the complete set of unselected `{path, bytes, sha256}`-shaped file records discovered recursively in the selected five gate/qualifier reports. They are not a complete inventory of every physical dependency of cold qualification. The exact per-file map is retained in SEMANTIC-READBACK.json; PHYSICAL-GAP-GROUPS.json provides the subdivision.

| Group | File records | Recorded bytes |
| --- | ---: | ---: |
| Core | 406 | 34648902 |
| ELF-callers | 3 | 363991 |
| ELF-component | 213 | 8721698 |
| canonical-process-owner-source | 1 | 17601 |
| cold-B3-image | 1 | 668608 |
| instructions | 204 | 8031571 |
| state | 197 | 7138335 |

The recorded hashes, identities and relationships of these files were checked inside authenticated original reports. Their physical bytes were not independently opened by this audit. Most belong to subsequent compiler-gate build manifests, native images, wheel files, installed trees and component/boundary evidence. These files are necessary to independently repeat the corresponding strict physical acceptance predicates; the observed original gate PASS does not replace that work. Twelve ELF boundary gzip files, for example, remain hash references here and were not decompressed by this audit.

For the cold qualification itself, the B3 image is one of these entries: its 668,608-byte / 0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8 identity is joined through original receipts, but this audit did not read the image. Other B/M generation images and inputs, and all 38 archived phase ZIPs, are represented in the original reports with other field shapes such as `archive` or stage-specific input/output paths. They are therefore outside the count of 1,025 and also have not been independently read or expanded here. The original reports record the producer's checks before archival; those statements remain original reported observations, not new physical readback. The original large-artifact DIRECTORY is a checked inventory, not a substitute for opening its unselected members.

The audit fetched and read the exact canonical producer/test source subset listed in SOURCE-INPUTS.json. It did not independently fetch or hash all 787 source files. The entire 787-entry map is bound to the external canonical map digest and joined across original reports, which is a different claim from reading all source bytes.

## Preserved failures and limits

The original custody result remains CUSTODY_HOLD, its framing result remains FRAMING_HOLD, and cancelled/unknown historical operations are not reclassified. The first original observation over the 4 MiB reader limit was the 53,341,583-byte nested qualification.json after the 93,953-byte hia-cold.json; it was not DIRECTORY.json, which used a separate inventory admission. The later natural-guardian acceptance error is retained as a derivative failure. OBSERVATIONS.json was not originally produced.

The first independent semantic-audit script failed on a mistaken support-contract filename. Its unchanged source is preserved alongside the corrected r2 source and successful r2 report. This audit error is not a product failure. COMMANDS-AND-OUTCOMES.json records exact commands and observed terminal results and explicitly distinguishes those notes from raw tool SDK transcripts.

No new product test, native compilation, full 5,400-second retained suite, or 10,800-second formal controller was executed by these scripts. This checkpoint establishes full readback of the selected evidence and explicit report/receipt joins, with the physical gaps above still open.
