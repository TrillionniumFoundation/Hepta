# Source verification update: 5,432 of 6,116

This update adds 200 freshly read-back original source objects to the previous 3,215-entry increment. The disjoint 2,017-entry baseline yields 5,432 verified candidates; 684 remain unverified. The frozen candidate union is unchanged.

The previous ledger SHA-256 is `04f32b2678ac20937821d2e21dc243eda95ff3b7c06e2c125427486f7ff103e5`. This header and delta, together with `../5232` and the original reconstructed checkpoint, reproduce the exact cumulative JSON SHA-256 `ea42c0440c58c5ae57c843f139735c0db48691bceee54e7ed74168d2cb639830`. The earlier reconstruction provenance remains unchanged; the lost pre-reset serialization is not claimed to have been recovered.

Every new source was retrieved at its immutable repository commit and path, then checked against the original Git blob, SHA-256 and byte length. Eighteen accompanying manifest/verifier paths were read back separately and do not count as original source candidates. All six retained branch refs were checked again after readback.

Current archival attribution can be based on inspected project interfaces or an explicitly authorized project destination; it does not prove an exclusive historical owner. Scientific, runtime and full synchronization gates remain open.

Run `python3 verify_ledger.py` here to validate the preserved records. It performs no network reads and never executes preserved source. It does not authorize clearing original files.
