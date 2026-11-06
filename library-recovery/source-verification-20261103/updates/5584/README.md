# Source verification update: 5,584 of 6,116

This update adds 152 freshly read-back frozen candidates to the previous 3,415-entry increment. The disjoint 2,017-entry baseline yields 5,584 verified candidates; 532 remain unverified. The original candidate union and its categories are unchanged.

The new records comprise 108 inactive archived source objects and 44 existing historical paths. The latter include seven R70 GraphViz sources and four original text/JSON containers; their candidate types remain explicit. This is byte-preservation coverage, not a claim that every counted item is executable source. Twelve accompanying manifest/verifier paths were read back and are excluded from the candidate counts.

The previous ledger SHA-256 is `ea42c0440c58c5ae57c843f139735c0db48691bceee54e7ed74168d2cb639830`. This header and delta, together with the previous updates and original reconstructed checkpoint, reproduce cumulative SHA-256 `b3f7fae6369fc8cdb6bf39b43c6895c5aba8a148444afeae3de2b50b8485b4c7`. The earlier reconstruction provenance is retained; the lost pre-reset serialization is not claimed to have been recovered.

Every new record was fetched from an immutable repository commit and path and checked against its original Git blob, SHA-256 and byte length. Retained branch identities are listed in `ARCHIVE_REFS.json`. Current archival placement follows inspected project evidence and authorization; it does not establish an exclusive historical owner.

Run `python3 verify_ledger.py` here to validate the preserved records and exact serialized ledger. It performs no network reads and never executes archived source. Research, runtime, full synchronization and original-file deletion gates remain open.
