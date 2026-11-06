# Source verification update: 5,232 of 6,116

This update adds 263 freshly read-back original source objects to the 2,952-entry reconstructed increment in the parent checkpoint. The disjoint 2,017-entry baseline yields 5,232 verified unique candidates; 884 remain unverified. The frozen candidate union is unchanged.

The prior reconstructed ledger SHA-256 is `49f2ad294a7edfb9741d1b5354057437464982cad7047960cd9c62689ac67770`. `LEDGER_HEADER.json` and `source-delta263.json`, together with the parent checkpoint, reconstruct the exact cumulative JSON SHA-256 `04f32b2678ac20937821d2e21dc243eda95ff3b7c06e2c125427486f7ff103e5`.

The new sources were retrieved by immutable commit/path and compared against original Git blob, SHA-256, and byte-length fingerprints. Sixteen accompanying notice/metadata paths were also read back but do not enter the source count. Current retained refs at verification are recorded separately.

Run `python3 verify_ledger.py` here to validate checkpoint consistency and reconstruct the ledger hash. The verifier does not repeat network reads, execute preserved source, establish research/production acceptance, prove full synchronization, or authorize clearing originals.
