# Source verification update: 5,708 of 6,116

This update adds six exact original frozen candidates to the unchanged 3,685-entry increment. With the disjoint 2,017-entry baseline, 5,708 candidate identities have been verified and 408 remain unverified. The original 5,456 / 34 / 626 denominator is unchanged.

Four Chain objects are three generated Rust build inputs and one historical W1 CI collector. Two hepta-private-ci objects are unapplied plain-text patches: five Rust source files and a single Bazel dependency lock. Necessary original license notices and new manifest/verifier metadata are auxiliary and excluded from candidate counts. No mixed binary patch, notebook output or unreviewed material is added as code.

All six are pinned to independent archival commit/path/blob identities and complete remote bytes. The 1,850,327-byte lock patch exceeded the Contents API payload range; its immutable path response identified the exact blob, and a separate Git Blob API read returned all bytes for size, SHA-256 and Git-object hashing. An empty Contents response was never counted as byte verification. The downloaded new byte verifiers passed and rejected optimized Python.

The previous ledger SHA-256 is `9b9099ad1c7a9bb5ee29dfed0200f7d06d8ea84baae10b6e56556f31de79a1c7`. This header and delta reproduce the new cumulative SHA-256 `6aeda243a5ed28f7aa516fc1ad067de386684f8d4ba63ce147e80de3c1bf479e` when combined with the original reconstructed checkpoint and prior updates. Original environment-reset provenance remains unchanged.

Run `python3 verify_ledger.py` to verify these saved records. This command makes no new network reads and never executes preserved source. Full source synchronization, scientific and production acceptance, original R70 expected-member completeness and permission to clear originals remain unproven or false.
