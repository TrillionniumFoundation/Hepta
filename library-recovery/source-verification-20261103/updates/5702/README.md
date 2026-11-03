# Source verification update: 5,702 of 6,116

This update adds 118 exact frozen candidates to the previous 3,567-entry increment. The disjoint baseline contains 2,017 entries, yielding 5,702 verified candidates and 414 still unverified. The original 5,456 / 34 / 626 candidate sets remain unchanged.

The new records consist of 66 existing RustSec upstream paths (eight source/configuration files and 58 advisory documents), seven inactive embedded/generated source objects, and 45 R70 projections (37 fenced fragments, seven reference strings, and one required parent document). Original types remain explicit; metadata strings and advisory documents are not presented as code fixes.

The upstream RustSec source commit is an independently proven ancestor of current main, not its current tip. The other 52 candidate objects were published to independent archival branches. All 118 candidates were read from exact commit/path/blob identities; 16 accompanying metadata or license paths are excluded from the counts. The 44 R70 fragments were additionally reconstructed from 43 exact immutable parent inputs before independent publication and readback. Parent containment alone never counts as a verified child Git blob.

The previous ledger SHA-256 is `b3f7fae6369fc8cdb6bf39b43c6895c5aba8a148444afeae3de2b50b8485b4c7`. This header and delta, together with the previous updates and original reconstructed checkpoint, reproduce exact cumulative SHA-256 `9b9099ad1c7a9bb5ee29dfed0200f7d06d8ea84baae10b6e56556f31de79a1c7`. Earlier environment-reset reconstruction provenance is unchanged; the lost pre-reset serialization is not claimed recovered.

Run `python3 verify_ledger.py` to verify these saved records. It does not perform fresh network reads, execute preserved code, or evaluate mathematical claims. It rejects optimization modes that disable checks. R70 expected-member completeness, full synchronization, production/scientific acceptance and original deletion remain unproven or false. Two generated R70 paper text outputs remain among the unverified candidate set.
