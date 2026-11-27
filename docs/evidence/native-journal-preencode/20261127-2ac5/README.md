# Native journal pre-encode candidate

This is a qualified component candidate. Full native cold, release, install,
and rebuild qualification remain **HOLD**. The original 180-second cold failure
on exact source `2f4ff983a41212ba8bc6a89aa9dda001610a9d89` is retained separately
in commit `44353bfc2b3eac8754c69e8b73e90134b6c027d5`.

## Measured cause and change

The retained original signed journals each contain about 1.17 GB of logical
observations. Their child receipts sum to 6.77 and 6.85 seconds, while each
driver consumed 15.47 CPU seconds in the original trace. The added index avoids
re-encoding an already observed raw byte block when its original encoded block
is still admitted by the existing journal boundary index.

A hit still reads the actual prior physical bytes, verifies their stored
SHA-256, independently decodes them, and compares every decoded byte with the
current raw bytes. Index collisions and eviction use the original encoder.
The existing encoded index, stream hash, final physical hash, archive replay,
all execution nodes, and all child runs remain required. The additional 4,096
entries occupy the final 262,144 bytes of the original 4 MiB private workspace.
No execution result is reused.

## Actual component evidence

The candidate was constructed through the four pinned independent native seed
roots, including native machine emission and native packing. It has no target
or successor compiler dependency. The original driver is the exact pre-change
image, SHA-256
`7ba244d01989b94b9368cdde3fdb5712dfdcc4c0f3f44d8e86a98fbe11e09e48`.
The candidate driver is
`772fba5a47d3b662c94ef5c773f6f4836764ccb2bc3a57a96da222261b75f017`.

All 13 native callback controls passed: valid hits; partial reads and EINTR;
full raw-fingerprint collisions; raw-index misses; encoded-index eviction;
physical byte corruption, including corruption with an identical encoded FNV;
EOF and read errors; stored digest corruption; and invalid cached extents.
These controls invoke the actual candidate policy and its actual native SHA
companion. Their outcomes and guard checks are in `qualification.json`.

All eight pairs of full native driver runs exited zero. Each pair produced
byte-identical complete physical journals and byte-identical 64-byte receipts.
They cover zero data, random data, code, code with a zero workspace, full FNV
collisions, both index-collision classes, and chunk boundaries. The retained
archive contains all 16 original journals, stdout receipts, stderr files, the
qualification report, and an independent per-file SHA-256 manifest.

On this local component run, repeated random data was 2.07 times faster,
repeated code 1.99 times faster, and the code/workspace shape 1.65 times faster.
The zero-only sample was approximately unchanged (0.99 times). These are
finite component observations, not a claim about the complete cold deadline.

The three existing private codec scope/reproducibility tests also passed.
The checked-in candidate HIA assembly was independently regenerated exactly.

## Original failure readback

`original-cold-profile.json` was independently produced from nine retained
original journals, matching every complete record to its exact source plan.
Seven selected journals were complete. The two scalar-cast journals retained
only 20,506 and 21,095 complete nodes at the original deadline; they remain
explicitly incomplete. This diagnostic neither executes a product nor changes
the old source or receipts. The diagnostic program is retained beside it.

`native-journal-controls.tar.gz`: 512,853 bytes, SHA-256
`f3b4b7c3e4671ebdbb97d1d766377ba7a4f6403b23d61ccc626f445254f265bc`.

A new native source freeze and the original complete 60-phase qualification
are required against the final integrated source. The original limits remain
180 seconds plus 3 seconds cleanup, two phase workers, one archive worker, two
pending archives, and four unsealed phases.
