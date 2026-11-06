# HCSN P2: binary64 normalization breaks exact scale equivariance (Iteration 43, HOLD)

Parent: Hepta Draft PR #745 exact HEAD b05d49607c4b90c424623e9aee1f6e3d0d70d864; exact source Git blob ac5a4a6c757c5c9c01983639d17178b29c08d406. This branch adds a **negative regression only**.

The positive rational rays [1,1] and [7,7] are exactly identical (integer cross product zero). Their binary64 normalized values from Math.hypot differ: 0.7071067811865475 versus 0.7071067811865476 in each coordinate. write([1,1],17) then read([7,7]) returns ambiguous, while read([1,1]) returns known. Attempting scaled write throws AddressCollision. No false acceptance was observed.

Fixed exhaustive small-grid probe: integer x,y in 1..12 and positive integer scale 2..19, 2592 equivalent rays. Node 22.16.0: 1737 known, 855 ambiguous, 0 unknown. This is a deterministic grid count, not a failure-rate estimate or learned-model result.

The issue is representational *liveness*, not a demonstrated signature bypass: a naive epsilon-key equivalence would instead risk treating truly different learned semantic keys as known. Protect the conservative ambiguous response until source provenance and a stable identity contract are justified. There is no evidence that the actual learned HCSN has solved address aliasing, reset accuracy, Selective Copy/MQAR or OOD heldout.

Run, on the exact branch:
- git rev-parse HEAD
- node --version
- test "$(git hash-object research/hcsn/p2_exact_occupancy_reference.mjs)" = ac5a4a6c757c5c9c01983639d17178b29c08d406
- node --test research/hcsn/test_p2_exact_occupancy_reference.mjs research/hcsn/test_p2_config_contract.mjs research/hcsn/test_p2_signed_zero_reference.mjs research/hcsn/test_p2_input_snapshot.mjs research/hcsn/test_p2_scale_equivariance_negative.mjs
- node research/hcsn/p2_scale_equivariance_evidence.mjs --json /tmp/scale-raw.json
- node research/hcsn/p2_scale_equivariance_evidence.mjs --strict  (expected **nonzero 2**; not accepted scientific gate)

Actual local exact-source test results: 4/4 new tests passed; independent strict command returned 2. Original 23 controls were not run locally in this iteration; the exact-head workflow explicitly runs all 27, and a queued or unobserved workflow cannot count as passed.

P0–P6 remain OPEN; all previously established negative tests and CodeQL findings retained. No merge, activation, signature relaxation, or Library deletion.
