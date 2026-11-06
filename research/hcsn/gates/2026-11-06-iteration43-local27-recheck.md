# HCSN Iteration 43 exact-source local 27/27 recheck (HOLD)

Recheck performed after original 4/4 witness on Node.js v22.16.0, 2026-11-06 UTC. All source and all four pre-existing suites were restored locally and their Git blob hashes were independently matched to exact stacked source HEAD #745 `b05d49607c4b90c424623e9aee1f6e3d0d70d864`:

- `p2_exact_occupancy_reference.mjs`: `ac5a4a6c757c5c9c01983639d17178b29c08d406`
- `test_p2_exact_occupancy_reference.mjs`: `4bdf5933f1d930185018f9b032622391e27dcee0`
- `test_p2_config_contract.mjs`: `60c1cdf7d44bbcf3027043b4e791f94647de2ef3`
- `test_p2_signed_zero_reference.mjs`: `771cb5876424f036a2b4fc76d8ee5aa8314046e0`
- `test_p2_input_snapshot.mjs`: `687ec5cf80ee7c25a4790cd7b45d34f04ab9f6c3`
- `test_p2_scale_equivariance_negative.mjs`: `e480ee44480f2eac8ee75f588b064f517154fb0d`

Exact run: `node --test research/hcsn/test_p2_exact_occupancy_reference.mjs research/hcsn/test_p2_config_contract.mjs research/hcsn/test_p2_signed_zero_reference.mjs research/hcsn/test_p2_input_snapshot.mjs research/hcsn/test_p2_scale_equivariance_negative.mjs`

Actual result: **27/27 pass**, exit 0. Complete original TAP is stored as `gates/2026-11-06-iteration43-full27.tap.gz.b64` (base64 of deterministic gzip -n); decode using `base64 -d | gzip -d`. Decoded TAP SHA256 `846b4ed5378f409f1d33d515af2c997f7f0f6a15559f2544bf827bd8aa52d790`. Original 4/4 standalone TAP and P0–P6 strict exit 2 remain separately recorded.

**Science gate status**: none of P0–P6 has external acceptance. This 27/27 is only the bounded exact-source occupancy regression, NOT original HX/QVI, full HCSN learned-address, independent heldout, FLOP fairness, GPU profiling, or production qualification. GitHub exact-head Actions conclusions must be checked separately; a queued check is not green.
