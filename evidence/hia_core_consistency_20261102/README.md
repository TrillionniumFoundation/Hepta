# HIA Core consistency increment — source-bound positive and negative evidence

Tested code: `d55ea70cf854428f30c2ba7e044741f5f379a419`; tree `a6981ee997a59c70ecf422e8202526c49567cf16`; parent #549 at `1f6b45f1cfe148adb8c03b17d8a71bce2db5ac41`. Implementation: [PR #550](https://github.com/TrillionniumFoundation/Hepta/pull/550). This branch carries evidence for that source; it is not a release or qualification of its own commit.

## Results

- Four adversarial ownership-cache tests fail on the unchanged parent; the fixed focused suite passes 69/69. The full checker and incremental checker now both reject after capability-policy changes.
- Final strict integrated suite executes exactly **210 planned tests: 209 pass, one error, zero skips**. The retained error is the sealed executable path `/proc/5/fd/4` unavailable in the local container PID/proc namespace. No execution-custody check was bypassed. The overall local gate is **false**, pending independent real-host CI.
- Native scalar conformance includes 1,132 independent mathematical-oracle/VM cases, 894 normal native cases, 60 exact SIGABRT probes and 20 VM first-trap-order probes. Native aborts alone do not distinguish trap codes.
- Twelve fresh-process proof measurements all prove both guarded candidates under the same 10,000 ms solver timeout. Median guard-8 proof-call wall: 626.58 to 11.44 ms; guard-10: 7,006.10 to 11.03 ms. Both equality partitions remain in one query. This is local proof cost, not an end-to-end 10-second guarantee or native/NDU speedup. Original source hashes and the modified working-tree hashes are preserved in each timing receipt; the timing study preceded the final commit.
- Final same-source checked-reduction experiment completes with unchanged clean source and tool/artifact identities, but only **45/60** Rust comparisons pass. Heldout and broad parity gates remain **false**. Rust 1.95.0 uses opt-level 3, fat LTO and one codegen unit; the explicit byte-arithmetic comparator is retained. These workloads do not constitute application-wide or PGO qualification.

## Reproduction

On Linux x86-64 with actual Clang 20, Rust 1.95.0, and Z3 4.15.4:

```sh
cargo fetch --locked --manifest-path rust/hia-core-shadow/Cargo.toml
CLANG=/usr/bin/clang-20 HEPTA_TEST_CLANG=/usr/bin/clang-20 python -B tools/qualify_hia_three_lane.py --suite core-consistency --output /tmp/new-core-receipt.json
python -B tools/qualify_hia_reduction_release.py --output /tmp/new-release-study --clang /usr/bin/clang-20 --rustc "$(rustup which rustc)"
```

Use fresh outputs and a clean exact checkout. `proof-timings/measure.py` retains its original command paths in raw receipts; pass your own `--baseline`, `--patched`, and `--output` paths as shown by `--help`. Do not infer proof reliability or future performance from these three local trials per candidate/arm.

P0–P7 remain **0/8 closed**, `DENY_ALL`, no safety certificate or production activation. The all-language refinement, cross-target hardware/ABI, third-party maintenance, complete-cost NDU, unseen real Agent and durable production recovery gates remain open.
