# Source-bound trusted Core evidence

Implementation: `4eacb263b6e73bfee813317089cd0490fd82518f`, tree `8da715748f9a423a51a708be4934eafe83658989`, stacked on #550 (`d55ea70`).
[PR #551](https://github.com/TrillionniumFoundation/Hepta/pull/551) contains the implementation only.
This evidence branch adds observations and is not itself a qualified implementation.

| Check on the published implementation | Result |
| --- | --- |
| Exact trusted Core suite | 269/269, zero skips/errors/failures |
| Exact inherited Core consistency suite | 210/210, zero skips/errors/failures |
| Additional P4/native/gate controls | 70/70, zero skips/errors/failures |
| Rust Core tests | 121/121, zero ignored/failures |

Groups overlap and must not be summed. The two exact receipts assert unchanged clean source,
matching planned/started/completed identities, and bind the published commit and tree.
Pinned Z3 4.15.4, Clang 20.1.8 and Rust 1.90.0 were actually used locally; versions,
binary hashes, source-file hashes and bootstrap identities are in `published-source-tools.json`
and `environment/` inside the archive. The CI workflow separately requests Rust 1.95.0.

[raw-evidence.zip](raw-evidence.zip) preserves original parent failures, development tool skips,
prepublication clean-tree results, publication-SHA results, raw native/Rust logs and receipts.
[SUMMARY.json](SUMMARY.json) indexes final outcomes. [SHA256.json](SHA256.json) binds the archive;
`PAYLOAD_SHA256.json` inside it binds every payload. ZIP SHA256: `ebc7594b6dae0d28b99cac1bae7047630044e0b1d1f161c4ee09bea3e94eae47`.

Original parent witnesses: six cache-policy failures, three source-layout failures (with two
passing controls), and four lowering-budget/deadline failures. The final source contains sixteen
new regression methods. Development skips remain retained and are superseded only for their
specific checks by actual zero-skip final execution; they are not erased.

To reproduce final checks, check out the exact implementation commit, keep build targets and
receipts outside the source checkout, set the recorded compiler paths, then run:

```sh
python -B tools/qualify_hia_three_lane.py --suite trusted-core --output /outside/source/trusted-core.json
python -B tools/qualify_hia_three_lane.py --suite core-consistency --output /outside/source/consistency.json
python -B -m unittest tests.test_hia_optimization tests.test_hia_guarded_optimization tests.test_hia_scalar_lowering_check tests.test_hia_scalar_lowering_budget tests.test_hia_three_lane_gate -v
cargo test --locked --manifest-path rust/hia-core-shadow/Cargo.toml
```

For parent RED, use a separate `d55ea70` checkout and copy the three new regression modules
from this implementation into its tests directory, leaving all three implementation files at
the parent's exact bytes. Run the three modules directly with the same tools. The retained
original traces include the observed failures, source/test identities where recorded, and the
intentional small-budget counters; they do not claim a clean parent test tree.

The two tested implementation commits have identical Git trees; both rounds are retained.
No new performance benchmark, NDU/Agent trial, physical AArch64 execution or durable recovery
qualification was run. Full P0-P7 gates remain open. Cooperative deadlines are not hard OS
preemption, and live cache policy snapshots are not arbitrary process-code attestation.
