# Final artifact continuity review — run3

**The final qualification remains `measurement_inconclusive`.** The unified run completed 10/11 gates with 1,787 tests and zero skips. All fixed performance time-ratio limits passed, but two groups exceeded the unchanged 5% relative-MAD requirement:

| Group | Relative MAD | Required maximum |
|---|---:|---:|
| constructor_error / HIA LLVM | 5.054698% | 5.000000% |
| two_stage / handwritten Rust | 5.285384% | 5.000000% |

This bounded review verifies artifact continuity and schedule adherence. It does not change the qualification result or infer a physical cause for the remaining variability.

## Exact artifact continuity

The driver, HIA library and handwritten Rust library are byte-identical between run2 and run3. The generated Rust whole-ELF identity differs; fixed-length construction does not claim identical embedded path strings or identical whole binaries.

For generated Rust, this review compared all three measured kernels and every defined allocation-named function: **119 functions**. Their exact instruction bytes and addresses match between run2 and run3. The complete `.text` section has the same address and size, but three bytes outside those compared functions differ; all three offsets and before/after bytes are retained in `review.json`. Whole-ELF and whole-`.text` reproducibility are therefore not claimed.

| Artifact | Run2 SHA-256 | Run3 SHA-256 | Byte-identical |
|---|---|---|---|
| driver | `c80eacbd74a83d31f53ae93d137e3b874f4155b09e4541a53442265cdcc72e22` | `c80eacbd74a83d31f53ae93d137e3b874f4155b09e4541a53442265cdcc72e22` | Yes |
| handwritten_rust | `123d8d5d9c20b23e9dc6f06ea43a52f018ef6690a5d9e20fd4257d17f40b9a77` | `123d8d5d9c20b23e9dc6f06ea43a52f018ef6690a5d9e20fd4257d17f40b9a77` | Yes |
| llvm | `171dbadc0090fc04c72bbb3a27f1f46d05dcb9a5d5ede9ffb3de6ff859467d8f` | `171dbadc0090fc04c72bbb3a27f1f46d05dcb9a5d5ede9ffb3de6ff859467d8f` | Yes |
| rust | `c7c9b284955b00043ba37f7a9e3a94bb17fa98a085f725d8a546a5e50b242935` | `2dabac3ed28ee62eae13decfc2c52fa214b24a9a586507930ee02ea4dbacb91d` | No |

## Retention and schedule checks

All **16 retained files from run2 and 16 from run3** were independently rehashed. Sizes, hashes, manifest identities, original-to-retained path mappings and measured/resource-observed artifact identities agree. Every native sample also agrees with its retained raw stdout, library identity and driver identity.

All **63 run3 identities and sample indices match the preregistered v3 schedule exactly**, including the protocol hash. The counterbalanced schedule used for measurement is the same schedule used for evaluation; the earlier fixed-middle defect was not silently reintroduced.

## Scope

The review used existing ELF symbol/code inventories and read retained files. It did not modify source code, recompile a library or driver, execute a measured workload, collect a timing sample, change a threshold or select a replacement result. Run1 and run2 remain retained alongside the final run3 candidate. Remaining measurement instability is still an open performance qualification blocker.

All supporting numeric, identity, schedule and static comparison data is contained in `review.json`.
