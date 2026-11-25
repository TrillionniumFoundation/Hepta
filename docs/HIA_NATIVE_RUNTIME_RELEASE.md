# Native public runtime release stage

The source-bound stage 12 now constructs and publishes `hia-ndu-evaluator` and its frozen `hia-ndu-evaluator-build.json`. This checkpoint qualifies this new construction and the exact delivered products. It does not claim that the full new native release, unified object dispatcher or final cold/install chain has passed.

## Runtime construction

`examples/hia_bootstrap/release_stage_runtime.hiastd` contains 189 native DAG nodes, 130 handles and 11,784 bytes. It captures the retained HIA sources, independently compiles each source twice through the current sealed `hia-source-build`, compares complete compilation results, constructs its filter and packer with the native source kit, and invokes the actual HIA packer. Runtime execution uses HIA, the existing native release owner and fixed syscall transport. The Python author and qualifier are development tools, not production dependencies.

Every frozen NDU source pin, five compiled module pins, source-compiler pin, packer-wrapper pin, final product length and SHA-256 is checked before publication. The complete generated evaluator is 685,362 bytes with SHA-256 `7dbe3f18f329be0124ba1af55bad4358654262e1b0503a7745b56b9f3b76057e`. The receipt is published only after those actual checks. The original receipt retains its original compiler/filter provenance; the new construction report separately records every tool that actually ran in this stage. It does not claim to have executed an old filter root merely because an output matched.

## Actual qualification

The final qualifier captures and seals the real compiler once, performs two native compilations of each of ten source files, builds the actual composer/filter/packer, and matches every frozen module, wrapper and final image pin. Five native packer controls reject changed magic, reserved word, first length, truncation and trailing data. A valid explicit-abstain request executes the resulting native CLI, whose response identifies `hepta.hia.ndu_evaluator.v1` and `hepta.hia.ndu-native-response.v1`. All sources are reread after execution. The author also reproduces the recipe and stage inventory byte for byte.

Earlier fixture failures remain recorded: an invalid empty/cap-zero request and a missing-abstain request were correctly refused; the next fixture incorrectly expected the historical Rust response schema. Neither failure required any product-source change. The final native response schema and its explicit reference entry identity are preserved.

The companion JSON contains exact source, native tool, product, command and report hashes. To reproduce the development construction gate, run `tools/qualify_hia_native_runtime_release.py --compiler <actual-qualified-hia-source-build> --output <new-private-directory>`. The compiler must match the frozen receipt before it can run. Final release qualification still requires the whole matching source authority, cold/admission/post-build, installation, reconstructed package, Worker, actual agent and unchanged 136-tool boundary gates.
