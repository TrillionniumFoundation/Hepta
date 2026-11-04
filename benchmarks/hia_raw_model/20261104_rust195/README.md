# Rust 1.95 raw-model qualification and fixed service study

Measured source: `99d4cb5942755ba12e1d3006558bb53d435734d8`. The original NDU pin is `8e52e1187f47f6d4edc8d942fc7cb7eca4bc447d`. This evidence commit archives that earlier clean source run; it does not rewrite its source identity.

A new isolated release build used Rust 1.95.0 and an initially absent target directory. All 22 actual native correctness/refusal tests passed with no errors or skips, covering the full 128-model registered corpus, 318 recorded one-shot native calls and 20 refusals. Persistent-stream lifecycle tests are separately named in the qualification log. The earlier protocol-only unit invocation had 18 passes and five legacy-profile tests skipped; it is not reported as a native pass.

The single pre-registered service campaign completed all 2,976 calls and 744 equal decision/witness quartets, with no failures, unattempted calls or changed inputs. No sample was dropped or rerun.

| Arm | Service seconds | Observed build + service seconds |
| --- | ---: | ---: |
| one_shot_exact_dp | 12.478576895 | 65.153129974 |
| one_shot_ndu | 12.689370712 | 65.363923791 |
| session_exact_dp | 6.184250563 | 58.858803642 |
| session_ndu | 6.435034619 | 59.109587698 |

The NDU service cost was 1.6892% above exact DP with one-shot transport and 4.0552% above exact DP with sessions. All decisions and witnesses were identical. Both modes benefit from process reuse; this does not establish an incremental NDU planning benefit.

The common observed build is 52.674553079 seconds, charged once in full to each standalone alternative. Its scope is build() entry through source extraction, staging, compilation and receipt preparation. The complete outer build command was 52.810597380 seconds.

A first attempt against the existing promisor checkout failed at the 180-second source/build timeout before creating the build output directory. Its complete outer attempt consumed 183.246959526 seconds and is retained separately in failed_source_attempt/. The failed build command's original streams were not returned by that first timeout wrapper: they are unavailable, not empty. The successful retry used the preexisting local, remote-free object mirror for the same exact upstream commit, with lazy fetch disabled. No original NDU source changed. These prior costs are additional to B and cannot be silently removed from an enclosing preparation ledger.

shared desktop host; root reports no concurrent performance benchmark or model inference, but small source tests/integration work and independent proof profiling may overlap; no exclusive-host, CPU pin, machine-cold or population inference claimed.

These are bounded planner-service observations. Application execution, imports, caller audit/logging and source/dependency acquisition outside the recorded build are excluded. The preexisting mirror/cache acquisition is not measured here. This is not a fully cold-machine or complete application-lifecycle comparison, and there is no strong-fixed or lightweight application arm. The full-lifecycle NDU advantage claim remains false.

The archive retains original registration, result/error records, compiler streams and build receipt, actual-native transcript, all service records as lossless gzip, outer command accounting, failure records, source identities and exact driver scripts. Original uncompressed transcripts remain at the host output paths; gzip decompression hashes were checked before this archive was committed. Native executables and staged upstream source trees remain on the host and are not duplicated in Git.
