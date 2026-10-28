# Actual default-deleter unique-array project qualification

Final retained attempt02 passed on compiler source hash `743f3cead166d76994958e1864eb2ddaf0429e7e6b05f24b731db6bd3573aa8a`. All recorded source bindings were unchanged. The source/contract and native targets use the same standalone HIA checker as other routes.

After attempt02, an independently reviewed adaptive-runtime cleanup fix changed
`hepta/hia_adaptive.py`, and therefore changed the whole-compiler source inventory.
The two `cpp_unique_*` production modules were unchanged. The archived result
continues to describe its original exact snapshot; it is not relabeled as the
later source commit `25f357d4bfe2c5ce011efa40b983f5d488a7c2a6` or a later compiler
hash. The final root integration gate will recapture the C++ controls on the
final source bytes and report that result separately. The original qualified
artifact identities, source bindings, measurements and failures remain intact.

| Configuration | Cases | Owned-array allocations/frees | Actual allocation refusals | Live at completion | Project declaration occurrences | Standard-library declaration occurrences |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| three_weight | 437 | 401 /401 | 196 |0 |139 |92,058 |
| five_weight | 437 | 401 /401 | 196 |0 |139 |92,058 |

Both independently compiled original C++ programs and generated HIA targets matched the independent value/lifecycle oracle. HIA targets contain no original C++ link input. Removing a required linear drop was rejected without publishing an object in each configuration. C++ owner observations instrument `new[]`/`delete[]`; exception-runtime internal allocations are outside that trace.

Each configuration migrates two project free-function implementations, structurally handles composite algorithms/cross-TU transfers, and uses one explicit trusted `std::unique_ptr<unsigned char[]>` default-deleter contract. Zero foreign bridge functions and zero standard-library bodies are counted as translated. The 92,058 library declaration occurrences receive **dependency-only** dispositions; they are not 92,058 migrated implementations or proved declarations. No general C++ source-equivalence proof, custom-deleter/shared-ownership support, universal safety or performance advantage is asserted.

The full 67,599,769-byte qualification JSON, every declaration disposition, capture/header/source identities, source-derived HIA/Core/LLVM, independent cases, native objects/executables, commands and outputs are retained in the lossless archive. Full raw Clang AST streams are not retained: complete stream hashes/lengths, bounded EOF/census receipts and captured inputs are retained. Clang opaque addresses can differ on recapture.

## Costs and control history

The actual migration timer was 82.531603561s; qualification through final checks was 88.966702589s. Both exclude process startup, final report serialization and archive creation; qualification already contains migration and should not be added to it. Reported process and child peak RSS are each 196,768KiB. Human engineering time remains unknown. This is not a migration-cost superiority study or native speed comparison.

The initial development suite executed seven methods: six passed, one failed solely because an incomplete project was correctly refused at an earlier owner/ODR phase than the test expected. The destructor/admission contract was kept unchanged. The corrected missing-definition plus ODR test then passed in87.535s. Six final streamed-capture controls passed in1.120s, including actual process-group timeout cleanup observed through an exact child pidfd. Earlier `/proc/<pid>` assertions incorrectly crossed the environment's PID namespace; both failures are retained. These logs are separate invocations, not a claim that one final integrated13-test run already happened.

Attempt01 of retained native qualification refused after40.858801548s because another compiler module changed during capture. Its report and log remain present. Attempt02 used the refreshed stable source and passed. All development failures and the explicit source-drift refusal are kept; no failing case was deleted or rescored.

Archive creation and the benchmark lane briefly overlapped during the handoff. `ARCHIVE_LANE_OBSERVATION.json` records exact output file mtimes and the later UTC/monotonic observation, without inventing an unlogged absolute monotonic interval. The benchmark owner was notified to account for possible preparation contention; this C++ qualification is not a benchmark.

## Files

- `RESULT.json`: compact result, complete compiler-source bindings, counts, costs and scope limits.
- `qualified-native-02.tar.xz`: 30 members, 68,584,480 raw bytes, 1,229,488 compressed bytes; SHA-256 `29dba57095da6cdf9f1af65d920cb2c05f99ae042e634ee6b835da9f0ecf6dba`.
- `qualified-native-02.manifest.json`: exact ordered member lengths/SHA-256, archive identity and full extraction/roundtrip checks.
- `DEVELOPMENT.json` and original logs: earlier development refusals and validation corrections.
- `archive_evidence.py`: read-only qualification packager; it does not rerun native programs or edit results.

General profile documentation is in `docs/CPP_UNIQUE_PROJECT_MIGRATION.md`. Broader integrated tests and exact-head CI are reported by the root delivery independently of this scoped qualification.
