# Source-only CI evidence: 5b66f96a

The actual GitHub Actions run for source commit
`5b66f96af480d6f599d8646cff6ef7e542de1072` completed successfully.
This is evidence for that source-only commit; the later evidence/documentation
head is a separate commit.

- Run: <https://github.com/TrillionniumFoundation/Hepta/actions/runs/40676510092>
- Job: `122776198122` (`verified-native`).
- Terminal run/job observations: `20261028T111024_209Z.run.json` and
  `20261028T111024_333Z.jobs.json`.
- Actual downloaded artifact readout:
  `20261028T111507_371780Z.actual-artifact-readout.json`.

## Verified archive bytes

`artifact-12810424438.zip` is the original downloaded GitHub artifact ZIP:
4,654,139 bytes, actual SHA256
`4efc9e6b11aa8dea795cf105de639f25fa951502494cd404952c9ce20232330a`.
The independently computed digest equals the digest reported by GitHub and
printed by the upload step. The temporary signed download URL is not retained.

The archive contains 405 members totaling 84,650,067 uncompressed bytes.
Only the five requested JSON files were extracted, totaling 1,209,437 bytes.
Their member names, sizes, SHA256 and ZIP CRC checks are in
`20261028T111330_701197Z.selected-extraction.json`. Large C++ result/AST
bodies were not read. Three small CLI ELF members totaling 46,152 bytes were
additionally hashed directly from the archive, without extraction or loading;
each equals its receipt's artifact digest and binds the same verified final
Core. No local proof, compilation or workload was executed by this review.

## Concrete results

The regression result reports 327 tests, zero failures, zero errors, zero
skipped tests and unchanged source bindings. The narrowing CLI result contains
56 actual native observations: 20 scalar `calculate`, 18 `full_lifecycle` and
18 `packet_xor`; all actual values equal their separate expected values.
Timeout and unknown candidates never published an artifact. The guarded CLI
has another 36 actual observations, also all correct, with timeout publication
refused. These CLI counts are separate from the 288-observation narrowing
qualification also run in CI.

At the recorded readout time, all 123 narrowing CLI source bindings, all 286
regression bindings and all three owned-state bindings matched the current
workspace bytes. This comparison is timestamped; it does not certify later
edits. The owned-state qualification records all seven refusal/ownership
controls as true, the same owner/allocation identity across switching, and a
final ledger of 17 allocations, 17 frees, zero live resources and two allocation
refusals. Its performance experiment was not requested.

The extracted native NDU identity binds private source commit
`c4a1bbed3a39beba43a6abf1a18b6f75c5725c21`, source digest
`82d9dde94b55b551e6fc2e11053d1907e888e06c852751f4cae02752d5c58baf`
and bridge digest
`7385e8ddf22dc48d615b650809cd206a969988f1b4081b8b299dd00e4ede9a69`.
The manifest's CI native executable digest is
`182b538f61121a85db1873e5f690960628a8dd55d093482e865f5e093ff40a0c`;
that native executable body was not independently loaded or verified by this
readout.

## Scope and chronology

Earlier timestamped observations are retained unchanged, including the initial
artifact-metadata-only readout before the ZIP was downloaded. The later actual
artifact readout records the successful byte verification.

Synthetic `correct`, timeout and infrastructure-failure cells printed by model
fault-control unit tests are not actual model-cohort results. A passing CI step
that retains a finite NDU experiment does not establish NDU performance
superiority. This CI run did not revise or repeat the separately registered
local eight-arm performance study, and it does not make private repository
`blocking-ci` pass. Serialized evidence remains diagnostic data, not deployment
authority.
