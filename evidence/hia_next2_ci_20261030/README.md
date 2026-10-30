# Exact-source CI evidence: 953fa62

The official [GitHub Actions run 41081527613](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41081527613) completed successfully. The unchanged bounded offline reader independently verified this run's ZIP and retained API receipts. `VERIFY.json` has both `passed=true` and `latest_required_source_verified=true` for source `953fa62dee5aa563551d57b1374ab95b6d548b45`, tree `aa0683509a02ca97e4e0c1dd723e4047f50d81b3`.

## Observed denominators

| Observation | Actual count |
|---|---:|
| Integrated gates | 8 |
| Full Python regression, unique method IDs, zero skips/errors/failures | 4346 |
| Rust tests, zero failed/ignored/measured/filtered | 121 |
| Rust binary/doc-test launch and footer records | 21 |
| Critical coverage groups / modules / methods | 82 / 194 / 1926 |
| Canonical capabilities / unique selectors | 50 / 527 |
| Recorded tracked files / external identities | 6907 / 440 |
| ZIP members / expanded bytes | 46 / 7367996 |

Critical coverage and canonical selectors are checked subsets of the full regression, so their counts are not added to the full Python total. Three conditional standalone-profile workflow steps (20–22) and the alternative profile's artifact step (25) were intentionally skipped because this run selected the integrated profile; the integrated qualification, matrix, and artifact steps (23, 24, 26) succeeded. The actual selected Python, Rust, and canonical test logs contain zero skipped or ignored tests.

## Identities and scope

Official artifact `12993630367`: `1364149` bytes, SHA-256 `c958985f54b2ace092af6c2ed38f95b06bd73414b6365a23bc4931c88794faa0`. Canonical contract SHA-256: `3ff0362f995c8341ab75fa32c19cc6bb9fc5d1bc1bbe932ab00d45409ef62faa`. `CI_PINS.json` binds the official completed run, artifact API digest and download receipt. `MANIFEST.json` binds every ZIP member.

`verify_ci.py` is byte-for-byte the prior reviewed reader (SHA-256 `e2ab3be7afd0e2b47feb5a0d5a465cc9cc8c2a37426b002a89ec341d58e16437`). It performs a bounded no-follow single read of the ZIP, verifies its official digest, limits expanded sizes/types/paths, and never extracts or executes its contents. It compares source and external inventories before/after, checks all eight separate gate reports against the qualification report, recomputes unique Python IDs, parses each Rust binary footer, verifies exact critical subsets and canonical selector statuses, and keeps all unsupported safety/optimality claims false.

This ZIP records source/tool inventories; it does not bundle the complete source checkout or tool installation and does not independently re-hash those absent bytes. The current CI pass does not reclassify the CRC cold-cost negative observations or the V13 model qualification failure. It establishes no global optimality, absolute safety, or broad performance superiority theorem.

## Cost and raw retention

`SUMMARY.json` gives the measured download and reader costs. Reader inner, process and outer costs are nested. `ACQUISITION_COSTS.json` preserves instrumented connector call durations at millisecond resolution and explicitly leaves the initial uninstrumented calls and complete authoring/manual cost unknown. Raw API snapshots include earlier in-progress states, the final official run/jobs/artifact receipts, the official job log, and the exact ZIP. No workflow was re-dispatched and no test/model payload was run for this audit.

## Repeat the offline readback

Use a fresh output path; the reader refuses to overwrite a prior result:

```sh
python verify_ci.py --root . --pins CI_PINS.json --pins-sha256 df996516aa9db5818a34f836c97d0c5199b193304d8dea1d460f96367cde3225 --manifest MANIFEST.json --manifest-sha256 d55b5d59cfb5a1aa64cfae6c3de4c32389528896e258c2248ebc8c451534c1b3 --output /tmp/hepta-ci-953-independent.json
```

`VERIFY.stdout`, `VERIFY.stderr`, and `VERIFY_EXECUTION.json` retain the actual first readback and its outer receipt. `FILES.json` lists the final portable package files and hashes except itself. No signed download URL or credential is saved.
