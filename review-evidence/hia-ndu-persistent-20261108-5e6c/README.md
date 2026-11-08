# Persistent native NDU evidence, 2026-11-08

This directory preserves the complete registered three-arm native experiment.
The API, framing contract, cost boundaries, observed regression and CI commands
are in [HIA_NDU_PERSISTENT_RANKING.md](../../docs/HIA_NDU_PERSISTENT_RANKING.md).

**P2 remains HOLD.** Persistent transport was slower than prepared transport
in five of six single-request pairs. At the registered lengths 4, 16 and 64,
all six pairs favored persistence. The ordinary exact scalar control was
faster than persistent NDU in all 24 pairs and made the same selections.

| File | Contents |
| --- | --- |
| `registration.json` | Exact frozen sources, all 64 requests, complete arm order and budgets |
| `result.json` | Every paired timing and explicit HOLD conclusion |
| `replay.json` | Independent original-frame, identity, cleanup and arithmetic replay |
| `originals.tar.xz` | Complete campaign directory, all original byte observations, cell journals, 14 frozen source files and native build receipt |
| `unit-tests.txt` | Final 62-test output, including 22 new tests and three original-native tests, zero skips |
| `development-tests-1.txt` | Earlier 18-test output, including the deliberately external-reaped fixture bookkeeping warning |
| `development-tests-2.txt` | Earlier 21-test output |
| `development-notes.json` | Ownership review fixes, local workflow-validation failure and unknown development costs |
| `provenance.json` | Native artifact and archive hashes, exact source/time bindings and scope |

The archive contains 72 completed cells, 534 actual native processes, 1,020
original native responses and 510 ordinary controls. There were zero failed
or unstarted cells and no retry. All 510 native response pairs were
byte-identical. The single-request negative comparisons are fully retained.

Each archive member is listed with its byte count and SHA-256 in
`archive-contents.json`. Extract into a new directory and replay independently:

```sh
python -B tools/replay_hia_ndu_persistent_ranker.py \
  --directory /absolute/path/to/extracted-campaign \
  --registration-sha256 4fc7b9a02c26d8641f658975f7ed481a08b5dba8b094407aa38f73405a46c9c7 \
  --output /absolute/path/to/new-replay.json
```

The replayer needs only Python's standard library. It verifies original
request/response bytes, closed source identity, frame session/sequence,
complete lifecycle cleanup, finite scalar selection, disjoint owner costs and
paired summary arithmetic. It does not execute the native binary or
independently authenticate clock readings.

The real new binary is in
[CI run 42505864233](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42505864233),
artifact `13627467066`. Its exact SHA-256 and original build cost are retained
in `provenance.json`; this archive does not duplicate that binary or the entire
upstream repository. The original build receipt and exact bridge source are
included.

The first CI build compiled production Rust and ran the previous 142-test
integration suite. The three newly authored Rust framing unit tests are not
included in the local 62-test count; the proposed updated workflow invokes
Cargo test and requires all three by name, with zero ignored tests.

Local collaborators paused CPU-heavy work during the 2.428-second campaign.
The host remained shared and unrelated sessions were not excluded. Earlier
native functional checks had warmed unknown caches. Acquisition, development,
environment recovery, energy and monetary costs remain incomplete and are
never assigned zero to assert an economic result.
