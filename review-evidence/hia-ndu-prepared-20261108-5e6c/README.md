# NDU prepared-ranking evidence, 2026-11-08

This directory preserves two complete original-native mechanism experiments
and one registration rejection. The source/API contract, rounded results,
cost boundaries, artifact provenance and reproduction commands are documented
in [HIA_NDU_PREPARED_RANKING.md](../../docs/HIA_NDU_PREPARED_RANKING.md).

**P2 remains HOLD.** Prepared executable reuse improved the original one-shot
transport in all 24 pairs of each campaign. The same-resource ordinary scalar
control was faster in all 24 pairs of each campaign and made identical
selections. Neither campaign establishes general NDU productivity or economics.

## Files

| File | Contents |
| --- | --- |
| `first-registration.json` | Frozen earlier source, all requests, orders and budgets |
| `first-result.json` | All paired observations and explicit HOLD conclusion |
| `first-replay.json` | Independent consistency replay of the original records |
| `first-originals.tar.xz` | Complete earlier campaign directory, original I/O, process records, source snapshots and build receipt |
| `final-registration.json` | Frozen final source, same task inventory and orders |
| `final-result.json` | All final-source paired observations |
| `final-replay.json` | Independent replay of final-source original records |
| `final-originals.tar.xz` | Complete final-source campaign directory, original I/O, process records, source snapshots and build receipt |
| `unit-tests.txt` | Exact final local 40-test output, zero skips |
| `registration-rejected.json` | Reconstructed diagnostic for a pre-native clean-source refusal; setup time unavailable |
| `provenance.json` | Exact archive hashes, artifact identity, costs, timestamps and source bindings |

Each tar.xz archive contains an `archive-contents.json` with the SHA-256 and byte length of
every other member. A source frozen by the first campaign was restored from its
recorded local commit after execution and rehashed against the registration.
The final qualifier exports actual frozen source during registration before
native execution. The final run followed a context-entry descriptor-close fix;
all prior observations remain available.

There are 72 cells, 1,020 native calls and 510 ordinary calls in each completed
campaign. All cells completed without a retry. The final campaign's 510 paired
native stdout values were byte-identical, and independent replay confirmed
original process cleanup, request/result bindings and disjoint cost arithmetic.
Clock readings and the shared host are not independently attested.

## Offline replay

Extract one archive into a new directory, then use the corresponding digest:

```sh
python -B tools/replay_hia_ndu_prepared_ranker.py \
  --directory /absolute/path/to/extracted-campaign \
  --registration-sha256 24e435dffef293e1f785094620630eacdfd39bf48957e20c4a4706136cfba66b \
  --output /absolute/path/to/new-replay.json
```

The shown digest is for the final archive. The first archive uses
`d49ef0292bb7be35d7d709f1b493d543eeb9295163a85bf184b8942d3670370e`.
The replayer needs only Python's standard library and the archive. It does not
need the native binary or the original local source checkout. Its own exact
SHA-256 is recorded in the retained replay reports.

The separate original native binary is available in
[GitHub Actions run 42497221815](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42497221815),
artifact `13624221619`. The binary and its full upstream source are not
duplicated in these campaign archives. The exact bridge source and original
build receipt needed to identify it are included.

The known historical native build cost is retained once as provenance, not
added again for every request. Environment replacement, code recovery,
development, acquisition, unknown setup cost, monetary cost and energy are not
zero-valued and do not form a complete lifecycle ledger.
