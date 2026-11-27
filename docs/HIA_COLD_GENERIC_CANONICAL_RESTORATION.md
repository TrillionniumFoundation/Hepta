# Canonical generic cold corpus

The thirteen original generic families are retained in the native `cold_plans`
pools. The complete 0768 branch was merged before removing its 1,601 duplicate
payload files from the current tree. All fourteen original metadata files remain
byte-identical. The merge parents retain the full historical tree.

`tests/fixtures/hia_cold_generic_canonical_pool_v1.json` records each original
path, Git blob, SHA-256, size, mode, canonical pool and exact byte range. The
development restorer validates the complete fixed map, all thirteen pool files,
all fourteen metadata files, pool headers and both padding regions. It writes
a fresh directory outside the source tree, verifies every output, and rereads
every input before returning.

```sh
python -B -m tools.restore_hia_cold_generic_corpus \
  --source /absolute/path/to/Hepta \
  --output /absolute/path/to/new-corpus \
  --report /absolute/path/to/new-restoration-report.json
```

The output contains exactly the original 1,615 files. Restoration executes no
compiler, VM, native program or reference implementation, and makes no cold
qualification claim. The report distinguishes recovery from product execution.

For development authors, the two original collection commands now require
explicit external `--output` and `--data` paths. Importing them creates no
source directories and does not replace assembly or VM entry points. Their
original collection loops, assertions and normalization branches are preserved
by a whole-source fixture and AST comparisons. Fresh authoring remains a
development action; the historical qualification JSON is preserved as historical
evidence and is not relabeled for newly generated inputs.

The planner already accepts its input data directory explicitly. After
restoration, `source_pool(restored, output, families=(family,))` recreates each
canonical pool byte for byte. No duplicate generic phases are added to the
production catalog: its existing 60 phases and 479,882 nodes are unchanged.

## Verification

The dedicated physical controls cover full recovery of all 1,601 payloads and
fourteen metadata files, byte-identical reconstruction of all thirteen pools,
missing or altered authority and inputs, symlinks, input and output changes
after restoration, destination overwrite protection, import side effects and
preservation of the original author assertions. These data controls supplement
the separate native cold and whole delivery gates.
