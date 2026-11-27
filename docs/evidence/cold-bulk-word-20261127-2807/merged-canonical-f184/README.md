# Integration with canonical f184

The canonical head f1849351072dde8df5a568e0c5965d8ed932ff2f is retained by a normal
two-parent merge, b03b109165552032310d3b6882c06b5bf97ee784. Its parents are the original
qualified cold-bulk-word head beba4afeca9cf27e879821f8467a841e7f7bc33f and that canonical
head. There is no rebase, dropped parent, or replacement of the upstream custody and
readback work.

The incoming native source change fixes release_stage_generation_lease.hiastd. All
native authority sources, recipes, worker identities, admission sources and the contract
were regenerated from the combined tree. Only docs/HIA_SELFHOST_CORE_SUPPORT.json
needed a further content update. The authority remains 1285 sources; the original
60 phases, 479882 qualification nodes, 14 checks and 180 seconds plus 3 seconds are unchanged.

## Actual checks on the merged source

- Eight source/profile author tests ran and passed again.
- A fresh preseed made 57 native invocations from the seven verified original bootstrap
  inputs and 15 current HIA sources.
- All 31 newly built preseed products were compared by full-file SHA256 and byte count
  against the prior qualified products. Every product is identical, including the new
  cold-bulk-word backend and the complete private cold driver.
- All recorded component source pins and the additional construction and codec dependency
  Git objects are unchanged.
- Source preparation ran on the exact merge commit and regenerated the native contract
  with the canonical release-kit source fix included.

The earlier 646 native and 5278 codec controls remain evidence of the unchanged component
sources and emitted images. They were not executed a second time for this merge, and the
old clean-HEAD receipt is not used as proof of the new source identity.

After this evidence and the new contract are committed, publication runs a fresh preparation
at that exact final HEAD. It must produce no source or development-artifact changes, the
same newly derived manifest and contract, and an empty tracked Git diff. The final receipt
is under finalize-merge-v2/receipt.json and the clean preparation report is under
freeze-merge-clean-v1/report.json in the dedicated ROG scope. The PR description records
the resulting exact head and report SHA256.

## Evidence contents

integration.tar.gz contains both merge execution receipts, their command outputs, the new
preseed report and the complete new source-freeze evidence. The first merge's full-index
whitespace check timed out after 120 seconds; its error is retained. After checking that
job's terminal unit and empty cgroup, the source-path whitespace check passed and the
ordinary merge continued without resetting the index or changing tests.

The new products are all byte-identical to the existing preseed.tar.gz members, so those
binaries are not duplicated. summary.json lists every newly constructed product, its
exact pin and the corresponding retained archive member. index.json pins the integration
archive and each of its members.

This is component and source-identity evidence. Whole-cold and whole-native delivery
qualification remain separate integration gates.
