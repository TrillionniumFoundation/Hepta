# Decode the one exact970 original-custody log

This is preparation only. No new workflow has been triggered here and no970original log stream has been decoded. The JavaScript function was constructed in V8, but no new input was supplied; no Python parse/product test was performed.

The decoder preserves the established HIA_ORIGINAL_FRAME_* v1 protocol and uses the new frozen354-path selection plus six custody originals. It accepts only exact16MiB/24MiB/24KiB limits, the original970artifact seal and the independently supplied actual create-run identity. A missing END, altered hash/offset/order, duplicate file, unexpected path, unaccounted target, incorrect FINAL or over-budget output is refused. An explicit complete HOLD stream can be retained as HOLD; it is never promoted.

EXPECTED-CONTEXT.json intentionally has run_id:null. Replace only that value after the parent agent supplies the actual single create-run API identity. A=1e45e6b02c28b388cd78ff3ca1ef62d6155d1925 and B=896cb5ceaf8a34c9263b26e8131886285042cea6 remain immutable. This preparation commit does not alter either, add a workflow, or change the trigger branch.

The exact existing hashes.js is blob033c84ac79687183024a7aa797f93404878e5afb and utf8.js is blobd16ad75009f894cbe8d1756ee6922964e47214b6, both retained under experiments/hia_ci_original_artifacts_actions_20261112/small-log-reader-r1/recovery-preparation/. Load those pure V8 helpers; do not use an external product process.

The Native producer-path review is included unmodified from4aa5c2958e8322b04d1f49bc6cb84088ee0425c1, blob7bfe74091f55b87cf99f10badaaaa8018f7fca8f. Its scope is static only. The actual354present/16MiB capacity still depend on the forthcoming original read.
