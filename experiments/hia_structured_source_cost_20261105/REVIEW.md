# Independent review: local structured-source parsing cost, r2

> Historical finite Core/native observations; removed harnesses are not
> delivered product entry points or current-source qualification.

**Recommendation: accept r2 for the next complete source validation and qualification.** The reviewed change preserves the current parser/validator boundary under the conditions below. This review and its two controls are not a qualification, Lean acceptance, or evidence that the final replay now fits its 600-second budget.

Reviewed source: `08402fc66f092ebe65adbb9d257cabeecf17eddf`.
Tree: `c970788b9d774a1ece75fbd50c662e2bca273df7`.
`retired harness core-syntax-structured-sources` SHA-256: `ee1b584163fb94e6f24e843ee5f4711a228af14abe1dfef306cd87ad6cbe7a3a`.

## Two rejected r1 behaviors and r2 repairs

1. **Invalid whitespace could cause quadratic rejection cost.** The r1 unanchored `_TOKEN.sub` repeatedly tried the `\s*` prefix at successive positions in a long invalid suffix. The retained bounded counterexample records about 21.5 / 91.0 / 323.0 ms for 1,000 / 2,000 / 4,000 trailing spaces. These are descriptive local observations, not timing gates. r2 first uses anchored `(?:TOKEN)*+` fullmatch. Each nonempty greedy token is committed as in the old adjacent-match loop; prior tokens cannot be repartitioned after failure, and an invalid whitespace suffix is attempted from its current position once. `findall` runs only after full coverage succeeds. Empty input still reaches the old incomplete-expression failure; trailing whitespace and gaps still fail lexical coverage. This reasoning applies to the exact nonempty token pattern and pinned Python version under review.

2. **External equality could mutate a cached decoded container.** In r1, a caller-supplied list/dict subclass could receive the cached root through `decoded_root == expected_tree`, modify it, and conceal an incorrect Raw value from a later subtree check. The retained AST-only counterexample demonstrates the old helper rejecting a recheck while the poisoned cache accepts it. r2 restores the exact original `_raw_value(root) == expected_tree` comparison: the external comparison receives a fresh recursively decoded value, while internal memoized values remain private. This avoids introducing a new deep-copy contract or changing the public helper.

## Local DAG reuse boundary

`verify_structured_source` creates a fresh decoder and environment for each invocation. The parser constructs builtin values, resolves only existing aliases, and implements `::`/`++` with fresh lists; it does not mutate published aliases. Internal subtree expectations are independently rebuilt from exact canonical bytes. Existing alias-validation calls, full-source reconstruction, hash/manifest checks, resource limits and subtree checks remain present.

The cache key retains `(raw_object, decoded_value)` and checks object identity, so temporary Raw wrappers cannot release their ids and cause stale hits. Entries are published only after complete successful domain and object-key-order checks. `_Raw` is only shallowly frozen: this design depends on private read-only parsed inputs and private decoded containers, not on the dataclass alone. It must not become a cross-verification cache or an API for mutable external Raw objects. The old `_raw_value` helper and its accepted domains remain unchanged.

## Independent actual-module controls

Two tests ran once against the actual module in the isolated optimization worktree, on CPU 9, with `-B` and `PYTHONDONTWRITEBYTECODE=1`:

- A real builder/verifier test constructs valid small sources, changes a Raw literal from 1 to 7 and updates its manifest hashes. Hostile root-dict and nested-list equality methods cannot conceal the mismatch; the independently rebuilt subtree comparison rejects both. Unchanged sources remain accepted.
- Four 16-KiB invalid whitespace/gap inputs are rejected by one coverage call each before global token extraction. A valid input makes one coverage pass and one extraction pass. This counts integration operations rather than imposing a short wall-time assertion; the regex-structure argument above addresses internal rescanning.

Result: **2 tests passed**, unittest body **0.020 s**, child outer wall **0.380669696 s**, exit 0, no retries. The outer wall includes child imports, unittest output and captured-log close/fsync; it excludes registration/source scans, controller transport and final receipt serialization. HEAD, tree, full Git status and module digest were unchanged before/after. No source worktree files were added or modified by this review.

Runtime job: `1a1aa35944f-fc05-3f29`.
Evidence: `/data/hepta-hia-round4-9925-20261105/evidence/proof-source-cost-independent-review-08402fc-r1` (`REGISTRATION.json`, test script, original stdout/stderr, `SOURCE.after.json`, `RESULT.json`).
Test SHA-256: `32b331f3a516f22d5a4a5da1f7567b46e26d2624ee7c7435d1fbff521467e0ed`.
Stderr SHA-256: `08b49667d2b4f2d20d422becd80015c1bc5474ee4d7360c544300b142e8806d6`.

The rejected r1 script/results are retained as `review-negative-r1.py` and `review-negative-r1.json`. Full 11-module/manifest identity validation and the complete timed replay remain separate required evidence; overlapping cProfile cumulative costs must not be added into a promised speedup.

If further cost reduction is necessary, the next conservative candidate is compiled-regex and prefix dispatch inside `core_syntax_partition_sources._parse`, retaining the exact original framing regex checks and order for applicable lines. Repeated whole-source validation or acceptance results should not be cached to satisfy the deadline.
