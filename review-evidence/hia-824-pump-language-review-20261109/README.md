# PR #824 pump containment and native language review repairs

Review comments 4509674154 and 4509674159 identify deterministic defects in
published head `786bc8e827d2355ac1e5c93fa7a9b355f6a2c06a`. Its CI and review
history remain intact. Local implementation commit
`d05222dc6953fd84a88a235e209c6bc4d8a2e5af`, tree
`f00f29f5e71aeb31c6792b232d179f7584ba9b43`, contains the repaired sources.

## Native pump containment

Every retained non-null pump must provide an exact nonnegative integer
`wall_ns` no greater than its enclosing selector call. This applies before
the early returns for failed attempts and retained audit errors, and in the
live completed-call audit. A null pump still means no pump observation was
recorded; it is never promoted into a successful native evaluation.

The 23-test scalar module passes without skips. Four new tests cover missing,
Boolean, float, negative and oversized pump times, failed/audit-error paths,
the exact zero/enclosing-call boundaries, and the original native campaign
with every NDU call shortened to 1 ns and its summary recomputed. Against the
old checker, the same 23-test suite has 21 failed subtests; `red-scalar.log`
preserves that result. `green-scalar.log` retains the repaired run. The
unchanged original 128-cell / 64-native / 307-object archive remains a
positive control, without launching another evaluator or benchmark.

## Full native language qualification

The native unittest now expects all 832 scalar witnesses, including the eight
Boolean equality/inequality combinations already present in the inventory.
The pinned support contract was regenerated from actual changed source bytes.
`red-language-count.log` and `green-language-count.log` exercise only that
assertion with an explicitly authored report; they are not native evidence.

A separate actual full language run passed **18/18 tests**, zero skips, in
79.714 seconds. Its retained qualification report passed **910/910 internal
checks** in 68.980492827 seconds and recorded all **832 scalar witnesses**,
66 positive programs, 250 rejections and 136 traps per compiler, under both
the original B3 and modified M3 HIA compilers. All 252 source hashes match
the repaired local implementation. These denominators overlap and are not
added together. `full-language-tests.log` and `native-language-summary.json`
bind the run and original report; the full raw records are archived separately.

This is full language qualification for the bounded v14 profile, not a new
full source-only cold selfhost run, general Core support or a compiler theorem.
Earlier 105-check reports bind older test/contract bytes and are not relabelled
as exact-source receipts for this repair.

## Preserved setup failures and remaining gates

The same twelve integrated modules now pass **258 unique tests** in 63.321
seconds, with zero failures, errors, skips or expected failures. The retained
driver checks uniqueness and the original native bridge's current adapter,
builder, lock and executable identity. The 70 native budget/proof/machine tests
and 23 scalar controls are included in 258, not additional tests. The three
native persistent-stream controls use the original CI-built executable and
receipt; this is not a new build or economic benchmark.

`stale-contract.log` records the expected stale-identity rejection before
regeneration. `first-driver-setup-error.log` records a local evidence-driver
serialization mistake before any integrated tests started; the corrected
driver unpacks the existing identity checker's pair result. Neither is a
passed test run or a changed production contract.

No previous CI run is cancelled or rerun here. Independent new-head CI and
review remain required before source merge, followed by merge-commit CI.
No default release lock, production configuration, state, journal, deadline
or native budget changes. A future default lock must still be copied byte
for byte from the final merged source's original successful CI artifact.
General compiler/machine/ABI/resource/FFI/ISA/loading proofs, the original
stranger-Agent lifecycle/provider bill and stable fair NDU economic value
remain HOLD.
