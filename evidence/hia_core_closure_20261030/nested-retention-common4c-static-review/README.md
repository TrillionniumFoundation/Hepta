# Independent static review of the nested-view/native-retention integration

The local integration passes static composition review:

- Local commit: `4c96828de373b8a0e9edd05c2d91d8d405a505f1`
- Tree: `d3fb9ae660d79219071f03bd21c30b84c2678602`
- Actual local parent: `2f4891ce7c5b92979ffb4c65575075367a1ecb15`
- Intended public parent: `a6cfb7e00a1c08276d27459bdcc5628aa7622079`

The reviewer is `review_resume`, independent of integration assembly and the
nested-view implementation. Its earlier authorship of the retention protocol
tests remains disclosed in the original component review.

## Source composition

The completed audit passed **47,402 read-only conditions**. All 7,702 tracked
files were materialized and checked against their raw Git blob bytes and modes
before and after the review. The checkout remained clean. No candidate module
was imported, and no test, native program, compiler, checker or oracle ran.

The two component changes have disjoint file sets: five retention files from
`2f4891c` and ten nested-view files from
`6b83eae0aef1cfbc9654510b55f5c35ed0bd55d5`. Every nested-view file is byte-for-byte
the independently reviewed component file. Every retention file is unchanged
except its native-host workflow, whose sole additional change is the new
branch allowlist entry.

Exactly three workflows gain the single branch token
`codex/hia-nested-views-native-retention-20261030`: the main qualification,
native-host and upstream-C++ host workflows. Removing that one addition from
each reproduces its exact 2f4891c bytes. The separate six-outcomes workflow
change belongs to the already reviewed nested-view component. This gives
exactly 17 cumulative paths relative to the intended public parent: 5 + 10 + 3
with the native-host workflow counted once.

The entire 106,130-byte cumulative patch was applied in the reviewer's own
temporary index based on the intended public parent a6cf. It independently
reconstructed the declared integration tree. The raw 17-file export, hashes,
file modes and exporter identity were also checked.

Both original peer PASS records are hash-bound in `review.json`. Their local
source identities, original failed attempts and subsequent corrections remain
unchanged. Their results are not relabelled as integrated-tree execution.

## Exact execution plan, without execution credit

The canonical contract is byte-identical to the reviewed nested-view contract:
359 distinct methods, 36 capabilities and unchanged false unproved-claim
fields. The precise planned populations are:

| Population | Outside canonical359 |
| --- | ---: |
| Existing source regression selection: 92 original methods | 68; the other 24 are already canonical |
| Native-retention protocol selection | 25 |
| Environment protocol selection | 17 |
| Original NDU convergence methods | 2 |

These sources have no cross-group duplicates. The exact method union is
**471**, consisting of canonical359 and 112 additional methods. Removing the
two NDU methods from the additional selection gives the separately scheduled
110-method difference.

All 471 class/method identifiers were checked using ASTs without importing
the tests. Thirteen historical composite selectors inherit their method
definitions from the existing private support module; that exact import and
base-class relationship was checked explicitly. No duplicate discovery of the
support classes is inferred.

The plan's two NDU entries count test methods, not two graph invocations. The
unchanged original producer shares one graph between those methods; its actual
invocation count must be recorded by the later execution. The two planned
GCC/Clang host matrices and their retained files are separate observations,
not extra method counts.

## Audit provenance and limits

The first local auditor attempt misread the plan's `original` count as a list
and stopped with a `TypeError`. Its script and raw logs are retained as
`attempt1-*`. The auditor was corrected to compare that count with the actual
original method list already read from its bound input. No product source or
plan was changed, and neither auditor attempt executed a method or native
program. The final completed review is `review.json`; its full source and
input inventories are retained separately.

This package establishes static preservation of the reviewed components and
the exact planned selection. It does not qualify this integrated tree or a
future public commit by execution. The actual public SHA must receive its own
source-bound qualification. Python remains production authority, optimization
policy remains `no_change`, and all 27 strict P0–P7 blockers remain open.
