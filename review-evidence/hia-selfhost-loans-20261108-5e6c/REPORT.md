# Selfhost-Core v11: explicit borrowed-view lifetimes

This local source candidate adds `borrow.read`, `borrow.mut` and `loan.end` to
the existing borrowed-buffer profile. Its operation inventory is **40/50**.
Owned allocation/transfer/drop, owner chains, returned loans, general Core
signatures/types/effects and an all-input compiler or machine proof remain open.
The compiler source is `767db02473d2c4e0a388f8e23501553a553f4cba0c134f590ca693d5c4916b8f`.

## Implementation

The HIA-written checker stores each live capability's root, parent and active
state. Shared siblings and valid reborrows are admitted. Conflicting exclusive
loans, suspended-parent access, ending an external or non-childless loan, and
use after end are rejected. A consumed capability keeps its SSA definition.
Ordinary returns require every local loan to have ended.

Each CFG edge carries every live local loan and every selected capability's root
and parent exactly once. Sixteen existing bytes in each block record encode the
root and parent parameter indices; a separate known bit distinguishes unseen
state. The checker compares complete renamed incoming graphs at joins. A bounded
phase-zero reparse checks blocks whose predecessor appears later in source order.
No machine output is written before all reachable incoming graphs are checked.

The authoring aid removes an identity join when only one branch continues and
uses boolean instructions for total scalar boolean expressions. Expressions
containing calls, reads or checked shifts retain short-circuit control flow.
The resulting compiler has 58 functions, 4,470 operations, 1,219 blocks and
maximum SSA index 1,725. Its assembly has 353,140 bytes. Existing limits remain:
1 MiB source/output/workspace, 128 functions, 1,536 total blocks, 256 blocks per
function, 16 parameters/arguments, SSA index 2,047 and 8,192 instructions.

## Final local qualification

| Gate | Result |
|---|---|
| Source/contract/language source tests | 24/24, 17.912 seconds |
| Cold reconstruction | 10/10, 80.037 seconds |
| Native qualification inside that cold export | 699/699 |
| Language qualification | 910/910 |

The language run includes 824 independent scalar witnesses, 66 positive programs,
250 refusals and 136 arithmetic/shift traps per compiler. All original bulk,
integer, capacity, tail-call, object and source-identity checks remain included.
The loan extension contributes 23 Core-VM result/byte cases, 39 invalid Core
cases, six valid general-Core cases outside the fixed SSA profile and three
flat/object text comparisons per original and mutated successor compiler.

The original fixed point is B1 = B2 = B3:
`18c38a3fb6ab1bd47cff7cd04f380d99caa47fc00376e6879d29ab19ab6fe7a2`.
The modified fixed point is M2 = M3:
`5157ad0a1330c4ba192e51ec0e43d668531f3b0eb7bc8f8dc7697184713d9e4a`.
M1 differs from both, as required by the retained wrapper mutation experiment.

## Retained development finding

The first candidate passed its original finite cases, but review found an
uncovered refusal path: a loan result named `v8192` was rejected by `define`,
then execution continued into capability-state writing and the compiler trapped.
The final candidate immediately returns from `instruction` when `define` fails,
before any capability-state write. The exact maximum valid result `v2047` now
has a positive witness. Read and mutable results at 2,048, 8,192 and UINT64_MAX
are classified by the independent checker as valid general Core, then refused
transactionally by both final successor compilers. The pre-fix observation is
retained rather than relabeled as a passing run.

A separate finite matrix compared all 72 pairs of three-node graph permutations
for shared and exclusive loan chains, with the join placed before both incoming
blocks in source order. All 12 accepted and 60 rejected cases agreed with the
independent Core checker. This matrix used the pre-fix compiler, so it is a
development observation rather than final-head qualification.

## Evidence and integration scope

`evidence/reports.tar.gz.b64` contains a gzip-compressed tar archive of the exact
reports, logs, targeted pre-fix observation, matrix report and complete raw-file
index. Decode base64 before decompressing. Archive identities and member names
are in `evidence/evidence.json`. The indexed full raw archive contains 14,958
files and has SHA256
`6ec1251e0c930d0f2523994d682bc98ff9489630d87d5c78a596da3c9e5b962c`.
That gzip representation has 13,685,143 bytes. The same complete tar archive is
provided as `evidence/raw.tar.xz.b64`: after base64 decoding its 3,185,680 XZ bytes
have SHA256 `3a6ef3103d42d60dfb9b68094b53452e079e993bcb9cf1d3ada6107b1d7e50a9`.
Every archived member was read back from the XZ stream and rehashed against the
raw-file index. The separate small report bundle contains reports and index;
the XZ bundle preserves all indexed individual sources, native outputs and logs.

These results bind the local source manifest recorded in the reports. Integration
with Agent/NDU changes requires regenerating the complete source closure,
including `tools/hia_selfhost_loans.py` in the public release freeze inventory,
and rerunning exact-head CI. They do not change a selected public lock, live
service identity, caller-owned-buffer obligations, or the finite nature of the
machine execution evidence.
