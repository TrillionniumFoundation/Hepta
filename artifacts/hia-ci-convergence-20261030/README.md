# Integrated CI repair and source-bound revalidation

The original integrated source (`71aff3e9`) and registration (`e223932a`) each
exposed three actual CI failures. `TRIAGE.json` records the six job URLs, exact
commits, causes and SHA-256 values. All six original decoded job logs are
retained alongside it. They are historical failures, not passing evidence for
the later source.

## Reviewed repairs

1. Regenerate the complete safety-contract registry from the unified source
   and update its independently reviewed canonical hash. Compare full canonical
   JSON bytes, including the instruction catalog; do not omit fields to evade
   tuple/list representation differences.
2. Resolve unittest module/class/method selectors to the actual longest source
   module. Retain all 118 integration selectors and 277 safety selectors.
3. Replace obsolete Z3 `4.13.4` assertions with the real `PINNED_Z3_VERSION`.
   Installed Z3 is `4.15.4`, wheel `4.15.4.0`; both assertions remain mandatory.
4. Execute native Agent controls with actual explicitly configured CI compilers.
   The closure workflow installs Rust 1.95.0. Tests call the unchanged evaluation
   worker with a test-only configuration; the production study protocol and
   runner are unchanged. Zero-skip gates remain mandatory.

The applied patch was locally committed as `97b445da` and published as
`000acac3c357430ca062957ba288756a8d89e147`. Both have exactly tree
`2beabb7f2fbea8f6cd6a57c943c3512e04787af7`; connector commit metadata differs.
`PUBLICATION_BINDING.json` binds all six changed files and the original local
records. The local test report correctly retains its actual base HEAD
`e223932a` plus the then-applied worktree patch, rather than pretending the
published commit existed when those tests ran.

## Actual local verification

`APPLIED_FOCUSED_RESULT.json` and `applied-focused-tests.log` record 65 planned
tests, 65 executions, zero failures/errors/skips/expected failures and about
4.925 seconds. The suite includes safety protocol, catalog/schema, resource
contracts, selected formal input validation and actual native Agent/Vec
controls. It does not replace the pinned-Lean qualification in the Core
evidence or the complete remote workflows.

`CI_TOOL_OVERRIDE_RESULT.json` retains a separate execution of the 18 native
controls with compiler paths different from the frozen study's development
paths. All pass without skips; the production protocol SHA is unchanged.
These 18 are a rerun of a subset, not 18 additional distinct tests.
`SOLVER_PIN_CHECK.json` records the actual solver/wheel and both workflow
assertions. Earlier sparse-fixture failures and a proposed canonical-container
comparison failure remain in their original logs and patch history.

## Second repair from actual remote failures

The `000acac3` run passed the six-outcome/application workflow and both native
host jobs, but two later gates exposed additional failures. Closure completed
174 unit tests with zero skips, then failed before Lean execution because the
bootstrap lacked Python `zstandard`. CRC passed 52 controls, then exhausted its
unchanged 120-second study budget at 121.031788701 seconds after attempting
1,640 of the planned 2,856 contexts. The exact original ZIPs and job logs are
retained here; the failed study remains unqualified.

Commit `3ecae1a92f6e77f14a0561fbd3a22595ebf1d09b` fixes the missing dependency
with `zstandard==0.25.0` and removes a specific redundant host-oracle operation.
The integer observation helper previously encoded and decoded a newly formed
canonical result for every CRC byte. The failed run had already made 7,937,024
such oracle calls; trace preparation took 84.326066569 seconds. Exact integer
values now pass the same u32 range check and return fresh containers directly.
The dictionary/trap paths, every oracle call, candidate bank, information
permissions, CRC protocol/runner, observation count and 120-second budget are
unchanged. No result cache or skipped oracle work was introduced.

`crc-oracle-diagnostic/RESULT.json` records the old/new development comparison:
16,384 calls have identical ordered arguments and output SHA, 23 value/refusal
cases agree, and alias and first-trap controls agree. Profiled development
times are not extrapolated into CI economics. The first sandbox-native test
failure is retained; normal host execution passes 31 finite-context/CRC tests
with zero skips. The existing eight bootstrap controls also pass, including
real small zstd decompression and bad-checksum refusal.

`SECOND_REPAIR_BINDING.json` records exact source/tree identities and these
limited local checks. The complete CRC study was not rerun locally. A new
source CI must independently execute the full unchanged gate. Original e223
Ring, NDU and Agent studies remain unchanged; this post-study helper repair
does not retroactively alter their source snapshots or results.

## Remote gates

`REMOTE_CI.json` records actual GitHub results for the tested repair commit,
with workflow/job URLs, exact head SHA and available executed test counts.
It must be read independently of the local focused reports. Subsequent
evidence/documentation commits are checked on their own PR head; a historical
green run is not relabeled as a run of a later commit.

The original repair launches these five workflows:

| Workflow | Run at `000acac3` |
| --- | --- |
| Six-outcome source/application gates | [41036215282](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41036215282) |
| Verified optimization and native NDU | [41036215329](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41036215329) |
| Intelligent assembly closure | [41036215455](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41036215455) |
| Finite CRC and static controls | [41036215289](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41036215289) |
| Native x86_64 / AArch64 hosts | [41036215326](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41036215326) |

Passing correctness/qualification workflows does not reverse the registered
negative Ring optimization, NDU contribution or Agent efficiency results.
No regression gate, solver pin, study result or acceptance threshold was
removed to obtain CI success.
