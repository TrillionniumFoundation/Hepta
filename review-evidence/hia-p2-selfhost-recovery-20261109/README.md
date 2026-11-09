# P2 original source recovery and fresh qualification

The source tree in recovery commit `136ff136b206152d3ee94c0da256d6e2c4d11bda`
is exactly `68f65d26db13db6f2c3f94490b8d5bc881105f71`, the tree of original local
commit `459d92be7248a4d268748ef9c77e13151dc3da87`. The recovery commit has new
metadata and parentage. This is a byte-preserving recovery of inspected original
files, not a reconstruction from a conversation summary.

`original-commits.bundle` retains the original, separate commits:

1. `225c47778285ca01346c9e639fc67d5cf78e0167`: compact short-circuit CFG while
   preserving evaluation order, partial checked-shift behavior and join values.
2. `459d92be7248a4d268748ef9c77e13151dc3da87`: extend the bounded native compiler
   to one through three unsigned/bool internal scalar results and matching calls,
   including CFG, ordered self-tail calls and resource-input combinations.

The public `f0(readbuf,mutbuf,mutbuf)->u32` ABI, the existing private result
frame, capacity limits, child wall limits and 180-second cold limit are unchanged.
This adds language coverage. It does not extend the scalar proof service or
establish universal compiler correctness.

## Evidence boundary

The executor interruption removed the original `/tmp/hia-bootstrap-728f`
evidence directory. The previously observed 269/269 development checks are
historical observations whose raw report is unavailable. They are not accepted
as fresh qualification of this remote head. Interrupted cold and language
terminal results remain unknown. Earlier CFG cold timeout and ordinary
qualification failures remain failures; their historical archive identity is
recorded in the manifest without claiming the archive was recovered.

The dedicated read-only Actions workflow checks this pull request's exact head.
It verifies the original bundle and all recovered source hashes, regenerates the
assembly and inventory without accepting a diff, checks the source contract,
and runs all selected source tests with no skips. Its sequential native gates
run fixed-budget cold replay, ordinary full selfhost qualification, and full
language coverage. Each job uploads its own report, stdout/stderr and native
evidence even on failure. Workflow conclusions, not this README, determine
whether those new gates passed.

## Scope retained for review

The tuple matrix contains 43 input cases across 13 distinct programs: all six
supported scalar types, mixed triples, forward/backward calls, branches,
loop-carried results, ordered self-tail calls, borrowed input and consumed owned
input. Tuple checks compare complete output words; negative cases distinguish
invalid Core from valid general Core outside the bounded profile.

Signed types, empty/unit returns, returned owners/loans, arbitrary identifiers,
general module graphs/linking and full mechanical refinement remain open.
Release locks, online selection and production adoption are unchanged.
