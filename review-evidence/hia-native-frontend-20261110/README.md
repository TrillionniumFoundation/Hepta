# HIA native frontend continuation: exact-source evidence

This directory records actual source checks and failed cold qualifications. It
does not contain a passing qualification, a production activation, or permission
to retire the old implementation.

## Source subjects

| Subject | Source identity | Observed result |
| --- | --- | --- |
| Initial frozen source | Local `049afb8bf8191f0e90a1aa5f71b072cb1f9c3cfc`; published `f142ab4ef99cde30128bfced0f3d6299fc373b43`; both tree `e97eab65ab6dffba156a0340b691a8a993dbb728` | Cold FAIL at 180.204743498 seconds; 28/38 phases completed, zero recorded phase exceptions, owned child cleanup complete |
| Published source-job execution | `f142ab4ef99cde30128bfced0f3d6299fc373b43` | All three original CI source-job shell blocks ran locally; history recovery and regeneration passed; 121 tests passed in 279.678 seconds, with no errors, failures or skips; source remained clean |
| Loader and reference optimizations | `637d34d9e8164b752f5b6b6fe2bad4802274abc6`; tree `4b65ca5f59c7eff777062f3782778206bef2809b` | Cold FAIL at 180.248779364 seconds; 26/38 phases completed, zero recorded phase exceptions, owned child cleanup complete |

The local and server commits for the first subject differ in commit metadata,
not source bytes. The later optimization subject changes five files. A source
test pass does not supersede either cold failure. A fixed point reached before
the deadline does not establish completion of all required phases.

## Retained evidence

`manifest.json` binds every listed file by length and SHA-256. The static audit
is complete and gzip-compressed. Its ledger remains three partial and five open
components, with `whole_stack_rewritten_in_hia=false` and retirement ineligible.

`frozen-049afb8b-cold-receipts.tar.zst` includes all 19,849 textual receipts,
logs, witnesses and source-export files from the first frozen cold attempt.
Its internal `review-file-inventory.json` lists the exact hashes and lengths of
all 30,182 original evidence files, including 10,333 binary inputs, outputs,
objects and executable images that are not embedded in this review archive.
Those binary files remain in the original local evidence directory. The archive
is an explicitly scoped receipt package, not a complete binary-artifact export.

The separate source-job archive includes every file produced by that local job.
The extracted shell runner and complete log make the run scope reviewable. The
later cold report and phase index are preserved separately, so their different
source identity cannot be mistaken for the first attempt.

## Optimization controls

The final loader changes preserve all non-timing receipt fields and full output
bytes across 24 old/new pairs, each executed in fresh children. The tests cover
flat and ELF calls, poisoned workspace, actual SIGILL before and after writes,
zero capacity, source mutation and invalid requests. String-only path validation
prevents `open()` from treating an integer request field as a file descriptor.

All 106 names VM cases, 40 refusal/profile-boundary entries and both complete
alpha-renamed compiler sources remain exactly equal to the earlier reference
payload. The final canonical payload SHA-256 is
`6000d0393b692d4629b8f82a1ae51a3f220a3571db014fb4e4ff8db960b096fd`.
The full names module passed 12 tests. Observed verification records preserve
the identities and order of all 106 VM instances and all 150 direct assembly
checks in the independent reference.

Each of the three rename stages still performs complete verification, bounded
text parsing and canonical round-trip comparison. Negative controls retain
intermediate schema, CFG and loan failures and a case where an overlong
intermediate text would become short enough after a later rename. No verified
program cache, worker reuse, witness removal or budget increase was introduced.

The timing comparison separates local optimization effects from whole-gate
outcomes. All 17 reference payload hashes and all six compiler generation image
hashes are unchanged between the two frozen cold attempts. Several unchanged
references and native images ran slower in the later attempt; existing wall
observations cannot distinguish CPU contention, frequency changes and container
scheduling. Neither timing diagnosis changes the recorded FAIL result.

## Other limits and work in progress

The environment summary records actual tool versions and smoke observations.
GDB inferior execution and default LeakSanitizer execution encounter the host's
ptrace restriction. No debugger or sanitizer was hidden to convert that
restriction into a skipped or passing check.

One freeze-check invocation used a nonexistent unittest module name. Its error
log is retained alongside the corrected invocation, which passed 23 tests.

The complete repository regression was subsequently started on a detached clone
of public commit `637d34d9e8164b752f5b6b6fe2bad4802274abc6`, with all 7,860
discovered tests. It was still running when this evidence package was prepared;
no completion or qualification result is claimed here. The complete program
parser and module semantics engine are separate ongoing source work and are
not attributed to either frozen subject above.
