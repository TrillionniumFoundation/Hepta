# Task/I/O observation repair: retained originals

The complete task/I/O qualification passed on local commit
`8c88308eb9b6a8acf612ae9e8f7d9a7d89f5a776`: all 10 planned cases, three
executions of each executable case, the native alias compile rejection, and
all 10 source rejection controls. The separate unit suite ran 12 tests with
zero skips, failures or errors. The original `44cb3257` CI failure remains a
failure in its complete archive and in the selected originals retained here.

The published commit
[`4ac39e626acd7f78e2f66708be741e78308b4e6a`](https://github.com/TrillionniumFoundation/Hepta/commit/4ac39e626acd7f78e2f66708be741e78308b4e6a)
has exactly the same Git tree as the tested local commit:
`99a2273d45a333a1a9cc87110742399e7413d512`. This local subgate result does not
establish the result of the separately running complete published CI.

## What failed and what changed

The original [CI job](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40439677114/job/121976747689)
recorded an abort in positive trial 2, the third execution. The assertion at
generated `positive.rs:1337` checked every saved descriptor immediately after
reactor shutdown and observed `left: 1`, `right: 0`. That statement included
the internal wake reader as well as user ports; the original diagnostic did
not name which descriptor or record the precise concurrent thread schedule.

The existing runtime contract allows a canceller's temporary strong wake
reference to retain the wake reader and fixed attachment charges until that
reference is destroyed. The worker's local shutdown still consumes its
resident operations and user endpoints immediately. The old fixture already
contained a deterministic control that expected a retained wake reader to
remain open, making its separate immediate-close observation inconsistent
with this documented boundary.

The repair changes the fixture, its test and its documentation. It checks
user descriptors immediately after local shutdown. It then acquires and
releases the owning group's state mutex before checking the wake reader.
The production notification closure destroys its temporary strong reference
before returning, while the state guard is still held. After the worker has
destroyed its own reactor reference, this fence crosses final notification
cleanup without making runtime destruction acquire group state.

The deterministic handoff now exercises that same fence: the controller
holds state and a strong wake reference while the worker closes its user
ports and releases its resident buffer. The controller observes the wake
reader open and fixed charges retained, releases the final reference under
state, verifies descriptor closure and all four I/O charges at zero, and
then allows the worker to cross the fence and finish. This fixture starts no
later socket-producing work before the relevant workers/controllers join.
The saved FD integers are observations inside that isolated process; they
are not a general descriptor identity mechanism.

Runtime source, the qualifier, C fault helper, performance protocols, 10
planned qualification cases, repeat requirements, five wrong-runtime
controls and their acceptance criteria remain unchanged. The captured
compiler SHA256 remains
`baa9c71bf65c590b23598635012989ac2f07242803b1a876b13a28eec2848bd7`.

## Actual execution denominators

| Record | Observed result |
| --- | --- |
| Original CI 44 task/I/O | 10 cases: 9 passed, positive failed; all 27 planned native attempts recorded; no case or trial omitted |
| Original CI native outcomes | 11 exit-zero processes, 10 aborts including the unexpected positive trial, and 6 expected wrong-runtime timeouts |
| Unmodified-runtime boundary control | Exit 0: wake reader open while the final canceller reference is held, then closed with all I/O charges returned |
| Deliberately premature close assertion | Exit -6 at the same controlled held-reference boundary; exact diagnostic contains `left: 1` and `right: 0` |
| Targeted unit suite | 12 tests, 16.528 seconds, `OK`; includes an additional native regression of that wrong observation |
| Fixed three-round qualification | All 10 cases passed; 9 executable cases × 3 = 27 actual attempts: 12 exit zero, 9 expected aborts, 6 expected timeouts |
| Native alias | Rejected by the actual Rust compiler with `E0499`; zero native executions, as planned |
| Invalid source controls | All 10 rejected |

Each fixed positive execution recorded 208 tracked allocations, 208 frees,
zero live buffers and 137 actual poll entries. Each retained 64
parent/child cancellation-failure races, 64 attachment/cancellation races,
64 readiness/cancellation races and 32 shared-byte admission races. The
original timeout controls still reached their required markers and timed
out; the budget, reservation and buffer mutants still failed their
distinct assertions. A successful negative control is not an omitted or
successful native execution.

The baseline counterexample's ten task/I/O input hashes match the failed
CI report exactly. Its native runtime is unmodified; only main selects the
held-reference fixture and the negative observation deliberately asserts
that the still-owned descriptor is closed. This establishes the observation
error and a reproducible counterexample. It does not reconstruct the
unrecorded thread interleaving of the CI failure.

## Retention and identity

`native-records.tar.xz.b64.part01` retains 143 files, 45,248,710 uncompressed
bytes, including both baseline native binaries, every fixed qualification
binary and C object, generated Rust/C, all actual stdout/stderr streams,
the fixed report, unit log and before/after source identities. It also
includes the original CI task/I/O report, generated positive source and
the third positive trial's original output streams. The complete original
CI ZIP remains sealed separately under `ci_prerequisites_20261026/full_44cb3257/`.

The single-thread XZ stream is 1,638,888 bytes, SHA256
`251bf019eb8db73330de4e0b2f20d455c7a73bdf9583e115b43ba182b98edcb1`;
the ASCII part is 2,185,185 bytes. No originals were edited to create the
archive. Files retain their modes; tar owners and timestamps are normalized.

Twelve fixed source/test/document files were checked against the exact local
Git commit at capture; their bytes and Git blob IDs are retained along with
the original fixture and the original base, local and published Git commit
objects. The complete compiler source tree and external compiler binaries
are identified by the repository/tool receipts rather than duplicated in
this small appendix. The before/after fixed input maps match. Independent
read-only reviews from two agents found no blocking lock-order, lifetime,
FD-observation or coverage issue; their input identities are retained.

Run the bounded, read-only data verifier with:

```sh
python3 evidence/task_io_observation_fix_20261027/verify_bundle.py
```

It checks archive members, original process byte links, selected source
identities, unchanged fixed inputs, actual case/repeat outcomes, raw metrics,
the original abort and the independent review's inputs. It does not extract
or execute archived native programs, invoke production qualification, or
remeasure performance. This evidence closes this observation defect within
the recorded task/I/O profile; `whole_project_blockers_closed` remains false.
