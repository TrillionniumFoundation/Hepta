# UDP64 userspace stall: source-exact dispatch counterexample

**DRAFT / HOLD / DENY_ALL. No target repair or performance qualification.**

This additive investigation preserves the failed [#716 target run
42033735657](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42033735657)
at exact Hepta source `1a9deb8ea58b9091e7b9179cae87d9f93eef4c35` and
[artifact 13448779084](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42033735657/artifacts/13448779084).
Its ZIP SHA-256 is
`0c4121ab9ff0467f67986a89aeb858345a2f0edbda7e0d26a323ab27234a43ba`.
The original target remains failed. The dispatcher candidate below is **not
applied** to OpenVPN, the C/HIA builds, or the target runner.

## What the archived run establishes

`audit_receipts.py` reads the fixed ZIP as data only. It does not extract members,
import artifact modules, run binaries, access the network, or alter receipts.
`receipt-audit.json` is its deterministic output, including the full 216-workload
inventory and hashes of every actual measurement. Missing measurements are
explicitly unattempted only for the twelve original `planned` cases that have no
case receipt. No fabricated zeros or survivor-only inventory are used.

- 54 performance cases: 14 completed, 27 failed, one deadline interruption,
  twelve planned but unattempted.
- 216 workloads: 139 completed, 29 failed, 48 unattempted.
- All fourteen C-userspace and fourteen HIA-userspace UDP64 attempts fail.
  Client TUN transmit deltas are exactly 499 packets, with 749,221–777,560 drops.
  Every server-local receiver summary reports zero bytes. Reverse-direction
  reported loss is 72.80–74.75%; interrupted summaries are **not throughput
  measurements**.
- Those 28 measurements take 22.041–22.055 seconds, rather than the requested
  five seconds. Client process lifetimes are about 17 seconds, server lifetimes
  about 22.18 seconds including setup. Both have explicit timeout and SIGTERM
  receipts. Authenticated session identities remain unchanged.
- The client's final sender interval starts near five seconds and records zero
  new bytes through its forced termination. The preceding nonzero interval ends
  near four seconds: the archived client interval array omits the 4–5 second
  interval. Do not infer an exact stop time from that missing interval.
  Server reverse-sender intervals continue through approximately 22 seconds.
- All fourteen attempted DCO UDP64 measurements complete in 5.024–5.028 seconds
  with no client link transmit drops and both receiving directions present.
  This does not qualify the incomplete matrix or establish an HIA advantage.
- The separate 29th failed workload is final-case TCP interrupted by the global
  1,800-second budget. It is not another UDP64 timeout.

The timeout timing is intentional in [the exact controller, line
649](https://github.com/TrillionniumFoundation/Hepta/blob/1a9deb8ea58b9091e7b9179cae87d9f93eef4c35/experiments/openvpn_hia_20261105/target_host/run_matrix.py#L649):
wait `seconds + 12` for the client, then five seconds for the server. Logs are
regular files, not unconsumed stdout pipes. Merely extending this budget or
lowering the offered packet rate would not demonstrate a repair.

## Concrete upstream mechanism, not complete target causal proof

The target builds the unmodified official OpenVPN 2.7.8 source at
`dc1f569087135894ac2703aeabd7a960ee9452d4`, with the release archive checked against
`c070d1d2440b5a6fca6c2c68645c98cd492116ac36ef4f0946177115532c8e36`.

[Original `process_io`, forward.c lines 2271–2319](https://github.com/OpenVPN/openvpn/blob/dc1f569087135894ac2703aeabd7a960ee9452d4/src/openvpn/forward.c#L2271-L2319)
uses this exclusive priority order:

1. Socket write.
2. TUN write.
3. Socket read.
4. TUN read.
5. DCO event.

If inbound socket data is continually readable, TUN read can be perpetually
deferred. A socket read produces a pending TUN write; that write is serviced
first; the next socket read again wins over TUN read. The [P2P main
loop](https://github.com/OpenVPN/openvpn/blob/dc1f569087135894ac2703aeabd7a960ee9452d4/src/openvpn/openvpn.c#L57-L90)
calls this dispatch, and [flag selection](https://github.com/OpenVPN/openvpn/blob/dc1f569087135894ac2703aeabd7a960ee9452d4/src/openvpn/forward.c#L2039-L2140)
permits exactly this cycle.

That mechanism is consistent with receive-side load saturating both userspace
arms, filling the 500-entry client TUN queue, and starving outgoing data and
iperf control. The server continues sending until forcibly stopped. The exact
499-packet delta is consistent with a full queue after its preexisting packet,
but neither queue occupancy nor the time at which those packets drained was
recorded. The archived run has no dispatch readiness trace. CPU scheduling,
kernel queueing and iperf behavior therefore remain unseparated causes. The
offline result proves the conditional dispatch counterexample, **not that this
was the sole or actual cause of every target timeout**.

## Safe offline native reproduction and isolated candidate

`upstream_process_io.c` contains the original copyright/license preamble and the
exact final function from `forward.c`. `source.json` binds its line range,
upstream full-file Git blob/SHA-256, and exact excerpt hash. OpenVPN's original
`COPYING` and `COPYRIGHT.GPL` are included. The source came from the pinned
official repository, not the workflow artifact.

`candidate_process_io.c` adds a context-local, initially false read-direction
preference. When both inputs are ready, it chooses the direction not read last.
Writes retain their original priority and each call still performs at most one
data action. No shared-buffer double-processing is introduced into the model.
The preference field is supplied by a **stub context**, not by a modified actual
OpenVPN context layout. This file is a dispatch-only research candidate, not an
integration patch.

`dispatch_harness.c` supplies no-I/O callbacks and the original event-bit values.
The continuous-readiness trace models the P2P pending-output suppression with no
shaping or fragment residual effects. It neither opens sockets nor invokes an
OpenVPN binary. For each original/candidate build:

- 512 controls: 128 combinations of seven selected event bits × two preference
  states × two pre-existing signal states. These are not every real context or
  callback outcome.
- Pending-write priority, management processing, existing signal guards, one
  selected data action and unchanged event-status input are checked.
- Two contexts and a freshly zeroed context check that turn state is independent
  and resettable in the stub model.
- A 10,000-dispatch continuous-readiness trace gives the original **5,000 socket
  reads, 5,000 TUN writes, zero TUN reads and zero socket writes**. Requiring
  fairness returns expected nonzero exit 23 on both optimization levels.
- The candidate gives **2,500 of each read/write action** in that same trace.

Run only this explicit suite:

```text
cd experiments/openvpn_hia_20261105/target_host/udp64_dispatch
python -B -m unittest -v test_dispatch.py
python -B audit_receipts.py /path/to/hepta-716-13448779084.zip
```

Four unittest methods pass with GCC 14.2.0 at **O0 and O3**, UBSan enabled and
nonrecovering. That compiles and runs four tiny test binaries; no production
application, live tunnel, target workflow or artifact binary is executed.
The audit initially assumed unattempted workloads had measurement files and
correctly stopped at the first absent member. It was corrected to preserve the
actual `planned` cases with absent receipts. The original archive was never
changed.

## Unqualified boundaries and next evidence

Stubs do not model crypto, real buffer lifetimes, event waits, OS scheduling,
actual context storage/reset, timers, shapers, fragments, callback failures,
signals raised inside callbacks or kernel/DCO interactions. Pending writes
retain strict priority; this is not a proof of general scheduling fairness.
The production source, pristine C baseline, HIA replacement boundary, source
locks, controller budget, matrix size, offered rate and every acceptance gate
are unchanged. No workflow is added or dispatched.

A future authorized target investigation must separately retain the original
arms, bind any actual context-layout/dispatch patch to new source identities,
apply that patch symmetrically to C and HIA candidate arms, and collect evidence
that separates readiness starvation from other bottlenecks. Original failed
results cannot be replaced by candidate results. A new complete target matrix
and independent exact-source qualification would still be required. This PR
does not close #716, P0–P7, throughput, security, or production acceptance.
