# Observe dispatch starvation through actual poll readiness

**DRAFT / HOLD / DENY_ALL. Controlled local I/O, not a tunnel or target repair.**

This follows [#731](https://github.com/TrillionniumFoundation/Hepta/pull/731) at
exact `aec543003889f590ac6a63e2922b95d9c68dc675`. Every parent file, original
baseline, target source lock, runner, matrix, workflow and archived failed result
is preserved unchanged. The original [#716 target run](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42033735657)
still has 139 completed, 29 failed and 48 unattempted workloads out of 216.

## New evidence beyond the dispatch-only model

Two unnamed, nonblocking `AF_UNIX/SOCK_DGRAM` socketpairs provide real readable
and writable file descriptors. One represents the link-side descriptor and one
the TUN-side descriptor; neither is an actual TUN, UDP/IP socket, OpenVPN peer or
network interface. No privilege, namespace, route, listener, remote peer or
artifact executable is used.

The exact original event factory, Linux poll backend, event registration,
P2P flag generation, wait decoding and dispatcher run against those descriptors.
No readiness result is injected into `event_set_status`. The bounded driver
records the status returned by the actual kernel poll path before dispatch.

Both original and candidate receive exactly the same finite input: 64 identified
64-byte datagrams queued in each direction before execution. There is no producer
refill, thread scheduling dependency, rate tuning or outlier selection. Sinks are
drained after every dispatch with the same policy in all variants.

During a fixed **96-dispatch prefix**, the kernel-backed wait reports both input
directions readable on **48 turns**:

- Original dispatcher: **48 link reads/deliveries, zero TUN reads/deliveries**.
  Returned statuses repeat `[5, 12]`: both inputs readable, then TUN readable and
  TUN output writable. Selected actions repeat link-read/TUN-write.
- Unchanged #731 fairness candidate: **24 reads/deliveries in each direction**.
  Returned statuses repeat `[5, 12, 5, 3]`; selected actions alternate the two
  read/write pairs.
- Disabling only the candidate's tie-preference predicate restores the original
  **48/0** outcome. The explicit fairness requirement exits **23** on original
  and mutated versions, **0** on the candidate.
- After the fixed prefix, **every version eventually delivers all 64 datagrams
  in both directions**, then the actual empty wait returns timeout.

The result is finite, observed input starvation while both queues remain ready.
It is not infinite starvation: the finite original link queue eventually drains
and the TUN queue is then serviced. No elapsed-time or throughput claim is made.

## P2P uses the fast poll backend here, not the epoll banner

The target's `[EPOLL]` startup banner reports build support, not which backend
the client event set uses. In the pinned OpenVPN source:

1. [P2P initialization](https://github.com/OpenVPN/openvpn/blob/dc1f569087135894ac2703aeabd7a960ee9452d4/src/openvpn/init.c#L4538-L4546)
   calls `do_event_set_init`.
2. [That function](https://github.com/OpenVPN/openvpn/blob/dc1f569087135894ac2703aeabd7a960ee9452d4/src/openvpn/init.c#L4061-L4077)
   requests `EVENT_METHOD_FAST`.
3. [The original factory](https://github.com/OpenVPN/openvpn/blob/dc1f569087135894ac2703aeabd7a960ee9452d4/src/openvpn/event.c#L1125-L1197)
   routes FAST to the simple backend, which selects poll on Linux with poll
   available and no select-preference definition.

The archived `config.h` enables `HAVE_POLL_H`, `HAVE_EPOLL_CREATE` and
`HAVE_SYS_EPOLL_H`; its exact member hash and those lines are recorded in
`source.json`. The original platform macro expressions are preserved. The test
also checks the selected function pointer equals the actual upstream `po_wait`
and that the event set is fast. Epoll code is compiled but not selected or tested.

## Source identity and explicit adapters

All upstream inputs are pinned to OpenVPN 2.7.8 commit
`dc1f569087135894ac2703aeabd7a960ee9452d4`. `source.json` records immutable Git blob
identities, upstream URLs, exact source line ranges and local byte hashes.

- Complete, unmodified `event.c` and `event.h`, including their factory and poll
  implementation, are compiled under the compatibility headers in `shim/`.
- Exact source excerpts preserve `do_event_set_init`, `p2p_iow_flags`,
  `multi_io_process_flags`, `io_wait`, `socket_set`, `tun_set`, I/O constants and
  platform backend macros. Copyright preambles are retained for function files.
- The original and candidate `process_io` inputs are the unchanged sibling
  `../udp64_dispatch/` files from #731, with their original hashes checked.
- OpenVPN's original license notices and GPL text remain in the inherited
  [COPYING](../udp64_dispatch/COPYING) and
  [COPYRIGHT.GPL](../udp64_dispatch/COPYRIGHT.GPL). New harness/support code is
  GPL-2.0-only for this experiment.

The compatibility layer is deliberate and visible. It supplies synthetic
context/socket/TUN structures, ordinary allocation and descriptor helpers,
UDP-style no-residual registration, and no active DCO or management descriptor.
TLS, timers, shaping, fragmentation, real signal delivery and full application
initialization are absent. Unexpected event errors fail the test rather than
being treated as success. The actual P2P top-level infinite loop and
`pre_select` are **not** compiled; a bounded driver calls the preserved
wait/dispatch components.

Controlled callbacks perform actual nonblocking `recv` and `send`. Each direction
has fixed storage; pending output references that storage until successful send.
Sequence, direction, length and every payload byte are checked against independent
expectations on receipt and delivery. This catches duplicate, reordered,
truncated, misdirected or overwritten test payloads. These buffers are **not**
the actual OpenVPN buffer/context layout and do not qualify its ownership or
cryptographic implementation.

## Explicit native validation

```text
cd experiments/openvpn_hia_20261105/target_host/udp64_readiness
python -B -m unittest -v test_readiness.py
```

The suite requires actual Linux and GCC; missing dependencies fail rather than
skip. It compiles six binaries: original, candidate and disabled-tie mutation at
O0 and O3, with `-Wall -Wextra -Werror -Wno-unused-parameter`, UBSan and
nonrecovering diagnostics. Compilation is bounded to 20 seconds per binary and
each execution to five seconds. No binaries are published.

**Seven methods / 30 scenario executions pass** locally on Linux 6.18.57 x86-64,
GCC 14.2.0. This is a different kernel from the archived Azure target.

In addition to the three dual-ready variants, controls cover:

- Actual empty poll timeout and each input direction alone.
- Two simultaneous pending outputs: socket write retains priority, with no
  input read or pending-buffer overwrite.
- Actual AF_UNIX link-output backpressure: fill the send queue until EAGAIN,
  retain a pending output, and verify queued TUN input is not registered while
  that output is pending. Draining the blockers permits the old output first,
  then the queued next payload. The observed blocker count is host-dependent and
  not an acceptance constant. This is not callback send-EAGAIN after a reported
  writable event, and it does not cover real TUN backpressure.
- Two independent contexts plus a fresh zeroed synthetic context.

`LOCAL_VALIDATION.json` retains exact observed statuses/actions, expected negative
exit codes, compiler identity and source hashes. Independent review reran all
seven methods, verified all ten upstream inputs against the pinned GitHub
source, and confirmed all ten inherited #731 files remain byte-identical.
Separate temporary controls at O0/O3 reject a corrupted pending payload and a
mistakenly global turn preference at the intended assertions. Parent #731's
no-I/O model and immutable receipt audit are separate evidence, not silently
replaced.

## What remains open

This removes an important modeling assumption: dual readiness and output
writability now come from the kernel through the source-exact wait path rather
than assigned flags. It supports the dispatch-starvation mechanism. The actual
target lacked per-dispatch readiness evidence, so this still does **not** prove
the real UDP64 timeout's cause, exclude CPU/kernel/iperf interactions, or repair
the target.

No actual TUN, UDP/IP, HIA packet compiler, TLS, DCO path, application buffer
layout, context lifecycle, asynchronous callback failure, signal race or
timer/shaper/fragment behavior is qualified. Strict write priority remains;
general bounded-service fairness is not established. The candidate is still not
applied to the production OpenVPN build.

Any future integration needs a separately identified context/dispatch patch,
full-program validation, symmetric C/HIA candidate builds with the original
baseline retained, and a new complete target evaluation when authorized. No
workflow is changed or dispatched here; no merge, throughput advantage, target
acceptance, production grant or blocker closure is claimed.
