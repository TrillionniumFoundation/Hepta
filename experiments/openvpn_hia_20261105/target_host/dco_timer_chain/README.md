# Controlled OpenVPN DCO promotion timer chain

**Draft / HOLD / DENY_ALL. Diagnostic evidence, not a target repair.**

This continues #730 at corrected head
`6a33f048641a5bcc92ea509933c2b91ddd230545`. It executes more of the actual
timer-to-DCO decision path while retaining explicit clock, protocol and kernel
mocks. It does not run the full OpenVPN event loop, a TLS handshake, an OS event
wait, TUN, DCO, or any target-artifact executable.

## New result

With an authenticated generated new key eligible at t=105, an old mature key,
and no intervening callback, the unchanged `check_tls` chain advertises its
next timeout at t=110. The 15-second refresh and 2-second action horizon do not
create a t=105 callback. The kernel mock continues using the old key even
though the actual selection function would choose the new key at t=105.

An isolated hook after `interval_schedule_wakeup` adds the pending selection
deadline. The candidate advertises t=105, and the actual upstream
`dco_update_keys` performs the mocked swap then. `interval_test` is false at
this callback: the already-existing unconditional DCO check is what services
the promotion, not another TLS state-machine pass.

The original is deliberately serviced by an unrelated readiness event at
t=106 and swaps then. **This timestamp is a supplied test event, not a measured
target delay.** We do not invoke a fictitious quiescent protocol callback at
t=110, when real renegotiation would begin. A separate timely external callback
at t=105 masks the absent dedicated timer in both variants. Thus this establishes
a conditional missing-deadline counterexample, not the sole cause of the
original target's approximately ten-second promotion delay.

## Source and extraction

Official source is fixed at OpenVPN
`dc1f569087135894ac2703aeabd7a960ee9452d4`. Seven required files are independently
checked against both canonical SHA-256 and Git blob identity before compilation:
`ssl.c`, `dco.c`, `forward.c`, `ssl_common.h`, `interval.c`, `interval.h`, and
`otime.h`. `run_timer_chain.py` contains every expected identity and reports
them with compiler and generated-C hashes.

Fifteen complete function definitions are extracted unchanged:

- Key state: `get_key_scan`, `tls_select_encryption_key`,
  `auth_deferred_expire_window`, `dco_get_secondary_key`, `dco_update_keys`.
- Timers: `compute_earliest_wakeup`, `interval_earliest_wakeup`, `interval_init`,
  `interval_test`, `interval_schedule_wakeup`, `interval_future_trigger`,
  `interval_action`.
- Caller: `context_reschedule_sec`, `check_dco_key_status`, `check_tls`.

The final scheduler fragment from `tls_process` is also extracted unchanged.
It is placed inside an explicitly named protocol callback stub. Neither the
rest of `tls_process` nor `tls_multi_process` is executed. The candidate alone
adds a guarded call inside the extracted `check_tls` and a scheduling helper.
This changes only the generated mock translation unit, never an upstream file.

Source references:

- [Caller and unconditional DCO check](https://github.com/OpenVPN/openvpn/blob/dc1f569087135894ac2703aeabd7a960ee9452d4/src/openvpn/forward.c#L131-L236)
- [Interval scheduling](https://github.com/OpenVPN/openvpn/blob/dc1f569087135894ac2703aeabd7a960ee9452d4/src/openvpn/interval.h#L41-L128)
- [DCO update and error paths](https://github.com/OpenVPN/openvpn/blob/dc1f569087135894ac2703aeabd7a960ee9452d4/src/openvpn/dco.c#L108-L249)
- [Timer calculation](https://github.com/OpenVPN/openvpn/blob/dc1f569087135894ac2703aeabd7a960ee9452d4/src/openvpn/ssl.c#L3168-L3189)
- [Generation after timer processing](https://github.com/OpenVPN/openvpn/blob/dc1f569087135894ac2703aeabd7a960ee9452d4/src/openvpn/ssl.c#L3399-L3430)

The #730 initial newline-modified input mistake is not reused. All seven local
canonical source byte identities were verified independently against official
GitHub base64 responses. Adding a newline separately to each file is rejected
before even invoking the supplied compiler.

## Fixture assumptions and controls

`preamble.c` contains partial mock structures, logging and kernel callbacks.
They are not OpenVPN's actual ABI/layout. Constants used by these paths match
upstream, including FALSE=0, DEFERRED=1, TRUE=2 authentication states, S_ACTIVE=7,
S_GENERATED_KEYS=8, 15-second refresh, and 2-second horizon.

The observed short test profile uses renegotiation=10 seconds and handshake=60
seconds. The main fixture explicitly places pre-start, establishment and
installation in the same second t=100. The extracted expiry helper computes
100 + min(60, 10/2) = 105. Real authentication expiry starts at pre-start, not
installation. Empty reliable queues, cleared `must_negotiate`, and no retirement
inside the tested interval are declared assumptions.

Controls cover:

- Earlier independent timeout, reliable-send and negotiation deadlines.
- Timely external callback despite `interval_test` returning false.
- No old key, unauthenticated or deferred new key, disabled DCO and missing peer.
- Failed kernel swap and inconsistent installed state retain SIGUSR1 signaling.
- No authenticated key causes actual DCO-update logic to request key removal.
- A separately stubbed S_ACTIVE to S_GENERATED_KEYS transition after the timer
  calculation preserves the already-established timestamp. The later hook sees
  the new deadline that a timer-only insertion before generation could miss.
- Already-mature and repeated same-time calls do not schedule a past deadline
  or perform a second successful swap in these fixtures.

Review corrected two initial fixture mistakes before the final runs: the TRUE
enum value and the reachable state/timestamp before generation. No old fixture
result is claimed as the final qualification.

## Reproduce

Provide canonical files named as above in an existing local source directory:

```sh
python -B run_timer_chain.py /path/to/openvpn/src/openvpn
python -B test_inputs_and_mutation.py /path/to/openvpn/src/openvpn
```

GCC 14.2.0 at O0 and O3 with UBSan and nonrecovering undefined-behavior checks: **42 original and 43 candidate assertions pass per
optimization level**. The separate punctuality requirement intentionally returns
**RED exit 23 on original**, **0 on candidate**. It is not relabeled a passing
original deadline. `local-results.json` records the actual local outputs.

A separate read-only CI job fetches the same commit-pinned canonical files and
runs only these bounded checks. Hosted outcomes must be read for the exact
head; local results are not hosted passes.

Seven modified-source inputs are rejected before compiler execution. Disabling
only the candidate hook restores RED 23 at O0/O3. This checks that the deadline
result depends on the intervention rather than just the mocked fixture.

## Remaining boundary

The OS event wait, readiness, coarse-timer execution, full TLS/reliable protocol,
new cryptographic key generation, real kernel operations, packet races,
multi-client behavior and actual target callback history remain untested.
SIGUSR1 is recorded by a mock, not delivered to a process. Kernel slots are
integers, not cryptographic objects. No general event-loop absence of spinning,
security property, throughput gain or production fix follows from these tests.

Original #716 run and archive remain failed and unchanged. No source-lock,
official baseline, target build, matrix plan, observer, or acceptance-gate
replacement. No live-target dispatch, privilege, merge or deployment. A reviewed
full integration and new authorized target execution remain required.
