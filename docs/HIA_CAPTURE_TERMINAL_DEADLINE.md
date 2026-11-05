# Terminal observations and the existing diagnostic deadline

The bounded PTY collector must observe successful natural process termination
and output completion within its process deadline. A read or `waitid` call that
starts before the deadline may return after it. That late observation cannot
turn into `diagnostic_completed` merely because the child exited with zero.

The pre-fix implementation admitted precisely that trace in all three targets:
`LinearTransport`, `CertPart02`, and `SevenCertificatePart02`. A real Python
child exited naturally; the controlled observation clock crossed the one-second
test deadline at the first post-EIO `waitid`. Every target reported completed
at roughly two seconds. This is a regression of collector timing semantics,
not a Lean proof, a real-time scheduler theorem, or a change to a proof budget.

The collector now checks the active deadline after every `waitid` and captured
read, including the first EIO branch, ordinary EOF, and a nonempty late read.
Bytes observed by a late read consume the existing raw quota but are not written
as accepted output. The existing cleanup budget still owns draining and reaping
after cleanup begins. The process deadline, cleanup deadline, combined raw byte
limit, metadata limit, and proof budgets are unchanged. Independent review then
reproduced the same omission after the final real `wait`: all three targets
accepted a reap observation after the cleanup deadline. The collector now also
checks cleanup read/exit/reap observations against the original cleanup
deadline, records a late successful reap as reaped but nonaccepting, and never
renews cleanup after an exception. `cleanup_deadline_exceeded` and
`cleanup_incomplete` make that distinction explicit.

All three supported PTY modes also use the existing bounded pending-EIO rule.
A slave can close before `waitid(WNOWAIT)` exposes the leader's natural exit.
That race requires both a subsequent natural exit observation and a confirming
empty read within the original nonrenewable grace interval. A persistently live
child, reopened slave, new bytes, EAGAIN, timeout, interruption, or cleanup
failure remains nonaccepting. The leader is not reaped before group signalling,
so cleanup retains its original process identity.

The original legacy-only test asserted immediate failure even when the actual
child had naturally exited and only its exit visibility was delayed. That one
test is replaced with positive bounded-confirmation and negative live-child
controls for both legacy modes; its test count is retained. Eight new tests cover
the terminal observation deadline, actual stderr FD ownership, discarded late
bytes, natural exit confirmation, and refusal of live closed streams across all
three targets, including cleanup EOF, late data, late reap and nonrenewal. They
are an additional CI job; the historical 207 and 705 test
inventories remain unchanged.

## Reproduction

Use the same Python environment as the composition and run:

```sh
python -B -m unittest -v tests.test_core_capture_terminal_deadline \
  tests.test_core_syntax_diagnostic_capture \
  tests.test_core_seven_certificate_pending_eio
```

The fixtures execute real Python child processes and PTYs. The scheduling
boundary is injected in the observer clock; no Lean child or actual two-second
sleep is needed. The test adapter explicitly distinguishes the child stderr
descriptor from `Popen`'s private exec-error pipe.

This change does not transfer prior proof or composition acceptance to the new
source tree. The full qualifier and independent replay must identify the new
committed source. Every result continues to use `DENY_ALL` and carries no safety
certificate.
