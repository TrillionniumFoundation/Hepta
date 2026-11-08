# Diagnostic marker checkpoint synchronization fix

## Result and scope

The exact 42-test `execution` inventory from initialization research run
42524213946 passes locally after a change to
`tests/test_core_syntax_diagnostic_capture.py` only. The production collector is
byte-identical to source commit `14b2c03c35f0d8d4f3b77133cf3deecde92a2f40`.
No new GitHub CI run, publication, deployment, Lean admission, or native target
execution is claimed here. The local Python version is 3.12.14; the retained CI
used 3.12.16. Both final execution suites use Z3 4.15.4. Capture tests explicitly
mock the supported platform identity; that mock does not describe this host.

## Original failure and controlled reproduction

Job 128864062031 failed exactly one of 42 tests: the durable marker test expected
one event and observed none. The original 60,279-byte job log is retained without
editing. Its SHA256 is
`880a761abbf96816a574bad31e9f85f24ab10b1cd4e3ef535469ab21a29bcd62`.

The test put a real Python child startup, a marker write and parent collection
under a 150 ms deadline. The collector starts that deadline before creating and
syncing log files, configuring the PTY and starting the child. Its read path checks
the active deadline before interpreting the bytes. This is correct production
behavior, but the test assumed that its marker would necessarily arrive first.

The original unmodified test passes on this host without injected delay. With a
recorded 200 ms sleep before the original child code, it fails at the same
`len(events) == 1` assertion: zero markers, a real diagnostic timeout, SIGKILL and
a reaped leader. The exact original CI schedule was not observed; the controlled
case demonstrates the test's timing assumption rather than claiming to reconstruct
that schedule. Both child scripts, original test/capture bytes, raw streams,
event records, result metadata and failure traceback are retained.

## Change

The existing test now uses a test-local logical clock. Input still comes through
a real PTY from the fake Python child, and the default `MarkerObserver` still
parses it. The original raw and event append implementations execute their real
`fsync` calls. Only after both calls return, and reads of the stored raw bytes and
event file confirm the checkpoint, does the logical clock reach the unchanged
0.15-second configured process deadline. From that point, cleanup follows real
monotonic elapsed time.

If a marker never appears, the already existing one-second child-fixture budget
acts as a readiness guard and triggers the timeout. The test still fails for the
missing marker; it cannot manufacture an event or wait indefinitely. The original
real-time deadline tests remain unchanged. Production limits remain 60 seconds
for the process and 2 seconds for cleanup, with the same output and metadata caps.

All original marker, offset, last-marker, timeout and no-raw-copy assertions remain.
Additional assertions check actual sync calls, stored bytes, stored marker count,
unchanged configured timeout, leader reap, group kill and cleanup deadline.

## Validation and retained observations

- The 22 capture tests pass, with no skipped tests.
- The original 42 execution test IDs match the CI log exactly, and all 42 pass
  with no failures, errors or skips in 40.053 seconds.
- The identical delayed-child script that failed before now passes; a separate
  200 ms delay in the first start-record sync also passes.
- A child that never writes a marker still fails the same assertion after
  1.009 seconds, reports timeout and is killed/reaped without exceeding cleanup.

Initial local attempts to assemble the narrow checkout also remain in this
archive. One lacked a transitive proposer module; two lacked source-identity
documents, so the related class setup failed. Those inputs were fetched from
the same exact commit and verified before the final complete run. They are not
counted as successful runs or discarded as noise.

`exact-source-inputs-final.json` binds 31 exact Git files and 212 copied Hepta
sources checked against the exact commit's support manifest. `fix.patch`, the
original and fixed source snapshots, test scripts, stdout/stderr/events and all
test logs permit independent inspection. The final summary distinguishes these
local observations from future integration CI results.
