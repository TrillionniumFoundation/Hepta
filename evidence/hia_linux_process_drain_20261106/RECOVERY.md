# Linux command lifecycle: recovered implementation and evidence boundary

A command leader can exit while a descendant in its process group keeps running
and writing the same stdout/stderr files. The old Linux campaign runner reaped
only the leader after SIGTERM. This made timeout cleanup incomplete; the same
problem existed on cancellation and after a nominal leader exit of zero.

## Recovered, locally exercised change

[Recovered implementation commit](https://github.com/TrillionniumFoundation/Hepta/commit/8ef5dc680c957349be0db3eefa71ad92171c52b0)
contains the two files recovered byte-for-byte from the last tested local
version. Their SHA-256 identities match the identities printed by the original
test command before the execution environment disconnected:

| File | SHA-256 |
| --- | --- |
| tools/qualify_hia_linux_baseline.py | 65b654623c6d2b837163959eb6e4fea0859dc60ae3031dc88c196c76b0d44064 |
| tests/test_hia_linux_baseline.py | 813798e94be941369dabbd53304c94f0a00fd739c55de28f4c44814b347dff3f |

The three real subprocess counterexamples create an owned session and a child
that ignores SIGTERM. A separate-session sentinel must remain alive. The
fixtures use a scoped Linux child-subreaper and reap their own orphan children.
They test timeout, cancellation and normal leader exit with a still-active
writer. The tests check stable final stream hashes and preserve the original
exit code or raised exception.

Observed test-first result on the original #765 runner: **20 tests, 3 failures,
0 errors, 0 skips**. Observed result after the group cleanup change: **20 tests,
0 failures, 0 errors, 0 skips**, with a reported unittest duration of 1.522 seconds.
The original raw stdout/stderr files were written locally but became
unavailable with the executor. [OBSERVED_TEST_RESULTS.json](OBSERVED_TEST_RESULTS.json)
is an explicit transcription of the observed tool output, not a reconstructed
raw execution log.

## Additional consumer changes: UNVERIFIED

The subsequent source changes address a separate consequence of preserving the
leader exit code: callers using `check=False` must not treat exit zero as PASS
when an incomplete process group, interruption or undrained cleanup is already
recorded. The baseline and paired-system preflight/boot paths and the independent
evidence contract now reject those explicit failures.

Historical receipts lacking new lifecycle fields keep their historical scope.
The implementation does not add a claim that their process groups were
observed to drain.

Four additional test methods cover an otherwise complete 14-check guest serial
stream, legacy receipts, paired-stock admission, and build/preflight/boot
contract promotion. These changes were authored after the executor became
unavailable and **have not been executed in this recovery step**. The final
source needs a fresh test run; the earlier 20/20 result does not qualify it.

## Boundaries

Cleanup is limited to the session/process group created by this runner. It does
not contain a descendant deliberately escaping into a new session. The fix and
its unit tests establish no Linux build, guest boot, complete HIA kernel rewrite,
system throughput, memory result or NDU benefit. No production activation is
included.
