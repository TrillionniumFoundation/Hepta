# CI native side-effect observation budget repair

The initial CI run completed 201 tests with one failure: the ELF-constructor case expected SIGSYS but the native observer reached its three-second wall deadline first. All later side-effect cases passed. The artifact has no phase timing or scheduler telemetry; it does not establish a unique runner-delay cause.

Only the side-effect test module observation budget changes from 3 to 10 seconds, the existing observer maximum. The observer/compiler implementation, exact SIGSYS assertion, marker-absence check, timeout refusal and no-retry behavior remain unchanged. The budget includes isolated Python startup/imports, seccomp setup, dlopen/constructors and signal-exit observation.

`tests.log` records all four actual native tests passing with no skips. `result.json` records a separate real-Clang control: a constructor sleeps for 3.5 seconds before its forbidden write-open. At the old 3-second deadline the child is terminated and rejected as a timeout; at 10 seconds the actual syscall is reached and the child is rejected specifically with SIGSYS (-31). The file marker remains absent in both cases, and no function result is accepted. This demonstrates the timing distinction while retaining the security assertion; it does not assert that the CI runner executed this deliberate delay.

The exact C fixture and native artifact are retained. Compiler hashes before and after validation agree. The initial exploratory invocation without Clang on PATH skipped tests and was not counted as validation; the recorded run explicitly placed the actual Clang 20 directory on PATH. Full integration and GitHub CI are separate follow-up gates.
