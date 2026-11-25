# Native dequeue clock and worker profile

The private HIABGQ03 / HIABGW02 pair captures the actual worker start timestamp in the original dequeue critical section. This is a queue/worker component qualification; the complete BackgroundOptimizer business handler, failure drain, public constructor and installed release remain separate gates.

## Preserved domains

HIABGQ01 and HIABGQ02 retain their complete prior operation sets, accepted inputs, rejection behavior and output fields. HIABGQ03 is a new private profile allowing only operation 2. The queue still admits at most eight outstanding actual Jobs and uses the same FIFO, worker identity, strong reference and condition protocol. Its mechanical bridge and packer are unchanged.

After removing the FIFO head and recording the actual active Job, while still holding the condition, HIA invokes CLOCK_MONOTONIC. It retries EINTR. Success supplies seconds and nanoseconds; a clock failure preserves the actual active Job and all ownership, releases the condition, and returns the existing error status with the raw failure. No fabricated timestamp replaces a failed clock.

The 128-byte HIABGQR1 reply keeps its original fields. For a real timed dequeue it additionally contains seconds at 88, nanoseconds at 96, raw clock result at 104 and attempted flag at 112. The extra fields remain zero for old profiles and a closed empty queue.

HIABGW02 only extends worker initialization (operation 0). It selects the new dequeue profile; all old worker operations still use HIABGW01. The fixed business callback receives HIABGWQ2 with the original Job, token and slot fields, plus seconds at 80, nanoseconds at 88, raw error at 96 and attempted flag at 104. The callback's public output remains 128 bytes. The worker saves the active Job before processing a clock failure so failure handling does not lose accepted ownership.

## Actual checks

The exact new images passed the original queue suite (9 groups, 5653 native queue calls, 3132 native value calls), original pthread worker suite (6 groups, 334 public calls), the original pthread error controls and both original native packer suites. All actual worker threads were joined.

The unchanged seven-group combined queue/actual-Job suite also passed: real strong references, eight accepted Jobs, condition serialization against worker dequeue and shutdown, transaction identity refusal, and every one of eight actual allocation rollback sites. The external allocation observer was rebuilt from the unchanged frozen QA INJECTOR after the earlier shared object could not be located; its new source and image hashes are recorded. It is not a product dependency.

Six new groups exercise 128 actual dequeues, eight actual pthread jobs blocked behind a held condition, clock EINTR followed by the real syscall, two raw syscall errors, and 31 malformed new-profile requests. The clock-effect controls drive the same HIA policy and real queue ownership; only the selected syscall result is controlled by the external observer.

Worker state 3 is the native business terminal publication followed by the mechanical return. Exact public thread-liveness observation at that boundary is a separate whole-worker integration obligation. These component results do not claim a complete public BackgroundOptimizer.
