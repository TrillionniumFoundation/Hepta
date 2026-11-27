# Natural terminal readbacks: late lifetime and current public dispatch

This is an append-only readback of the two jobs that were still running when
commit 1a7dde9fded8a2112cbaabc15cc62e72358de41d was published. Earlier failed
observations and their original records are retained without changing their
results. The original Source qualification suite has **not** passed.

## Native post-write observation

Job `1a21eba748d-ffbe-5652` naturally completed with exit 0, durable complete
stdout/stderr, no cancellation and no timeout. The result is a completed
**development diagnosis**, not a native qualification. Its original full report
is 60,255 bytes, SHA256
`591b2aad590521a0dba2435725e8b6a365c48c50fb80a45f549c911a6f70878a`.

The development C observer writes the original late-event bytes first and then
captures the Python stack. Its original source, build invocation and compile
warnings are preserved. The C library is not a release component or a member of
native source authority. The Python observer's physical source was unchanged.

Both lanes executed all 15,830 business observations. Each reproduced its own
previous complete business and late bytes. The eight late differences between
the two lanes therefore remain actual counterexamples, rather than disappearing
as a side effect of the observer.

The stacks locate the delayed finalizers in different later cases. In the
original lane, finalizers for `generator_protocol.throw-instance.outer0/outer1`
run while recording another exception in
`generator_protocol.throw-class.outer1`; the active exception is that later
OuterError. In the unselected candidate, the same finalizers run inside
`json.loads` / `support.pairs` while reading the expected row for
`generator_protocol.retained-body-traceback.outer1`; its active exception is
null. These are observed stack locations, not changes to or normalization of the
late records.

A separate candidate moves business comparison into the parent after natural
process exit for both lanes. It must construct new authority against its actual
new source, preserve every full raw and late byte, and pass within the original
outer 1800 + 3 second bound. That candidate is still pending at this checkpoint.

## Current public service dispatch

Job `1a21ec13f42-ffbe-5661` naturally completed with exit 0, complete durable
output, no cancellation and no timeout. It built the current native word
component from the physically captured source with the explicitly identified
development B3 image. It then ran three independent owned processes.

| Lane | Public init cases | Current program cases | Actual owned-child seconds |
| --- | ---: | ---: | ---: |
| Unselected | 8 | 12 | 0.1940432109986432 |
| VM | 8 | 12 | 0.942218697979115 |
| Native | 8 | 12 | 0.2384600860241335 |

Each process used its unchanged 60 + 3 second bound and passed the independent
current-domain reader. Raw child reports and owned receipts are included, along
with before/after physical source pins. No historical compatibility body was
used as a replacement for the current `service_options`, `_program`,
`_admit_retained_program` or `native_candidate_import` semantics.

The whole observation is 67,057 bytes, SHA256
`97088cb5838a0d64031c72e8b32d37b1b2b2e817aaecd016ef19968a3ecc9ab0`.
Its status is
`PASS_CURRENT_PUBLIC_8_INIT_12_PROGRAM_THREE_OWNED_LANES_ONLY`.
It explicitly leaves matching-source cold qualification, the original Source
suite, and the whole native stack unqualified.

## Custody

Observation, stack, compiler diagnostics, child reports and owned receipts are
the complete UTF-8 bytes read from their physical output files. The separate
`job-terminal-readback.json` files encode the authoritative H terminal readback
objects; they are not represented as original child-generated receipts. All
new files other than this index are pinned in
`terminal-readback-file-pins.json`. Earlier checkpoint pins are unchanged.
