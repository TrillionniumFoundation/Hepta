# print_i64 output failure and visibility

The Rust backend lowers `print_i64` to `println!`, whose [documented contract](https://doc.rust-lang.org/std/macro.println!.html) panics when stdout writing fails. Rust's [stdio implementation](https://doc.rust-lang.org/src/std/io/stdio.rs.html) uses a locked `LineWriter`; the pinned Rust 1.90 test below must qualify actual redirected-pipe behavior rather than relying only on current documentation.

Previously, the C emitter discarded `printf`'s return value and relied on libc's exit-time flushing. A program printing 42 to Linux `/dev/full` returned success with no output. Fully buffered pipes also withheld a printed line while the program proceeded to a blocking foreign input call, preventing request/response progress.

The C emitter now checks `printf` and `fflush(stdout)` before proceeding. It evaluates the argument once, emits the same decimal integer and newline, and aborts on reported errors. Flushing is necessary to observe failures hidden by a successful buffered `printf`.

## Limits

- This is submission through stdio to the OS, not `fsync`, durable storage, receiver consumption or delivery acknowledgment.
- No signal disposition changes: default C SIGPIPE may terminate during a broken-pipe write; if SIGPIPE is ignored and libc returns an error, the guard aborts. Rust startup may use a different signal disposition. Tests preserve and distinguish these outcomes.
- No atomicity promise across foreign writers or the separate printf/flush calls. The C profile does not acquire Rust's stdout lock or change host buffering modes.
- Windows console/text-mode behavior, non-Linux profiles and asynchronous stream closure are not newly qualified.
- Per-line flushing has a cost. This is a correctness/visibility change, not a performance improvement.

## Recorded local cost

[C_PRINT_FLUSH_COST_20261103.json](C_PRINT_FLUSH_COST_20261103.json) retains all 14 observations, the source program, generated-source hashes, compiler identity and fixed protocol. GCC O3, Linux x86-64, 20,000 lines to `/dev/null`, one warmup per arm and seven alternating paired rounds: median end-to-end time increased from **3.006 ms to 7.662 ms (2.55x)**. Timing includes process startup. No samples were discarded. This one shared-host output microcase is not a general throughput estimate or a Rust comparison; real pipes/files may behave differently.

Reproduction: emit the recorded Hepta source from the recorded base commit and this patch, compile each with the recorded flags plus `-lm`, then run each executable to `/dev/null` using the recorded paired order. Check generated-source hashes before comparing timings.

## Qualification

`python -m unittest tests.test_c_print_failures tests.test_c_backend -v`

The new Linux tests execute GCC O0/O3 with UBSan: exact success bytes and once-only argument evaluation, default-buffered `/dev/full` flush failure, unbuffered write failure, a real bidirectional pipe handshake and broken pipes under default/ignored SIGPIPE. Every failure checks that the later foreign marker was not executed. A separate real Rust reference runs the same sources and helper object with panic=abort.

The exact-head workflow requires all 16 tests with zero skips on Linux x86-64 and AArch64. Local absence of Rust is an explicit skip, not reference evidence. Hosted results must be read for the tested commit; prior commits do not qualify this change.
