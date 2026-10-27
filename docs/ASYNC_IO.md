# Bounded local-stream asynchronous I/O reactor

Hepta now has a real, caller-driven readiness reactor for **`x86_64-unknown-linux-gnu`, hosted Rust**. Source programs can own a reactor, create private Unix socketpairs, submit multiple owned buffers, wait on native readiness, cancel requests, collect partial results, and close all resources. `examples/io/pipeline.hepta` transfers data through two native socketpairs with four simultaneously admitted requests and cross-file helpers.

This is an asynchronous I/O **profile**, with an explicit pump. It is not an `async`/`await` language implementation, a background executor or arbitrary network/filesystem I/O. The separately qualified [worker-owned task-tree composition](TASK_TREE_IO_COMPOSITION.md) adds shared I/O reservations and cancellation wakeups through `io_attach`; this document and `validate_io.py` retain the standalone-reactor scope. Other target architectures, libc environments and operating systems fail at the runtime's target guard. `no_std`, the independent C backend, resource IR, concurrent IR and HMIR reject the I/O profile, including unused I/O declarations. Their existing acceptance of other Hepta programs does not imply I/O coverage.

The source ownership checker and the final Rust compiler both remain required. The sole production `unsafe` operation added here is the `poll(2)` call described below. This qualification does not prove language soundness, backend refinement, pointer provenance in arbitrary FFI, or a whole-process resource bound.

## Source API

`IoReactor` and `IoRequest` are opaque linear owners. `IoPair` and `IoReport` are Copy snapshots whose fields can be read; source construction is rejected. `port` is a checked `u64` identity, never a native file descriptor. Time arguments are `u64` milliseconds. All byte storage is an initialized `Buffer<u8>`.

| Operation | Arguments | Result and effect |
| --- | --- | --- |
| `io_reactor` | `ports: usize, requests: usize, bytes: usize` | Owned reactor; inspect `io_report(read io).status` for construction refusal. |
| `io_local_pair` | `mut IoReactor` | `IoPair {left: u64, right: u64, status: u8}`. Creates two connected nonblocking endpoints owned by this reactor. |
| `io_read` | `mut IoReactor, port: u64, move Buffer<u8>, requested: usize, deadline_ms: u64` | Owned request to read the requested number of bytes or finish with a partial result. |
| `io_write` | Same argument modes as `io_read` | Owned request to write the requested prefix or finish with a partial result. |
| `io_poll` | `mut IoReactor, max_wait_ms: u64` | `Result<usize,u8>`: count of requests newly completed during this pump, or a configuration/argument error. |
| `io_cancel` | `mut IoReactor, read IoRequest` | `bool`: true only when this call changes a pending request to cancelled. The ticket remains an owner. |
| `io_request_status` | `read IoReactor, read IoRequest` | Current `u8` status; does not pump. |
| `io_take` | `mut IoReactor, move IoRequest, mut usize, mut u8` | Original owned buffer. Writes transferred count and final status; first cancels a still-pending request. |
| `io_wait` | Same argument modes as `io_take` | Pumps all pending requests until this ticket is complete, then returns its original buffer and outputs. |
| `io_close_port` | `mut IoReactor, port: u64` | Closes the owned endpoint, finishes its pending operations as closed, and returns whether the identity existed. |
| `io_report` | `read IoReactor` | Copy resource and operation counters; does not pump. |
| `io_shutdown` | `move IoReactor` | Cancels remaining pending operations, drops all resident buffers and endpoints, and returns a final `IoReport`. |

All operations other than the two snapshot/status reads currently require the conservative effect set `{alloc,block,panic,io,write}`. This covers allocation/setup/cleanup and explicit event waiting without claiming that every individual call always allocates or blocks. Ownership transfer is written with `move`; a function declaration receiving the owner uses `take`.

An invalid constructor returns a failed **owned** reactor. It must still be consumed with `io_shutdown`; it cannot silently disappear on a return path. Refused submissions return an owned request containing the original buffer. Such a request must also be consumed with `io_take` or `io_wait`, then the returned buffer must be released or moved onward.

The current profile permits direct owned I/O parameters and returns, including cross-file helpers. It rejects hiding I/O owners in structs, enums, arrays or generic arguments, even an `Owned` generic. It does not provide `Result<IoRequest, Error>` or stored references to I/O owners. These restrictions keep unsupported resource composition explicit.

## A usable owned flow

The following is the core of the application in `examples/io/pipeline.hepta`; the full runnable example also checks every byte and the final resource counters.

```hepta
fn main() -> Unit effects {alloc,block,panic,io,write} {
    let mut io = io_reactor(2,2,16);
    assert(io_report(read io).status == 0);
    let pair = io_local_pair(mut io);
    assert(pair.status == 0);
    let input = buffer(8);
    let mut output = buffer(8);
    for i in 0..8 { output[i] = 23; }
    let reading = io_read(mut io,pair.left,move input,8,1000);
    let writing = io_write(mut io,pair.right,move output,8,1000);
    let mut count: usize = 0;
    let mut status: u8 = 0;
    let received = io_wait(mut io,move reading,mut count,mut status);
    assert(status == 0); assert(count == 8);
    release(move received);
    let sent = io_wait(mut io,move writing,mut count,mut status);
    assert(status == 0); assert(count == 8);
    release(move sent);
    let report = io_shutdown(move io);
    assert(report.reserved_bytes == 0);
    assert(report.open_ports == 0);
}
```

Waiting for `reading` also advances `writing`. The runtime does not create a blocking thread for either request. `io_wait` blocks the **calling thread** in the readiness primitive when progress requires an OS event. A user implementing a larger event loop can instead call `io_poll` with an explicit maximum wait and inspect multiple tickets between calls.

The three source applications exercise distinct paths:

| Entry point | Observed work |
| --- | --- |
| `examples/io/pipeline.hepta` | Cross-file `IoRequest` returns, four admitted operations, two socketpairs, byte-for-byte content checks and explicit collection. |
| `examples/io/cancellation.hepta` | Cancel then collect, an actual timeout, peer EOF, broken-peer write, and final empty resource counters. |
| `examples/io/failure_paths.hepta` | Failed reactor construction, `Result` handling for an invalid pump duration, request-slot refusal, byte-budget refusal, and cross-file owned error/early-return cleanup. |

## Completion and cancellation rules

Each admitted operation stores its owned buffer, requested length, transferred count, original absolute `Instant` deadline, port identity and terminal status. No buffer borrow escapes a pump call. A read touches only the unfilled initialized range, and a write reads only the unsent prefix of the supplied buffer.

Reads and writes may complete partially. The reactor continues toward the requested length until success, EOF, close, cancellation, timeout or error. The returned count is the prefix actually transferred. A partial read leaves the rest of the original buffer initialized and unchanged. A cancelled write cannot retract bytes the peer has already received.

All reactor mutation requires an exclusive borrow. The native reactor is additionally `!Send` and `!Sync`, so safe Rust cannot move it to another thread or share it concurrently. Cancellation is serialized **between pump calls**:

1. If cancellation happens before the next read/write attempt, that request performs no further I/O, even if bytes are already waiting in the socket.
2. If a pump has already completed a request, later cancellation returns false and keeps the completed result.
3. `io_take` on a pending request performs cancellation and collection together. `io_cancel` alone keeps the slot and buffer reserved until collection.
4. `io_close_port` preserves already completed results and marks only pending operations closed.

An unattached reactor has no external cancellation token or wakeup FD. Its owner regains control through a bounded `io_poll` call. The explicit task-worker attachment adds an owned wakeup FD for propagated group cancellation; it still never allows two threads to mutate the reactor and provides no hard scheduling deadline. The standalone native race controls run a peer writer concurrently with cancellation. Task-tree cancellation is qualified separately in `qualify_task_io.py`.

The deadline is computed once at admission, in the inclusive range 0 through 86,400,000 milliseconds. A nonempty request with a zero deadline times out without I/O. A zero-length request completes successfully without I/O after normal admission checks. `requested > len(buffer)` and larger durations are refused. Time spent queued behind other work counts against the original deadline.

Each pump performs a bounded round-robin scan with at most one nonblocking syscall per pending request per scan. If this completes an operation it can return immediately. Otherwise it calls `poll` once for the minimum of the caller's wait and the nearest operation deadline, then scans again. It rounds a fractional millisecond upward to avoid repeated premature deadline wakeups. `EINTR` does not restart deadlines. Nonblocking reads/writes decide the actual outcome after readiness or peer-close races; `revents` does not grant authority to touch memory or extend a deadline.

An OS failure of `poll` completes the currently pending requests with `SYSTEM`; the pump returns the number completed. Thus `Result::Ok(n)` from `io_poll` means the pump completed `n` requests, not that those requests all transferred their requested lengths. Inspect each request's final status.

## Status codes

| Code | Meaning |
| --- | --- |
| `0` | Successful construction, pair creation or complete requested transfer. |
| `1` | Cancelled; transferred count may be nonzero. |
| `2` | Original deadline expired; transferred count may be nonzero. |
| `3` | EOF before the requested read length. |
| `4` | Owned port was closed before completion. |
| `5` | Native system operation failed; `last_os_error` retains the latest available errno. |
| `6` | Invalid configuration, length or duration. |
| `7` | All request slots are occupied, including completed uncollected requests. |
| `8` | Admitting the buffer's capacity would exceed the byte budget, or the sum overflows. |
| `9` | This endpoint already has a pending operation in the same direction. |
| `10` | Stale ticket or an admitted ticket used with the wrong reactor. |
| `11` | Missing, stale or foreign port identity. |
| `12` | Fixed reactor metadata allocation was refused. |
| `13` | The process-wide monotonic identity space is exhausted; identities never wrap. |
| `14` | Fewer than two endpoint slots remain for a new socketpair. |
| `255` | Request remains pending. |

Statuses are currently `u8` values rather than a public status ADT. A terminal refused ticket owns its own buffer and can be collected without accessing any reactor slot. A terminal admitted ticket refers to a buffer still owned by its originating reactor.

`io_request_status` and `io_cancel` reject a foreign **admitted** ticket without consuming it, so the caller can still use the correct reactor. If the caller consumes that ticket with the wrong reactor, `io_take`/`io_wait` return an empty buffer, zero count and status 10. They never follow the foreign identity to another reactor. The original buffer remains bounded and owned by the original reactor until shutdown, which counts it as abandoned and frees it. This is failure containment, not a statically proved origin relationship or immediate recovery of the original buffer. Normal source code should collect each ticket with its origin before shutdown.

## Resource accounting and costs

The reactor admits 2 through 256 owned endpoints and 1 through 1024 occupied request slots. One endpoint can have one pending reader and one pending writer. Completion frees that direction for a new operation, while its old request slot and buffer remain reserved until collection.

`byte_limit` counts the **capacity in bytes** of every admitted `Vec<u8>`, not its length. This includes pending, cancelled, timed-out, errored and successful-but-uncollected buffers. Capacity is checked with overflow detection before insertion. Refusal retains the original buffer in the returned ticket and changes neither occupied slots nor resident bytes. The budget recovers when a resident buffer is collected or the reactor is destroyed.

The three metadata arrays—ports, request slots and poll records—are fallibly reserved before use. Their sizes depend on the explicit port/request limits. Partial constructor failure keeps ownership of prior allocations until the failed reactor is shut down or dropped. Native controls refuse each of these actual allocation attempts and verify that all earlier allocations are freed. Ordinary ready submission, pumping and collection also have a native allocation-entry-point control observing zero new heap allocations after setup.

This is a bounded metadata and admitted-buffer model. It excludes buffers allocated before admission, buffers in refused tickets, allocator bookkeeping, native socket buffers, other reactors, process RSS and CPU time. The regular `buffer` constructor can still abort on ordinary allocator exhaustion; a caller needing fallible buffer setup uses the existing `try_buffer` flow. No runtime can promise recovery from `panic=abort` or process termination through this interface.

`IoReport` contains the configured limits; current open ports, occupied/pending requests and reserved bytes; peak slots/bytes; and saturating `u64` operation counters. `admitted` counts admitted requests. `refused` counts rejected pair creation and request admission attempts. `completed` counts admitted operations that reached a terminal status. `cancelled`, `timed_out`, `abandoned`, poll calls/interruptions/failures, read/write attempts, would-block results and bytes transferred are separately visible. `abandoned` counts resident request buffers destroyed by shutdown without ticket collection. `shutdown` marks the final report.

Port lookups are bounded linear searches. A full progress pass has worst-case work proportional to request capacity times port capacity; the runtime does not claim epoll-scale behavior, Rust-wide performance superiority, or zero overhead for arbitrary programs. The explicit limits and measurements make this first profile's cost visible.

## Descriptor, buffer and unsafe boundary audit

Descriptors are created by Rust's safe `UnixStream::pair`, configured nonblocking before insertion, and kept in owned `UnixStream` fields. Production source has no raw FD import, FD export, descriptor cloning or externally supplied buffer pointer. Port and request identities come from a checked monotonic process-wide counter. Slot reuse does not reuse an identity, and identity exhaustion refuses admission.

The sole added production unsafe call is libc `poll` with a `#[repr(C)]` array of `{i32, i16, i16}` records and a `usize` count. The guard restricts this declaration to the qualified x86-64 GNU Linux ABI. The independent C fixture compares native `<poll.h>` size, alignment, offsets and `nfds_t` width against the Rust declaration. Every array entry is initialized, its exact length is passed, the allocation is not resized during the call, and the OS retains neither this pointer nor ownership of the file descriptors.

The exclusive reactor borrow prevents close or reassignment while polling or calling `Read`/`Write`; the owned endpoint remains alive throughout. Closing a port drops its stream exactly once. The implementation does not retry a raw numeric close, reconstruct ownership from a stale FD, or pass a user integer to `close`. Native tests confirm actual kernel descriptor closure with `fcntl`, force numerical FD reuse, then verify that old port/ticket identities cannot alter the new endpoint. Buffer storage stays owned until no read/write invocation can still access it.

Rust `UnixStream` writes use the `MSG_NOSIGNAL` behavior documented by the standard library, so a broken peer is reported rather than requiring a process-wide SIGPIPE handler. The qualifier checks this with the pinned Rust 1.90.0 toolchain. Peer closure and partial data are handled by the real nonblocking I/O result. The Linux `poll`, Rust standard-library ownership/syscall wrappers, compiler, libc and kernel remain trusted external components.

The test fixture contains additional unsafe allocator instrumentation and C hooks. These are linked only into its standalone native controls. Production source applications do not link the fixture. The fixture's direct socket clones and manually reconstructed stale ticket are trusted test setup; source programs cannot perform those operations.

## Qualification and failure retention

Run on the declared host with the pinned native Rust 1.90.0 compiler and GCC:

```sh
RUSTC=/path/to/rust-1.90.0/bin/rustc python tools/validate_io.py \
  --repeats 3 --output artifacts/io-reactor-attempt-001.json
RUSTC=/path/to/rust-1.90.0/bin/rustc python -m unittest tests.test_io_runtime -v
```

The qualifier runs all three source applications for every repetition, checks 16 invalid/unsupported source profiles, and executes the native controls. Each native trial includes:

- Actual delayed peer readiness with wall-clock, calling-thread CPU and time inside real `poll`; a separate full-socket write waits for the peer to drain and completes through write readiness. The controls require bounded wakeup counts and actual event waits.
- Partial read plus EOF, partial-read cancellation with the initialized tail preserved, a broken peer, a partially delivered 2 MiB write cancelled before further progress, ready-before-cancel, and 64 peer-readiness/cancellation races.
- Five timed EINTR returns injected at the native `poll` boundary to test preservation of the original deadline, and an injected poll error followed by successful reuse of the descriptors. This is native syscall-boundary injection, not a claim to test real signal delivery.
- Request-slot, port-slot, direction and capacity refusals, including completed-but-uncollected reservations and subsequent recovery.
- Numerical FD reuse, stale request reuse, foreign reactor rejection, actual descriptor close observations, and tracked resident-buffer cleanup at shutdown/native drop.
- An actual kernel FD-limit refusal by temporarily lowering only the qualification process's soft `RLIMIT_NOFILE`, restoring it before assertions, and then creating a new pair successfully.
- Three distinct native metadata allocation refusals, successful subsequent construction, zero-allocation observed ready paths, and identity exhaustion refusal controls.

The standalone validator re-lowers the current source graph and checks compiler/source identities, the module graph, ownership checking, actual optimized native builds, artifact identities, native C object/link flags, exact case denominators and raw per-trial output. It requires the complete expected compiler flag list, with controlled sysroot/linker selection, and binds the C command's executable path to the current compiler binary hash. Every execution records its actual argv, byte size and binary hashes before and after execution, linked to the build record. It rejects altered scope claims, missing failures/refusals, false timing, omitted trials, boolean counts, contradictory flags, inconsistent raw metrics, or metadata-only builds presented as executed binaries. It cannot authenticate arbitrary third-party reports; hashes are identity bindings, not signatures or proofs of execution.

Reports are checkpointed before inspecting execution success. A failed process, timeout or denied syscall therefore stays visible with its output and partial denominator. Child stdout/stderr bytes are retained as base64 with their byte hashes; successful output is separately parsed as strict UTF-8. Non-UTF8 failure/timeout output is retained without replacement decoding, and even an exit-zero process with non-UTF8 output is recorded and rejected. The tool refuses to overwrite an existing report, including a failed attempt. A syscall-filtered environment may permit socketpair creation but deny `send(MSG_NOSIGNAL)` with `EPERM`; such an attempt must remain failed. Running the same actual local-only qualification in an approved environment is separate evidence, never a change to the runtime's I/O semantics. No listener or external network service is used.

## Work still outside this profile

Async language syntax, general futures, background executors, arbitrary external cancellation tokens, arbitrary files/network protocols, epoll scalability, portability, broad allocator policies and whole-process budgets remain future work. The finite explicit task-worker attachment now supplies task-tree wakeup and shared reservation composition; it does not complete those broader obligations. Generative reactor lifetimes, resource-carrying I/O ADTs and independent I/O IR/refinement proofs are also absent.

## Primary references

- [Linux `poll(2)` contract, readiness, millisecond timeout and errors](https://man7.org/linux/man-pages/man2/poll.2.html).
- [Linux `close(2)`, descriptor reuse and close/retry races](https://man7.org/linux/man-pages/man2/close.2.html).
- [Rust `UnixStream`: unnamed pairs, nonblocking mode and SIGPIPE behavior](https://doc.rust-lang.org/std/os/unix/net/struct.UnixStream.html).
- [Rust 1.90.0 `Read` contract: initialized buffers, partial reads and interruption](https://doc.rust-lang.org/1.90.0/std/io/trait.Read.html).
