# Independent task/I/O composition review

This review extends the acceptance evidence for the task-tree/local-reactor
composition without changing production runtime semantics. It found no
reproducible runtime defect in the inspected lock, admission, rollback and
destruction paths. That is a bounded review result, not a proof of deadlock
freedom or of all schedules.

## Exact source and observations

The three-round qualification binds commit
`76f33a2b9f34da03de917994c379a92bc05e42c9`, tree
`e550f28aed492f52a0a8e6b1a8c97cf258fc24a8` and compiler SHA-256
`80c75b69e289a489593792994606c7347cb0b679280495e57ab95bde19ec6636`.
The review commit changes only fixtures, qualification/verification tests and
the feature's documentation. A subsequent integrated compiler requires its
own full qualification.

- **11 task/I/O tests passed**, with no skips, failures or errors. The final
  test log is retained. Disposable unit-test native directories were removed
  by the test suite; the two explicitly retained qualifier directories below
  include their native products.
- **10/10 planned qualification cases passed**, with three prescribed rounds
  for every executable case. This means 27 actual binary invocations: nine
  source-example runs, three native-control runs and 15 deliberately incorrect
  runtime runs. The tenth case is an actual rejected Rust alias build, with
  no claimed execution.
- Every positive native-control round observed **208 buffer allocations,
  208 buffer frees and zero final live buffers**. Actual poll entries were
  136, 137 and 137, respectively; their timing/order is not a performance result.
- Each round retains 64 parent/child cancel-versus-fail races, 64 attachment
  races, 64 readiness races and 32 shared-byte admission races, in addition to
  the original timeout, error, adoption-refusal and resource controls.

## Two added boundaries

**Partially established wake sockets.** A preparation `strace` of the earlier
qualified source example established that this pinned Rust/Linux profile
calls `ioctl(FIONBIO)` for `UnixStream::set_nonblocking`. The new qualification
shim injects actual syscall errors at the first and second wake endpoint's
nonblocking setup. Each failure happens after the kernel has created both
descriptors. The control observes both descriptors closed with `EBADF`, all
four pool reservations unchanged, and a successful subsequent attachment.
Both actual refusals execute in every round. The shim admits only this finite
FIONBIO pointer ABI and is absent from source-example builds.

**Last cancellation reference destroyed under a group lock.** A deterministic
interleaving keeps group state locked and retains a wake `Arc` in the canceller
while the worker shuts down its own reactor. The worker returns its resident
buffer reservation before completing. The temporary cancellation reference
keeps the wake reader open and the attachment reservation live. Releasing that
last reference while still holding group state closes the reader and returns
the remaining reactor/endpoint/request reservations. The worker then completes
and tree joining verifies all reservations are zero.

Five separately compiled wrong runtimes remain required negative controls.
Omitting the cancellation wake and adding a group-state lock inside binding
destruction each reaches its documented native handshake and hits a genuine
two-second timeout. Shared-byte budget bypass, omitted reservation release and
an actual resident-buffer leak each abort at its own expected assertion.
Across the three rounds, those are six recorded timeouts and nine aborts;
they are expected negative-control outcomes, not omitted failed trials.

The documentation also makes the one-time pool configuration rule precise:
the invoking group must have admitted no tasks, and the shared pool must have
no outstanding worker reservations. An unused surviving sponsor may configure
I/O after older groups have joined. This does not retrospectively budget prior
work and does not change the existing runtime behavior.

## Complete sealed bytes

`native-records.tar.xz.base64` retains **173 members / 73,356,788 decoded member
bytes**, including generated native sources, every retained object/executable,
raw stdout/stderr, both qualifier reports, two test logs and the preparation
syscall trace. Its compressed archive is 2,304,164 bytes; the archive SHA-256 is
`761fcd763df54408a8d1d24ff88232362912f4bfd7af0b441c6635837a09800e`.
`MANIFEST.json` gives every member's exact original path, byte count and digest.

The archive separates these records:

| Archive prefix | Meaning |
| --- | --- |
| `development-001/` | First actual one-round review qualification, before the explicit final-reader FD assertion was added. It passed in that earlier source state and is retained unchanged. |
| `frozen-001/` | Complete three-round qualification at the exact commit above, including the final-reader FD assertion and every compiled wrong runtime. |
| `review/` | Two actual unit-test logs and a preparation trace of the earlier qualified pipeline binary. The trace is not substituted for current-commit execution. |

The source/example/path identities inside reports are original bytes; the
archive does not rewrite them to impersonate a new checkout. The native report
validator expects its bound source and retained artifact paths. The standalone
archive verifier checks sealed file identities without extracting, compiling
or executing anything:

```sh
python evidence/task_io_review_20261026/verify_bundle.py
```

The independent verification observed all 173 expected members, their exact
sizes and digests. That is an integrity check, not 173 additional native runs
or authentication against an author who fabricates every input and receipt.

To qualify a new unchanged source snapshot, use a new output path:

```sh
RUSTC=/absolute/path/to/rust-1.90.0/bin/rustc \
  python -m tools.qualify_task_io --repeats 3 --output /tmp/new-task-io-review.json
```

The original composition development failures and earlier three-round records
remain under `evidence/task_io_composition_20261027/`. This review does not
rewrite them or close the broader all-process budgeting, general async
scheduling, compiler-refinement or production-service blockers.
