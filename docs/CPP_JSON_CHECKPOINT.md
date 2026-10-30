# Finite caller checkpoints around the scoped JSON C ABI

`hepta.cpp-json-checkpoint.v1` keeps a bounded integer-array checkpoint in the
parent process while each invocation uses the existing Hepta caller and scoped
C ABI in a fresh child. It admits the pinned nlohmann/json 3.11.3 and 3.12.0
adapters on Linux x86-64. The C++ library, adapter, bridge contract and Hepta
caller are retained, not rewritten. Foreign memory safety remains an unsafe
interoperability obligation.

The earlier upgrade qualification observed 17 ordinary `operator new` sites
per release. Sites 1–14 returned the caught-exception status; sites 15–17
terminated with `SIGABRT` after allocation failed inside a `noexcept`
destructor. Those six failed foreign calls and their historical evidence remain
failed. This profile observes a different property: a failed child does not
publish a new parent checkpoint, and a new, explicitly requested invocation
can reconstruct the bounded operation from the retained parent values.

## Reused lifetime and process boundaries

`tools.qualify_cpp_upgrade.build_json_checkpoint_image` reuses the pinned
upstream headers, `examples/cpp/upgrade/adapter.hpp`, `contract.json`,
`consumer.hepta`, the existing C++ bridge generator and the existing Hepta
object compilation route. The scoped generated bridge finishes destruction
before it publishes the scalar output. The added `recovery_worker.cpp` calls
that same ABI. It neither suppresses allocation sites nor changes the foreign
destructor's `noexcept` behavior.

`hepta.cpp_json_checkpoint.JsonCheckpoint` uses `hepta.clang_capture.run_bounded`
as its sole process owner. The existing capture implementation retains bounded
streams, owns the direct child and its process group, and reaps the direct
child. A small Python bootstrap receives the immutable built ELF bytes,
checks their digest, creates a sealed executable `memfd`, creates sealed input
bytes and executes the ELF descriptor. A mutable build-path copy is not later
execution authority. The host Python interpreter, native compiler and their
dependencies remain trusted; this is not a capability defense against hostile
Python code or a complete operating-system sandbox.

No C++ object survives between calls. No foreign pointer or handle crosses the
process boundary. The parent state is an immutable tuple of integers, and its
transition is the registered replacement of one element. The parent checks the
native sum against independent integer arithmetic before committing that
transition. This is neither arbitrary C++ object serialization nor general
foreign-state migration.

## Exact admitted limits and commit rule

The checkpoint accepts 1–64 ordinary integers, each in
`[-1_000_000, 1_000_000]`. Boolean and floating-point values are refused. A
checkpoint can issue at most 128 requests, including requests that are later
cancelled, with one outstanding request at a time. Each request carries the
current revision, a monotonically increasing sequence, a private owner
identity and a fresh nonce. Its live object identity and original bytes are
checked before execution; serialized diagnostics, copied requests, stale
revisions and consumed requests grant no execution authority. Reentrant
mutation is refused while a request is executing.

Each invocation has a three-second capture deadline, at most 4096 bytes in
each output stream, and a launch envelope capped at 3,000,000 bytes. The
bootstrap applies child address-space, CPU, file-size and core-dump limits of
256 MiB, two seconds, 65,536 bytes and zero, or a stricter inherited limit.
These are concrete refusal limits; they do not prove whole-host RSS, WCET,
parent allocation success, full loader isolation or complete environment
closure. Existing process-group cleanup does not establish completion of
arbitrary escaped descendants.

Only a normal owned-child exit, empty stderr and one complete, closed, typed
response can commit. The response must match the request digest, nonce,
library version, sequence and revision; its ordinary allocation ledger and
scalar result must pass the fixed checks. Parent publication follows all
these checks. A complete success-looking frame followed by a nonzero exit
cannot commit.

| Outcome | Parent state | Subsequent authority |
| --- | --- | --- |
| Valid normal response | Commit the checked replacement and next revision | A newly prepared request |
| Caught injected foreign exception | Preserve the previous checkpoint | A newly prepared request |
| Observed `SIGABRT` with `std::bad_alloc` | Preserve the previous checkpoint; retain foreign failure | A newly prepared request |
| Bounded capture refusal with confirmed direct-child cleanup | Preserve the checkpoint | A newly prepared request |
| Malformed, stale, noisy or inconsistent response | Preserve the checkpoint | Owner poisoned; refuse mutation |
| Uncertain cleanup or interrupted execution | Preserve the checkpoint | Owner poisoned; refuse mutation |
| Return-value publication fails after commit | Retain the already committed state; record publication failure | Owner poisoned; refuse mutation |

No outcome automatically retries the operation. A failed request is consumed.
The publication-failure case must not be called a rollback: the history keeps
its actual committed state, annotates `publication_failure`, and records that
the owner is poisoned. Host allocation/report-construction failure is not a
claim that all diagnostic writes can always complete.

File, network, device or other external side effects are not part of the
admitted operation and are not rolled back. The profile grants no permission
to transfer pointers, handles, arbitrary C++ object graphs or foreign resource
ownership. It does not change default compiler, Rust interpreter or native
admission policy.

## API and qualification

The image factory builds the existing bridge and the new finite worker into a
new directory. The owner then requires explicit requests:

```python
from hepta.cpp_json_checkpoint import JsonCheckpoint
from tools.qualify_cpp_upgrade import build_json_checkpoint_image

image = build_json_checkpoint_image(new_build_directory, "3.12.0", rustc=rustc)
with JsonCheckpoint(image, [1, 2, 3]) as owner:
    request = owner.prepare(1, 5, revision=0)
    observation = owner.execute(request)
    # A later invocation must prepare a new request using the current revision.
```

The collector requires a new external output directory. Formal execution
additionally requires the exact clean implementation commit:

```sh
python -B -m tools.qualify_cpp_json_checkpoint \
  --output-directory /absolute/new/qualification \
  --rustc /absolute/pinned/rustc \
  --expected-head FULL_IMPLEMENTATION_COMMIT
```

Omitting `--expected-head` produces an explicit development observation. It
cannot later be promoted to a formal qualification merely by editing its
commit field. The formal source check compares the complete recorded source
closure against original Git blob bytes and Git owner-execute mode, rather
than relying solely on `git status`.

For each version, the actual native calibration supplies the allocation-site
denominator. Every measured site then runs a committed prefix, the injected
fault, a refused replay, a separately prepared reconstruction, and a further
state transition. The replay refusal launches no child. Three ordinary input
cases are additional. With the observed 17 sites per version, the collector
therefore executes `2 + 4 × 17 + 3 = 73` workers per release, 146 in total.
The 34 faulted calls remain 28 caught foreign exceptions and six foreign
terminations. Parent preservation, fresh-request reconstruction and subsequent
continuation are separate observations for all 34 sites, not 34 recovered
foreign invocations. Failed stages, raw bytes, allocation counts and elapsed
cost remain in the report.

The default `validate_report` preserves the strict current clean-HEAD check.
Historical audit has a separate command, including explicit relocation of
retained files:

```sh
python -B -m tools.qualify_cpp_json_checkpoint \
  --audit-report /absolute/retained/qualification.json \
  --retained-directory /absolute/relocated/qualification
```

This audit requires the original Git objects in the local source repository.
It checks the recorded original commit/tree, complete source-blob closure,
retained file hashes, raw process responses, request/state chains, independent
integer results and exact denominators. It executes no archived code or
native worker, does not rewrite the recorded directory or head, and reports
`execution_authority=false` and `qualified_current_head=false`. A docs/evidence
child commit can audit its predecessor's record but does not acquire a new
execution qualification. Byte consistency is not independent authentication
that historical execution occurred.

## Development observations and remaining limits

The first focused development suite passed 23 methods: 17 new protocol/native
methods and six existing upgrade input/failure-collection methods. It retained
the two-version 146-worker matrix and one additional actual immutable-image
control separately. Complete-frame/nonzero-exit and partial-frame/timeout
controls use real process exits but are not credited as C++ library successes.
Two later pure regressions cover original-object audit after a docs child and
publication failure after a commit. The final integrated implementation needs
its own fresh qualification; these development records do not qualify a later
commit.

Measured collector time includes builds, failed foreign invocations and the
new independent requests. Human effort and agent token totals remain unknown.
No speed advantage, general C++ rewrite, elimination of the six foreign
terminations, complete side-effect recovery or whole-library memory-safety
result is claimed.
