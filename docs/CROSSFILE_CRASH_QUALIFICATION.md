# Per-task workspace crash qualification

The cross-file evaluator now has a separate process-death qualification for
all five frozen Hepta tasks. It uses the production `hepta.patch.v4` workspace
path, the same native task/API check as the fourth study arm, the actual
namespace policy, and real `os._exit(71)` deaths in commit workers. A normal
provider attempt still stops when commit transport leaves publication
unverified. Recovery in this qualification is a separate trusted operator
action; it does not turn a failed provider attempt into a successful one or
erase its recorded usage.

## Run

```sh
python -m experiments.crossfile_eval qualify-workspace-crashes \
  --output artifacts/workspace-crashes-001.json
```

`--rustc` selects an explicit Rust compiler. `--execution-context` is an
optional public operator annotation of the outer environment, not an automatic
attestation. The output is append-only: an existing path is rejected. There is
no CLI fixture option and no weaker-isolation fallback. A host that cannot
create the required namespaces produces `environment_blocked`, with all ten
planned cases retained and none marked complete.

The two checkpoints already exist in `hepta.workspace.apply_workspace_patch`:

| Checkpoint | Durable state at child death | Required recovery and exact-request retry |
| --- | --- | --- |
| `prepared` | The new immutable version exists and `JOURNAL` is prepared; `CURRENT` still names the old complete version. | Two recoveries both report aborted and preserve the old version. Retrying the identical original expected-head/interface request commits the checked new version. |
| `published` | `CURRENT` names the new complete version; `JOURNAL` is still prepared. | Two recoveries both report committed and preserve the new version. Retrying the original request rejects `E_STALE_PROJECT`; no second commit acknowledgement is invented. |

The crash worker is copied only into a trusted qualification capsule. It is
absent from ordinary `ProductionWorkspaceSession` capsules and is not one of
the public study tools. The normal JSON helper cannot turn a message field
into the private Python `_checkpoint` callback. The worker itself has no
hidden inputs, task answers, provider credentials, or arbitrary Python
evaluation endpoint.

## What each case executes

1. Initialize a native-checked production store from the frozen public task;
   inspect its actual semantic nodes.
2. Prepare the reference semantic edits without publishing. Perform the
   independent native task/API check. Its source, object, and candidate-crate
   hashes are now recorded as a `task_native_check` trace event in ordinary
   production workspace sessions as well.
3. Send the identical checked patch to a new commit child. The trusted hook
   observes `CURRENT`, `JOURNAL`, and the old pinned version, flushes its fixed
   marker, and calls `os._exit(71)` at the chosen checkpoint. The parent checks
   both the marker and the actual child exit status. A normal exit, timeout,
   malformed response, or missed checkpoint fails qualification.
4. Retain `unverified_after_commit` as the transport outcome. A separate
   namespace worker observes the store before recovery. The observation must
   match the checkpoint marker and contain one complete old or new version.
5. Recover twice in separate processes and check idempotence. Replay the
   original patch, including its original CAS preconditions. Require the
   checkpoint-specific outcome shown above, then recover the final committed
   state again.
6. Check that the original pinned version still has every original byte and
   bound native profile. Take a fresh final production pin; the scored source
   must equal the prepared candidate. Close all workspace children and remove
   their temporary store before materializing private scoring inputs in a
   different capsule.
7. Build and execute the recovered final candidate against every hidden native
   case. Initialization, edits, validation, death, recovery, retries, pinning,
   and native scoring share a frozen 90-second wall deadline per case.

| Frozen task | Actual death points | Hidden native inputs per point | Total inputs |
| --- | ---: | ---: | ---: |
| Cross-module API migration | 2 | 75 | 150 |
| Owned `Result` API migration | 2 | 24 | 48 |
| C/C++ native bridge | 2 | 56 | 112 |
| Resource cancellation | 2 | 14 | 28 |
| Cross-file defect repair | 2 | 143 | 286 |
| **Required denominator** | **10** | | **624** |

Failures, missed deaths, native failures, and deadline exhaustion remain in
their task/checkpoint cells. They do not reduce the denominator or become
zero-cost successful samples.

## Evidence validation

`workspace_crash_evidence.validate_crash_matrix` checks all ten sealed records,
the exact task matrix, compiler/toolchain and evaluator identity, namespace
requirements on every RPC, actual death status, immutable file/source hashes,
the prepared native task gate, publication and journal byte hashes, recovery
idempotence, identical-request retry, old pins, final source identity, and all
624 native outcomes. It distinguishes an ordinary successful commit response
from a committed version recovered after a response-less process death.

The qualification also mutates and **re-seals** sixteen records. The validator
must reject omitted or duplicated cases, a normal exit relabeled as a crash,
the wrong checkpoint, missing namespace enforcement, a changed prepared
source, torn `CURRENT`, a changed old pin, false recovery, a rebased retry,
acceptance of a stale retry, a different scored source, omitted native cases,
an erased ambiguous outcome, a fabricated provider run, and erased wall time.
Re-sealing ensures these controls exercise the semantic checks rather than
only the record checksum.

The native unit tests use explicit fixture process separation to run on
restricted development hosts. Their records identify that narrower scope and
are rejected by the strict qualification validator. They also verify that
ordinary provider workers cannot inject these deaths, that missing deaths
fail, and that a host without namespace support never starts a fallback task.

## Limits

- These are trusted scripted reference edits, with **zero actual AI model
  runs, zero provider requests and no receipts**. They qualify infrastructure;
  they do not measure model success, manual correction time, billing cost, or
  language productivity. Human effort and monetary cost remain unmeasured.
- This closes the previously missing per-task checkpoint-death exercise for
  the frozen five-task set. It does not qualify every possible application,
  instruction boundary, I/O failure, filesystem, or concurrent hostile writer.
- `os._exit` skips normal Python cleanup but does not simulate power loss,
  storage-controller failure, filesystem corruption, or a machine reboot.
  The checkpoints occur after the corresponding production fsync operations.
- Hash seals and recorded traces are reproducibility and consistency checks,
  not signatures, hardware attestation, or proof against a dishonest operator.
- Provider receipt accounting and provider-attempt failure policy are
  unchanged. The qualification neither resumes an interrupted paid model
  attempt nor retroactively labels one successful.
