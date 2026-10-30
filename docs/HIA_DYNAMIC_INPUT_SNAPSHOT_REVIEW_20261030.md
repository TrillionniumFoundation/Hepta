# Dynamic input capture regression, 2026-10-30

Three caller-container races are closed before dynamic native execution:
scalar call arguments, initial owned state cells, and the outer committed-work
queue. The change is small but addresses real checking/usage and resource-limit
gaps. It does not introduce general effectful hot replacement or a proof of the
whole runtime.

## Findings and changes

`AdaptiveRuntime._arguments` previously checked a mutable row and subsequently
converted that row to a tuple. A producer thread could change the row between
those actions. The original native path really accepted these later values:
with an intended `[7, 2]` call, replacing the first value with `2**64`, `-1` or
`True` produced `2`, `1` or `3`, respectively, instead of `9`. This is more than
a test-spy discrepancy: the retained counterexample executes the real admitted
Clang-built function through its original ctypes function pointer.

The dispatcher now captures at most the batch limit plus one row reference,
checks that captured size, and captures at most the known ABI arity plus one
value from each row. It validates exact built-in integer type and the u64 range
on the captured tuple and dispatches that same tuple. Boolean values and integer
subclasses retain their previous rejection behavior. The extra element makes
growth beyond a limit detectable without copying an arbitrarily grown list.

`OwnedAdaptiveRuntime.__init__` previously checked the initial list length and
then iterated the still-mutable list. Growing a one-cell list to 65,537 cells
after that check caused all those cells to be processed and native preparation
to run. The C owner allocator then rejected the size; the previous implementation
did **not** write outside a native owner. The missing guarantee was rejection
before the bounded Python capture and native preparation. The new code captures
at most 65,537 references, checks the actual captured count, and then validates
and uses only those captured cells.

`OwnedAdaptiveRuntime.submit_queue` similarly checked the outer list's 128-item
limit before traversing the mutable list. The retained original counterexample
grows one valid item to 129 items after the check, admits that queue and executes
129 real native transition steps. The fixed runtime executes just the one item
captured before that mutation. Growth before the bounded capture instead rejects
before publishing any queue. The total iteration budget remains a separate
constraint; it never substituted for the advertised 128-item limit.

Only the outer work-item sequence is frozen by the queue change. Each work item
continues to be checked and lowered to the existing immutable `_Work` record.
The changes do not promise a single atomic snapshot across all scalar rows or
all mutable work-item dictionaries. They guarantee bounded capture and that the
particular scalar values checked for an admitted operation are the values used.

## Independent regression evidence

The original dynamic source is retained byte-for-byte. The scalar dispatcher
blob is `1b30383c47fbc2f1d3e100aa012126c6436f6f41`, shared by both integration
inputs. The original stateful adapter is catalog-input blob
`fa310d69d1f5e6e9b52a17917358b363cd29724c`; the P0–P7 branch retains the common
base's earlier adapter. The complete test package was imported for both the
original and fixed runs. The original source was placed in an isolated package
snapshot; production methods were not replaced with synthetic implementations.

| Evidence | Original implementation | Fixed implementation |
| --- | --- | --- |
| Eight scalar boundary/wiring test methods using explicit Python call spies | Seven failure records, including scalar subtests | Eight pass |
| Six separate native integration test methods | Six failure records and one error; one effect-rejection method passes | Six pass |
| Combined full-package run | 14 methods, 13 failure records and one error, zero skips | 14 pass, zero failures/errors/skips |

Failure-record counts include subtests and must not be read as numbers of test
methods. Some negative controls distinguish earlier rejection or a stable input
capture contract rather than demonstrating an unsafe native memory operation.
In particular, the original owner-size overflow was rejected by the native
allocator, and mutation to a Boolean during initial-cell validation was rejected
by the scalar validator. The raw tracebacks retain these differences.

The native suite uses the real verifier, optimizer, Clang compiler, sealed
loader, function pointer, owner driver and committed queue path. A real producer
thread mutates only caller-owned containers; Python line tracing selects the
interleaving. It does not change validator results, checked local values, native
function pointers or native return values. The eight separate wiring tests
deliberately use Python call spies and are not presented as machine-code tests.

The native effect-rejection regression also checks a valid Core module with an
unused trapping helper. The owned adaptive profile rejects it before loading a
new version, while preserving the live owner and its admitted native mapping.
This supports the closed, total-scalar transition contract. It does not establish
support for arbitrary foreign effects, callbacks or exception unwinding.

The execution used Python 3.12.14, Clang 20.1.8 and pinned Z3 4.15.4 on Linux
x86-64. It used the approved local execution environment in which process IDs
and `/proc` refer to the same process; no production pinning or mapping check was
disabled to accommodate the sandbox's different PID view. Source hashes were
checked unchanged across each retained run.

## Existing native contracts rechecked

The existing native qualifiers were rerun rather than duplicating their tests.
Both report `ok: true`:

- The empty-state qualifier checks 131 baseline/candidate native input pairs and
  four concurrent workers with 65,536 calls each. Its eight controls include
  refusing retirement while calls are active, actual memfd write rejection,
  loaded-image identity after publication-path tampering, and refusal of forged
  or stale selection evidence. Final owned native releases completed.
- The owned-state qualifier checks borrowing, switching with a persistent
  owner, allocation refusal cleanup, active-call switch/close/borrow refusal,
  completed and partially cancelled queue replay refusal, and actual native
  cancellation. This run stopped after 1,445,023 committed steps, reported zero
  replayed steps, and ended with 17 allocations, 17 frees and zero live native
  allocations. These counts describe this run, not deterministic timing bounds.

The existing resource safety policy remains explicit: active calls and live
leases prevent incompatible switching or destruction; uncertain release
outcomes are not retried by numeric handle. Automatic profitable scalar version
selection is still unsupported. No broad performance claim is made from these
regressions or from the concurrently executed qualification checks.

## Reproduction and retained files

All raw logs, exact original source files, source manifests, the full-package
runner and the two native qualification reports are under
[`reports/hia-six-track-convergence-20261030/safety-dynamic`](../reports/hia-six-track-convergence-20261030/safety-dynamic).
The earlier boundary-only AST-extraction experiment is retained separately and
explicitly marks that it did not import the full package or execute native code.
It is superseded for integration evidence by the full-package runs above.

With Clang 20, pinned Z3 and a compatible Linux memfd environment, run:

```sh
python -m unittest tests.test_hia_adaptive_arguments tests.test_hia_adaptive_snapshot_native -v
python tools/qualify_hia_adaptive.py --clang /path/to/clang-20 --workdir /new/adaptive-directory
python tools/qualify_hia_stateful.py --clang /path/to/clang-20 --workdir /new/owned-directory
```

The separate [Rust merge review](HIA_RUST_INTEGRATION_REVIEW_20261030.md) records
121 passing tests for the exact locked Rust crate source. That is a different
admission/execution profile and does not turn the native Python-hosted runtime
checks into a whole-language proof.
