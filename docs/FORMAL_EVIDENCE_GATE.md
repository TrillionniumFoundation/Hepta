# Abstract-core proof evidence gate

`tools/verify_formal.py` qualifies the small model in
`formal/HeptaCore.lean`. Its current receipt is `hepta.formal.v2`.
The mathematical core is unchanged by this gate update. Eleven named theorems
cover abstract resource states, group admission/channel occupancy and a
wrapping-u64 expression-to-stack lowering model. They are not a proof of the
production language or compiler.

## Why the evidence gate changed

The previous producer accepted a version-looking string, counted theorem
reports derived from the input, and accepted a nonzero exit containing
`error:` for each negative control. A local counterfeit executable was actually
run against that producer: it printed the expected version, eleven fabricated
axiom reports and two generic errors. The old producer returned `passed`
without executing Lean. This was a qualification defect, not a counterexample
to one of the mathematical theorems.

The v2 producer checks the executable against the committed toolchain lock
**before executing even its version command**. The same counterfeit now fails
before its marker file can be created. Release qualification must also call
`tools.verify_formal.validate_report(evidence)`; merely counting eleven theorem
keys and two mutation rows is insufficient.

## Inputs and observations retained

| Evidence | Required check |
| --- | --- |
| Lean executable | SHA-256 matches `formal/toolchain-lock.json` before execution; rechecked around proof invocations |
| Version command | Actual integer-zero exit, exact pinned-version output profile, empty stderr |
| Source and lock | Current file bytes bound by hashes and checked for changes during qualification |
| Actual proof input | Hash of the source plus the dependency-print commands actually sent to Lean; temporary file checked again after execution |
| Theorem inventory | The eleven reviewed names, each declared once and each reported once |
| Positive command | Actual integer-zero exit; stdout and stderr retained separately and combined deterministically; output and hash agree |
| Dependencies | Reports agree with the retained output; only `propext`, `Quot.sound` and `Classical.choice` are permitted |
| Negative commands | Exact mutated source and complete checked-input hashes, actual integer-one exits, full streams and a failed intended theorem |
| Claims | Exact narrow scope and explicit false claims for production compiler refinement, whole-language soundness, FFI/hardware and bounded cancellation |

The source currently contains four dependency-print commands. The producer
appends only the missing seven. Duplicate dependency reports are errors rather
than entries that can silently overwrite each other in a dictionary.

The input profile rejects placeholder proofs, unreviewed top-level commands,
checker options and extra imports. The actual Lean invocation and dependency
audit remain the proof authority; the profile is not a new Lean parser or a
proof checker. The imported standard library and runtime remain trusted.

An exit code of zero alone is not a proof. A regression runs the pinned Lean
on an actual `by sorry` declaration: Lean returns zero but reports `sorryAx`.
The positive gate rejects such output, including an error or placeholder
warning appearing only in stderr.

## Negative controls must reach the intended claim

| Guard mutation | Required invalidated theorem |
| --- | --- |
| Permit release while readers remain | `Hepta.no_release_with_readers` |
| Remove the task-admission bound | `Hepta.exhausted_tasks_reject_admission` |

For each control, the exact reviewed replacement site must occur once. Lean
must return a proof error and report `sorryAx` in the intended theorem's
dependencies after failed elaboration. A killed process, boolean in place of
an exit code, unrelated input error, missing dependency report or duplicated
control does not qualify as the expected rejection. The negative receipt
does not treat a failed theorem as a valid proof; it records that removing the
guard breaks the claim the guard is meant to support.

## Reproduce

Use the pinned Linux Lean 4.19.0 installation identified by the committed lock.
From the repository root, with `LEAN` set to that installation's executable:

```sh
python tools/verify_formal.py --lean "$LEAN" --output artifacts/formal-validation.json
python tools/verify_memory.py --lean "$LEAN" --output artifacts/memory-validation.json
python -m unittest tests.test_formal_verifier -v
```

The native test class reports a skip if no Lean installation is available.
A skipped native class is not proof qualification. The verification below used
the pinned executable and executed the complete class without skips.

### Observed on 2026-10-25

| Executed check | Observed result |
| --- | --- |
| Abstract-core producer | Passed; 11 named theorems and 2 intended guard rejections |
| Existing memory producer, unchanged | Passed; 19 theorems and 5 negative mutations |
| New formal regression suite | 20 tests passed in 8.296 seconds, no skips |

The regression suite includes real Lean runs followed by changes to the source
file or temporary checked file; both prevent receipt issuance. It also changes
the lock after an actual version probe, and changes a private copy of the
pinned executable after that executable's actual version probe. Both are
rejected before a proof can be credited. The installed shared toolchain is
never modified by these tests.

The observed core source SHA-256 was
`d3c3fb1e773cde932b5801684ddaffba2149dd565a67950a4c3b8623bca63423`;
the actual checked-text SHA-256 was
`0a8787298855964da23e36063b198fff9419218445c750e890e4f80a38b7b8fb`.
The executable SHA-256 was
`92c3d35b5bfaa5e0fea413a775d504cf46cd95e1345df61c2274f76779e7e023`.
These are observations from this run, not substitutes for rerunning the gate
on another candidate.

## Trust boundary and compatibility

`validate_report` checks the exact current inputs, scope, identities and retained
observations. It does not authenticate JSON produced by an arbitrary hostile
party, a compromised host, or a modified repository trust root. The pinned
executable still depends on its installed runtime and imported standard library.
This change does not establish cryptographic provenance for those components.

The v1 receipt lacks the actual checked-input identity, version probe, complete
negative streams and positive exit evidence required by v2. It cannot be made
valid by changing its schema label. A fresh run is required.

No correspondence theorem connects this core to the Python checker, source
resource lowering, resource IR, or the actual Rust/C/LLVM backends. Pointer
provenance, lifetimes, allocator behavior, foreign code, scheduling and hardware
remain outside this core. The separately executed memory model has its own
scope and receipt; adding its theorem count to this one does not prove the
production compiler sound.
