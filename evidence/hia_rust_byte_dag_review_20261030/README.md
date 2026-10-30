# Independent read-only review of raw byte-DAG admission

## Outcome and exact candidate

No blocking defect was found in the reviewed change and the targeted probes.
This is a scoped implementation review, not a whole-language soundness proof
or qualification of a later integration head.

The reviewed source HEAD was
`5622ab545256d21b9301caea0858185c52650578`, with parent
`76678b1ab86366948c04ca454497aa0a80a5f055`. The reviewer did not modify the
candidate worktree. The Rust executable was built in a separate target directory
with Rust 1.90.0 and the locked offline dependency cache. Its SHA-256 was:

`fe70881e322487bd49b2e19ad7319348de6993959eeb5e16b7e921f63a4c2ac4`

The executable was 19,164,808 bytes. It is identified here but is not packaged
in this evidence. `build.json` retains the actual Cargo output, invocation,
source hashes, compiler identity and post-build comparison of the complete
bound snapshot with the reviewed Git commit. The binding includes the nested
Rust byte-memory module and the Python transport/JSON preflight. The candidate
worktree remained clean after the probes.

The first independent build attempt used the default Cargo cache and failed
because `serde_json` was absent in offline mode. Its merged tool output and
invocation are retained separately. After selecting the already populated
locked cache, the independent build completed in 4.369616523 seconds. The probe
interval was 0.642611054 seconds. These are separate from P3 migration costs,
authoring time and the implementing agent's regression totals.

## Source inspection

The reviewed path uses `hepta/hia_rust_byte_dag.py`, generic helpers in
`hepta/hia_rust_crosscheck.py`, and `rust/hia-core-shadow/src/byte_dag.rs`.
There is no `hia_rust_transport.py` file in this candidate.

The Rust constructor decodes the original bytes, runs whole-module ownership,
loan, SSA, type/effect and CFG verification, audits every function's supported
primitive types/opcodes, rejects cyclic call/CFG graphs and checked-u64 bound
overflow, then compares all three static bounds for every function. Hidden
private functions do not bypass these checks. A private owned canonical byte
snapshot is the only input to the existing v4 execution path; no imported
receipt can construct admission, and the executor rechecks the same snapshot.

The Python entry handles bounded JSON representation, policy encoding, pinned
sealed executable transport, request identity and report consistency. It does
not call a Python semantic verifier, analyzer, normalizer or evaluator. In the
review probes, all six corresponding semantic modules were set unavailable
before importing the new API; the real Rust process still admitted and ran
valid inputs, preserved stopped resources, and rejected invalid inputs.

## Additional actual probes

| Category | Count | Observed boundary |
| --- | ---: | --- |
| Real Rust observations accepted through the pinned transport | 10 | Exact step limits 1/2/3/4; empty owner; object-size/heap/failure ordering; owner transfer followed by call-depth stop; original pretty-printed byte identity |
| Real Rust refusals | 6 | One-below values for each static metric; over-budget hidden function; hidden live owner; escaped duplicate JSON field |
| Deliberately altered response controls | 3 | Rehashed cross-input, cross-argument and cross-static-policy replies were rejected |

The third row is negative transport testing only. Those responses were altered
after obtaining a real report and are explicitly excluded from positive
execution evidence. These counts are not added to the implementing agent's
39 Python test methods or 109 Rust tests, and are not a model/productivity
experiment or a new Agent-study sample.

The step-prefix probes independently asserted the concrete ledger: stopping
before allocation has no owner; stopping before drop retains one owner and
three bytes; stopping after drop reports the actual free even though the final
return tick exceeds the budget. A call-depth stop after transferring an owner
retains that owner and its three bytes with no fabricated cleanup. Zero-sized
storage creates/drops a logical owner without consuming an allocation-failure
index. An oversized u64 allocation traps before heap/allocator work, while a
heap stop occurs before the allocation-attempt counter advances.

## Remaining authority and operational boundaries

The new authority belongs only to the explicit raw primitive byte-DAG Rust
interpreter mode. Source/nominal lowering and LLVM/native publication still use
their existing paths. Core bytes do not carry a proof of the source program's
meaning or a foreign ABI contract. Cycles, recursive chains and foreign code
remain outside this mode.

The static metrics count VM events, language allocation interactions and
logical synchronous frame depth. They do not bound total process RSS, JSON or
verifier allocations, native execution time or hardware latency. A stopped
program can retain a nonzero logical owner/loan ledger; the API states that
successful return or automatic cleanup is not guaranteed.

The selected executable, loader/libraries, kernel and caller transport remain
trusted. The byte pin and request digests prevent identity substitution within
that trust boundary. They do not make an attacker-selected executable correct,
or prove a self-consistent fabricated result after trusted transport is
replaced. The independent probes found no broader claim in the new contract.

## Retained evidence

`MANIFEST.json` binds the probe source, build log, initial environment failure
and complete probe receipts. `probes.json` retains the source input, exact
invocation, stdout/stderr/exit status and full execution report for each real
observation/refusal. `probe.py` contains the independent expectations.

The script records the reviewed machine's absolute artifact paths. To rerun on
another host, build that exact source with the declared toolchain and update a
new run's build receipt/paths; do not edit these historical receipts. The source
and original receipts remain available even after the temporary review target
directory is removed.
