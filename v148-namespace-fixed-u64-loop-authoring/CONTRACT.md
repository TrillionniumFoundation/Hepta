# Namespace word expansion candidate and R20 deadline analysis

Status: authored and statically checked only. No new generator, compiler, Native, VM, test, binder, product, or CI call. Original R20 remains 32 PASS / 3 FAIL. Neither this candidate nor either diagnostic closes those failures.

## The exact failures and different clocks

The complete original report is Git `037dd52b11f300e2cff029b1cbc2fee1f15c7191`. Its nested result supplies all 35 IDs in actual order and all three complete tracebacks. `ANALYSIS.json` retains them without rewriting their classification.

- `test_expired_evaluation_is_rejected_before_any_reference_or_native_runner` and `test_reference_loop_cannot_restart_or_overrun_frozen_context_deadline` both stop at `AgentToolCase.build_pair`, line 67, the first baseline `session.emit`. `_hia_emit_reference` performs all profile/context/program/receipt reads before `_remaining_ms(context)` is passed to `_compile`. `_compile_reference` rejects nonpositive remaining time with `E_HIA_BUDGET` / `codegen`, before emission. Neither failing method reaches its intended later evaluation/refusal checks. Their explicit frozen context limits remain 3000 ms total / 1000 ms native.
- `test_native_timeout_is_incomplete_terminated_and_not_adoptable` completes `build_pair`. Its stopwatch starts afterward and surrounds `session.evaluate`. The original `assertLess(..., 5)` fails with 6.1432236370000055 seconds. Its `max_native_wall_ms` is 1 ms; `Session.freeze` retains its default total budget of 600000 ms. This is not a third 3-second codegen expiry, nor proof that the 1-ms child deadline was raised. The subsequent report/termination/adoption assertions were not reached after the timing assertion failed.

`_hia_evaluate_reference` retains artifact/profile/receipt reads, reference execution, a separately owned native budget claim, and publication of measurements/cost-ledger/evaluation receipt. The 5-second test includes that enclosing request path; the native-child timeout alone is not the measured interval. There is no detailed phase profile of that formal 6.143-second call in the supplied evidence, so no exact split between those phases is asserted.

## What the existing observations do and do not establish

The separate instrumented expired-method run records 47 fresh scans between the actual stored context creation time and the first remaining-time check: 2,845,171,254 ns in fresh scans, 2,755,952,865 logical source bytes, and a first check at +3,542,386,194 ns. These are nested timings and must not be added together. This is a fresh-process diagnostic, not the formal 35-method ordering.

Across that entire diagnostic, all 1,341 `NamespaceState.call` invocations total 149,788,020 ns, including host work and instrumentation. Even eliminating this entire measured interval would be smaller than the diagnostic's 542,386,194 ns first-check overrun. This is a scope bound on the measured record, not an uninstrumented lower bound or a prediction for the formal job. The sparse native-entry samples are preserved as samples and are never multiplied into an alleged total.

The separate single-fresh observation took 270,752,930 ns, with instrumentation included and prior source guards warming filesystem cache. It made one `current_sources` call, 1,551 fresh reads over 58,637,295 bytes, and 1,823 protocol guards. Its 27 original ZIP members were decoded from the safe six-part recipe and independently rechecked for complete bytes, CRC, SHA, Git identity, and original ZIP modes. No unsafe signed-URL custody package was read.

## The only candidate change

`candidate/overlay/tools/generate_hia_artifact_namespace.py` changes only the HIA template functions `get`, `read_word`, and `set`. Each fixed loop runs its original body at i = 0,1,2,3,4,5,6,7 as eight explicit statements. Signatures, return values, all byte loads/stores, their order, and their original u64 multiply/add/shift expressions are unchanged. No bulk-memory primitive, word-load opcode, new host helper, cache, provider shortcut, bounds preflight, or HIA compiler change is introduced.

The source grows from 36025 to 36956 bytes. The original generated namespace asset is 50 functions / 1007 blocks / 3243 textual operations. No candidate assembly/image exists yet: actual generation counts, code size, elapsed time and fuel remain unknown. Increased source/image size is a real possible tradeoff, including a small increase in each full source hash.

The static proof reconstructs the candidate from the actual original loop AST and reverses the three exact byte hunks to the complete original generator. A first static authoring attempt parsed unsubstituted template placeholders and failed before creating the candidate; that script and failure record are retained. The corrected checker substitutes placeholders only in a private AST parse, not in the candidate bytes, and never invokes `source_program` or `document`.

## Equivalence boundary

On the same typed helper inputs, a normal return reads/writes the same eight byte positions in the same order and returns the same u64. Overflowing `index * 8 + i` and `index + i` retain the same wrap expressions. All shifts remain the original 0,8,...,56. A bounds trap occurs on the same first failing byte; `set` has the same successfully written prefix. No all-instruction-prefix equivalence is claimed for arbitrary fuel exhaustion or asynchronous native interruption: loop instructions disappear, so the PC and progress at such a boundary can change. Existing fuel limits are not raised; complete failure frames must be retained.

All other namespace source bodies, host owner code, state checksum, claim/ACK/reentry rules, request/budget owners, publication code, filesystem identity checks, original tests and fresh-source protocol remain byte-for-byte unchanged by this candidate. Exact full-span comparison is required; matching only status/output prefixes is insufficient.

## Fresh-source observable protocol that remains fixed

The exact R20 `tools/hia_selfhost_contract.py` is Git `fd474cb99412b5bbfe8402e4a121363c4a2f1e8b`. The local frozen3180 copy was different; the analysis uses the full Git-restored R20 body.

1. `current_sources` invokes `validate_contract`, which reads and JSON-decodes the declared contract before constructing the expected complete `support_contract`. The returned map is a new dictionary of the declared source entries, with a separate final contract read/hash. It is not the `file_digests` result object.
2. `file_digests` constructs `Path(root)` and checks the captured Path/I/O/hash protocol. Any noncanonical provider, root type or SOURCE_FILES representation takes the complete original expression.
3. The canonical route builds a new declared set, freshly enumerates `(root/'hepta').rglob('*.py')`, preserves each lexical name/fallback, unions and sorts the full path set. The observed 271 inventory candidates each incurred a guard. There is no surviving path inventory.
4. For each of the 1551 sorted paths, the dict-comprehension evaluates and captures `sha256` before evaluating `_source_lexical_read(...)`. Its lexical checks and the current mutable-provider guard occur before open. The exact CPython 3.14 route uses `_io.open(..., 'rb', buffering=0)`, one full `read()`, and context-manager close before returning the exact bytes to the already captured SHA callee; `hexdigest()` follows. A mid-open provider change must not silently replace that already captured callee, and subsequent files must see current providers. Exceptions and bytes reference/lifetime behavior are part of this boundary.
5. All 1823 guards (initial 1 + inventory 271 + read 1551) and all existing code/default/kwdefault/class-member/global-I/O checks remain. No digest/map/bytes memo, cross-effect batch, warmup, read skipping, provider replacement, or scan pruning is proposed.

There is no explicit held-descriptor/named-path stat comparison in `file_digests` itself. FileIO's underlying original behavior is retained. This must not be confused with the actual HIA publication protocol: `store_read_exact` first checks named metadata, opens the descriptor, checks descriptor-before, reads each chunk, checks descriptor-after, closes, then checks named-after. Policy gates compare the original inode/mode/size/mtime/ctime fields. The sealed executable path separately keeps full seals, `fstat`, and complete `pread` comparison. None of these other checks is removed or relocated.

## Why no fresh-path performance patch is currently offered

The evidence identifies fresh reading/hashing/guarding as the principal cost. It does not establish a faulty SHA backend or an equivalent faster implementation behind the same callable. Host-language tuple construction or port conversion cannot be called an improvement without measuring the original checks and preserving their effects. Moving the checks behind HIA ports would still require all current Python-provider reads and ordered file/hash effects; it may add dispatch cost. Replacing whole expected dictionaries with a digest changes validation/equality and allocation/exception behavior, while the measured non-fresh code-admission subtotal (144,837,206 ns in the diagnostic deadline interval) is already smaller than the overrun. Prior memo/unroll results are not revived.

The word candidate is therefore a concrete, falsifiable improvement attempt on the HIA execution path, not a demonstrated solution to the three deadlines. The original-case plan explicitly retains that distinction and all not-yet-executed gates.
