# Isolated compile-only runner

`tools/diagnose_hia_deferred_guard_layout.py` implements COMPILE_ONLY_PLAN.md.
The runner/workflow is pending independent review. No real Clang20 run or target
execution has been performed for this transformation. Mock compiler tests are
orchestration checks, not native compilation evidence.

The successful path performs exactly 8 Clang `-c` invocations and 24 native-tool
commands. Git provenance queries, Python tests and CI package setup are outside
that count. `Executor` enforces both native-tool budgets before invoking a
subprocess. There is no linker, target-library load, native harness or execution
command. Emission uses the existing Core verifier and LLVM emitter; it does not
call production native admission/build APIs.

Both real fixtures are prepared before ANY native-tool invocation. The independent
checker reruns proofs on a detached copy; a second detached frozen proposal is
retained for emission. The reference is reconstructed through fresh proof
verification without calling the production `_admit` path. Candidate, source,
reference, proposal, emitter implementation, input, LLVM, exports and target
identities must agree. Both arms use the same production reduction maximum,
not the small maximum used to exercise both branches in unit tests.

The output directory must be new and outside the checkout. A clean source tree
is required. On a machine already equipped with the documented Clang20/binutils
and pinned solver profile, the reviewed command would be:

```sh
timeout 300s python -B tools/diagnose_hia_deferred_guard_layout.py \
  --clang /usr/bin/clang-20 --output /tmp/new-deferred-layout-evidence
```

This is a reproduction command, not a request to install software locally or to
run before review. The new CI workflow is read-only, exact-HEAD and hosted-only.
It is separate from production qualification and preserves the existing formal
gates. Its artifact upload step, if subsequently authorized and executed,
contains ONLY a safe detached staging snapshot of this run's allowlisted
artifacts and focused test/run logs (or a sanitized staging-refusal report). The previously
blocked #586 ZIPs are neither inputs nor included payloads.

## Payload and interpretation

- REGISTRATION.json: source/tool/checker identities, two workloads/arms, flags,
  budgets, proof/Core/LLVM hashes and complete prepared-artifact hashes.
- Per workload: frozen proposal, independent CHECK, fresh REFERENCE_PROOF,
  canonical Core for each arm, emitted LLVM and full LLVM identity metadata.
- Per arm: relocatable object, `.text` extraction, disassembly with relocations,
  symbol listing, shrink-wrap MIR trace and the corresponding trace object.
- RESULT.json: bounded raw command captures, object/text equality observations,
  counts, before/after identities, artifact inventory and failure information.
- CI test/run logs, with mock results explicitly distinguished from real Clang.

REGISTRATION, RESULT, arm identity metadata and observations deny native,
production, performance and quota authority. Compiler errors, capture limits,
source/tool/checker/input mutations, trace mismatches and budget exhaustion are
failures; no retry changes the experiment. Equal and unequal reference/candidate
objects are both neutral observations. Runner wall time is administrative cost,
never workload latency. The known VM step/quota counterexample is still valid.

The final inventory excludes RESULT itself to avoid a recursive hash. Final
identity and inventory errors mark failure. A killed process or lost machine may
leave a running/incomplete receipt; such evidence is never a completed result.
Archive retention does not itself confer correctness or qualification. Compiler
binary hashes are not a complete shared-library/OS lock.

## Upload boundary and residual trust

The raw result tree is NEVER passed to upload-artifact. Its link-following
behavior would otherwise make a failed compiler artifact symlink an unintended
upload of an external target. A separate standard-library helper snapshots only
an explicit list of this experiment's artifact names and its two log names.
It opens every directory component with O_NOFOLLOW, requires ordinary files
with exactly one hard link, checks inode/metadata stability around reads, and
bounds individual files to 256 MiB and the complete snapshot including logs to
512 MiB. Binary observations additionally use the existing 64 MiB size bound.
Runner inventory uses the same safe snapshot reader, not recursive link-following
hashes. Unexpected files, including unrelated ZIPs, are refused.

Only after the entire raw tree and both logs have passed checks are detached
bytes copied into a new, separately created staging directory. No symlinks or
original hard links are reproduced. Unsafe inputs produce only STAGING.json
with a fixed sanitized reason and exception type, not external contents,
target paths or hashes. If the source or a log is genuinely absent, the staging
manifest explicitly records that absence; a partial snapshot never qualifies
the experiment. Existing staging destinations are refused.

The workflow uploads only that new staging directory and only when the helper
has finished and emitted safe_to_upload=true. An interrupted helper or failed
staging write emits no upload flag. A clean staging refusal may upload its
sanitized report while the staging step fails. Nothing uploads the old #586
archives, original raw tree or original log paths.

This is an isolated, trusted hosted-runner boundary, not a hostile-OS sandbox.
Before/after implementation hashes do not defeat arbitrary concurrent ABA
replacement or an attacker controlling the process/filesystem. No untrusted
process is launched after staging. Staging hashes document copied bytes, not
native execution, general correctness, or production/performance authority.
