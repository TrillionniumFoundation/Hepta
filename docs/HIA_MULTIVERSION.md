# Verified scalar native generations

`hepta.hia_multiversion` adds a finite Linux x86-64 lifecycle on top of the
existing standalone HIA verifier and direct LLVM shared-library builder. It
provides actual native calls, independently checked candidate admission,
immutable artifact generations, per-call leases and a retained baseline.

The scope is total, effect-free scalar code. This is not a general replacement
of running machine instructions or a protocol for migrating live heap objects.
No compiler backend refinement, whole-language soundness, cross-platform
runtime, performance gain or global optimization claim follows from admission.

## Admission and identity

The baseline and every candidate are re-read through `verify_program`. Public
`VerifiedProgram` instances and their hashes are not trusted without that
verification. Every function must be a public scalar entrypoint, have at most
16 parameters and exactly one scalar return. Supported scalars are `bool`,
signed/unsigned 8/16/32/64-bit integers and the 64-bit `isize`/`usize` host ABI.

The extra live-call profile permits wrapping add/subtract/multiply and casts,
bitwise and boolean operations, comparisons, select, constants and acyclic
branch/jump/return control flow. It rejects checked operations, traps,
allocation, borrowed or owned values, calls, recursive functions and cycles.
The limits are 16 functions, 64 blocks and 2,048 instructions per function.
These restrictions keep defined HIA traps or nontermination from crossing the
in-process `ctypes` boundary. Input arity and exact scalar ranges are checked
on a detached tuple before every native call; implicit `ctypes` coercion is not
the validation rule.

Before building a candidate, the runtime requires exactly the same scalar ABI
as its original baseline and calls
`hia_translation_validation.validate_translation` afresh for **every** export.
Every result must be `proved` and bind both exact canonical program hashes,
both input hashes, the function name and the exact schema/profile/scope. `unknown`, timeout, counterexample,
wrong scope and malformed results reject admission. There is no API accepting
a serialized proof receipt, `ok` flag or caller-provided native artifact.
Equivalence is always checked against the original baseline, so successive
optimizations do not accumulate unverified changes.

`build_program_native` builds a fresh real LLVM shared library. The lifecycle
recomputes the LLVM identity, reads the actual bounded ordinary output file,
compares its bytes with the build identities and independently inspects ELF
imports/exports. It then copies those exact bytes into a Linux `memfd`, installs
write/grow/shrink/further-seal prohibitions and reads the bytes back. The loader
opens that sealed descriptor. Subsequent changes to the disk copy cannot change
the loaded generation.

Before publication, native executions on deterministic boundary probes must
agree with the independent HIA interpreter. These observations cover the
actual compiled artifact and calling convention; they do not prove LLVM
refinement over all inputs. The translation proof covers the HIA function pair
in its declared model. LLVM, Clang/linker, dynamic loader, libc startup code,
Python, the kernel and hardware remain trusted. Sealing is immutability of
artifact bytes, not a sandbox against hostile Python code or a compromised
toolchain.

## API and lifecycle

```python
from hepta.hia_multiversion import ScalarMultiversionRuntime

with ScalarMultiversionRuntime(baseline, build_directory, clang="clang") as runtime:
    first = runtime.call("calculate", [17])
    published = runtime.publish(candidate)

    # All calls through this lease observe the same artifact generation.
    with runtime.lease() as pinned:
        value = pinned.call("calculate", [19])
        generation = pinned.info.generation
        epoch = pinned.selection_epoch

    runtime.rollback()  # Future calls use the retained immutable baseline.
    snapshot = runtime.snapshot()
```

`publish` serializes writers, but callers can continue using the current
generation while proof/build/probe work runs. The selected pointer changes
only after those gates complete. A failed gate leaves the selected generation
and selection epoch unchanged. Generation numbers may have gaps after rejected
candidates; the selection epoch advances only on an actual selection change.

A lease increments the chosen generation's retention count while holding the
selection lock. A concurrent publication changes future leases only. A retired
generation's native symbols, sealed descriptor and owned disk artifact remain
alive until its last lease closes. Closing a lease waits for calls using that
lease's lock. No raw native function pointer is returned by the public API.
The baseline is retained until the runtime closes, even when another generation
is selected. Rollback does not roll back already completed program effects;
the admitted profile has no such effects or cross-call state.

The default live artifact budget is eight generations, configurable between
two and 64. This includes the retained baseline, current generation and retired
generations still leased. Staging another artifact requires a spare slot;
leases are never invalidated to reclaim a slot. With a limit of two, rollback
and release of the current candidate may be needed before another publication.

`close` refuses new leases and publications immediately. Existing leases remain
usable until their owners close them; then native libraries and descriptors
are released. Use context managers for both runtime and leases. There is no
forced reclamation of abandoned leases. Copying a runtime or lease is rejected;
each lease has one close owner. Disk cleanup is limited to the
runtime's own inode/path, and failed cleanup is not permission to recursively
erase unrelated files. The protocol assumes cooperative access to its private
build directory; it does not defend against a malicious same-user process.

## Verification

Run with a real Clang 20+ and the translation validator's Z3 dependency:

```sh
HEPTA_CLANG=/absolute/path/to/clang python -m unittest tests.test_hia_multiversion -v
```

The tests execute actual baseline/candidate artifacts at unsigned and signed
boundaries, including narrow and boolean ABIs. They cover all-export validation,
wrong behavior, ABI drift, `unknown`/unbound proof results, corrupted compiled
bytes, sealing failure, rejection before pointer publication, immutable loaded
bytes after disk modification, concurrent publication with an old lease,
retirement after release, rollback, runtime close and live-generation budgets.
Native tests explicitly skip if Clang/Z3/Linux sealing prerequisites are absent;
such a skipped run is not native qualification.

`tools/qualify_hia_multiversion.py` performs a small actual native publication,
concurrent lease-retention, rejection and rollback campaign and emits a bounded
JSON record. It does not compare throughput or establish optimizer benefit.

## Remaining scope

Checked/trapping functions need an isolated execution contract before live
dispatch can support them. Resources and cross-call state need an explicit
state-transfer proof, object/layout epochs and a lifetime model that covers
external references. Persistent generation selection, crash recovery,
cross-process leases, remote authority and non-Linux runtimes are separate
work. NDU may propose which already-qualified generation should run; utility
cannot override this admission gate.
