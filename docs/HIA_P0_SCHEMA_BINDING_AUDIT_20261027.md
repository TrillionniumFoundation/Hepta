# HIA P0: refuse hidden schema/profile rebinding

## Exact development boundary

- Base: PR #210, commit `cf36bd112070bdb77dd70d9566455d9657c862a4`.
- This is a **narrow P0 audit hardening**, not the introduction of another
  verifier, a new HIA dialect, or a claim that P0–P7 are closed.
- Existing owner: `tools/audit_hia_schema_collision.py`. The runtime executable
  admission authority remains `hepta.hia_program.verify_program`; the
  version registry remains `hepta.hia_schema`.

## Fixed false-negative classes

The audit previously parsed literal top-level `SCHEMA`/`PROFILE` assignments
but could return `no_profile_collision_detected_not_semantic_equivalence` after
a module contained a later conditional assignment, loop target, import alias,
exception/match binding, namespace redefinition, or dynamic `globals()`/`exec()` operation capable of replacing one of those names.

It now rejects noncanonical AST bindings, including nested stores/deletes and
common dynamic-reflection entry points, rather than claiming an audit of
a mutable semantic declaration. The unchanged default remains strict: a
literal source constant and its matching profile must both be present.

The separate `compare` boundary also validates exact inventory keys, SHA-256
hex shape, schema/profile entry structure, and unique declaration/schema
keys. Duplicate inventory rows can no longer be silently collapsed by the
comparison dictionary. A correctly shaped SHA-256 string is **not** proof that
the supplied JSON originated from the named source file.

## Tests and exact scope

```sh
python -m unittest tests.test_hia_schema_collision \
  tests.test_hia_schema_binding_audit -v
python -m unittest tests.test_hia_schema_unification \
  tests.test_hia_core_upgrade -v
```

The self-contained AST/inventory logic and positive/negative controls were
exercised independently under CPython 3.13 (4 isolated test methods passed).
This was **not** execution of the exact new Git tree's complete Hepta suite:
the local environment cannot resolve GitHub for a full checkout. The
committed regression module must run with the pinned complete repository.

This syntactic audit is deliberately not a trusted-runtime evaluator. It
does not prove the absence of arbitrary dynamic Python module mutation,
that distinct source producers are semantically equivalent, or that an
HIA ABI/backend or C/C++ migration is safe. Neither `safe_to_merge` nor
`whole_project_blockers_closed` becomes true as a result.

## Next P0–P7 dependencies

P0 still requires all producer/consumer wire adapters (especially the
historical HSIR collisions) to be reconciled against exact source blobs.
P1 remains general Provenance/Memory SSA plus complete ownership effects.
P2 requires executable Core-to-Rust/LLVM refinement and error-path
differential; P3/P4 need live ABI and full C/C++ L2–L3 migration evidence.
P5 remains actual held-out model A/B with cost/error controls.
P6 still requires physical hardware and stable representative performance.
P7 requires machine-checked scoped refinement and production qualification.
CI queueing does not change these semantic acceptance conditions.

## 2026-10-27 P0: reflection-helper alias hardening

A standalone CPython 3.13 AST control exposed a fail-open case:
`from builtins import globals as g; g()["SCHEMA"] = ...` bypassed the
old bare-name-call guard while potentially mutating the declared schema.
The new static audit conservatively rejects AST references to common
reflection helpers, qualified attributes and imported aliases, including
an alias stored before later indirect invocation.

Six in-repository negative patterns cover imported `globals`, `exec`,
qualified `builtins.exec`, a stored `globals`, aliased `getattr` and
renamed `__import__`. It is intentional that benign uses of these
reflection helpers may now reject; the tool is a fail-closed inventory
audit, not a general Python runtime verifier or a promise that arbitrary
dynamic mutation is impossible.

An independent local AST model passed four selected controls. The exact
full-Hepta parser, Cargo/native tests and complete source checkout have
NOT been executed in this container. No P0–P7 production gate was
implicitly promoted: `whole_project_blockers_closed=false`.


## Follow-up P0: pinned-descriptor source reading on v7 convergence

- Parent: PR #286 exact `c6c38cccf57e62c76cbad1ad64323b99c0dd56c2`. Donor: PR #287 exact `a8762b6f67dce9ae2ac5a7da1963cb307909c1cb`.
- Review confirmed the existing v7 recipient retains alias-sensitive reflection
  refusal and strict inventory comparison. The donor descriptor-backed `_read`
  implementation is integrated without replacing these protections.
- Source reading now requires `O_NOFOLLOW`, opens a single bounded ordinary
  file descriptor, and checks `lstat`/descriptor `fstat` identity both before
  and after consumption. A final path read never follows a substituted symlink.
- Two unchanged donor regression methods exercise positive no-reopen/symlink
  refusal and an inode swap between initial stat and descriptor open. All
  existing alias rebinding / duplicate schema negative controls are preserved.
- Exact new branch regression plan:

```sh
python -m unittest tests.test_hia_schema_collision tests.test_hia_schema_binding_audit -v
python -m unittest tests.test_hia_schema_unification tests.test_hia_core_upgrade -v
```

**Evidence limit:** SHA/Blob review and committed regression construction are
not full in-checkout execution of those tests; Cargo/native/GPU/hardware and
whole P0–P7 qualification remain OPEN. A pinned regular file is not a proof
of the compiler/runtime or a defense against all malicious same-user writes.
`whole_project_blockers_closed=false`.

## 2026-10-27 follow-up: prevent blocked named-pipe descriptor admission

The audited P0 source-reader originally used `lstat → os.open(O_NOFOLLOW) →
fstat`. `O_NOFOLLOW` prevents following a final symlink but does not stop
`os.open` from blocking on a FIFO substituted after `lstat`. A deliberately
constructed Linux child process stayed blocked when `open` lacked
`O_NONBLOCK`, whereas the same FIFO opened immediately with the flag.

The existing `_read` now requires POSIX `O_NONBLOCK` alongside `O_NOFOLLOW`;
only a descriptor verified as the original bounded ordinary inode is ever read.
The new adversarial test swaps the regular source for a FIFO in the
`os.open` hook, checks the flags **before** opening (regressions fail rather
than hang), and requires an inode mismatch rejection. The original audit
reflection/inventory checks and no-reopen controls are unchanged.

This is a fail-closed **source audit availability and TOCTOU** correction,
not a general sandbox, source-to-Core proof, or compiler security
certification. Local Linux FIFO open controls exercised the blocking/nonblocking
difference; complete exact-HEAD repository tests, Rust native and hardware
qualification have **not** been executed in this tool environment.

```sh
python -m unittest tests.test_hia_schema_binding_audit tests.test_hia_schema_collision -v
```

`whole_project_blockers_closed=false`.
