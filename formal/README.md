# Checked abstract core and cross-execution tools

## Allocation identity and typed expression core

`HeptaMemory.lean` adds 19 kernel-checked theorems. Its explicit memory model
distinguishes allocation identity, generation and offset, rejects stale or
retired pointers, forbids nonempty one-past reads, narrows view ranges without
gaining write permission, and preserves pairwise loan compatibility on admission.
Its separate closed expression model proves canonical forms, small-step type
preservation, progress, trace preservation and the absence of a stuck reachable
well-typed expression.

```sh
python tools/verify_memory.py --output artifacts/memory-proofs.json
```

This checker verifies the pinned Lean executable SHA-256, inventories every
theorem's standard axiom dependencies and requires five rejected mutations:
removing allocation identity, generation or extent checks, granting write
permission to a read-only view, and making addition return a Boolean. The
kernel diagnostics for each broken variant are retained.

The memory definitions use mathematical natural numbers and explicit abstract
identities; actual allocator identity freshness, generation overflow, machine
pointer representation, initialization, alignment, FFI and concurrent runtime
implementation are not established. Allocation records are supplied assumptions;
there is no global freshness or pointer unforgeability theorem. Pairwise view
compatibility does not establish the validity or liveness of each admitted
view. The expression core has wrapping words,
Booleans, addition, equality and conditionals; it is not the complete production
Hepta type system or checked-panic arithmetic semantics. No correspondence from
the Python frontend, IR or native backends to either definition is proved.

## Earlier abstract resource and lowering core

`HeptaCore.lean` contains 11 kernel-checked theorems about three explicit models:

1. Loan-count resource state transitions preserve live/borrow consistency;
   borrowed resources cannot be released, released resources cannot be borrowed,
   and a successful release cannot be repeated.
2. Task-group admission and channel occupancy transitions preserve their stated
   task/input-byte/queue-slot bounds.
3. A structural translation from wrapping-u64 expressions to a stack machine
   preserves the evaluated value for every expression and initial stack.

`tools/verify_formal.py` checks every theorem's axiom dependencies and rejects
placeholder/custom axioms. The reported dependencies are standard `propext`
and `Quot.sound`. Two negative mutations remove a resource guard and a task
budget guard; Lean must reject the resulting broken proofs.

## Scope

The model abstracts individual loan identities and lifetimes to a count. It
does not model pointers, provenance, the actual AST/checker, Rust/GCC lowering,
FFI, the allocator, physical hardware, scheduling, panic recovery or termination.
The stack translation is defined in this proof file; it is not a proof that
`emit_rust` or `emit_c` preserves semantics. Establishing those refinements is
remaining work. Passing these proofs must never set the compiler's
`whole_language_soundness_proved` claim to true.

## Reproduce

The pinned proof checker is [Lean 4.19.0](https://lean-lang.org/doc/reference/latest/releases/v4.19.0/).
The optional installer downloads its official release, verifies the archived
SHA-256, and selects the transitive modules listed in `proof-dependencies.txt`.
It also installs the SHA-pinned Ubuntu AArch64 QEMU user emulator. It does not
change system directories or shell configuration.

```sh
python tools/bootstrap_verification.py
python tools/verify_formal.py
python tools/validate_cross.py
```

The Lean installer requires the optional Python `zstandard` package; extracting
the QEMU package requires `dpkg-deb`. These are verification dependencies, not
runtime dependencies of Hepta programs or the compiler frontend. Existing Lean
and QEMU executables can instead be supplied using `--lean` and `--qemu`.

`artifacts/formal-validation.json` binds the source and actual Lean executable.
`artifacts/cross-execution.json` records AArch64 execution under QEMU, including
a deliberately wrong sum implementation that must fail. This is ISA execution
under emulation, not physical-board or independently compiled foreign-C ABI
qualification. The syscall harness is a Rust `no_std` program with valid arrays
and explicit C-ABI calls into the Hepta library.
