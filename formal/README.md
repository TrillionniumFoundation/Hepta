# Checked abstract core and cross-execution tools

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
