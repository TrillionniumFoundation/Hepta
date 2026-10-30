# Shared HIA semantic kernel

This increment starts from `192d2cbba7e49bde3b03af73685ecf96f6fb1b05`.
It keeps the 50 instructions and all existing primitive versions. It moves
production rules, rather than adding an independently maintained second checker.

`hepta/hia_semantic_kernel.py` now owns the ordered CFG successor relation,
parallel edge-value snapshots, owner/loan parent and conflict rules, exact
linear capability renaming at CFG edges, and resource-balanced normal returns.
The production checker delegates to those rules; both the VM and direct LLVM
emitter use the successor relation and parallel-binding helper. The VM also
uses the kernel's step, call-entry and allocation-admission order. The LLVM
runtime and VM share the 64-bit maximum object extent and 24-byte chain layout.

Failure as a value and cooperative cancellation remain ordinary control flow:
every returning path must discharge local resources. Traps retain the stopped
ledger and do not assert destructor cleanup. An evaluator budget stop is a
different outcome from a program trap or allocator refusal. A VM quota is not
an automatically enforced native RSS, stack, time or allocator-metadata limit.

The incremental policy advances to `closed-body-and-direct-callee-interface.v4`.
It binds the live kernel helper objects and code, actual resource sets,
Capability class/methods, and implementation contract. Existing caches cannot
survive a changed ownership rule. Optimizer, resource-contract, finite-context,
bounded-unroll, native lowering and x86 search identities include the new file.
The catalog includes the scope and source identity for discovery, while actual
program bytes are still reverified; catalog metadata does not grant admission.

## Verification

`tests/test_hia_semantic_kernel.py` exercises real production entrypoints:
parallel scalar swaps in a resource-carrying loop, cancellation and failure
returns, every finite fuel stop, heap admission before failure injection,
unexecuted unsafe CFG arms, parameter-origin renaming, interrupted resource
ledgers, atomic rejected returns, and live-rule cache invalidation.

Its separately gated native test compiles the actual Core to a native object,
links an independently compiled C allocator observer, and executes 30 child
process cases. It compares C ABI values, allocation attempts, live bytes and
peak payload bytes against the VM. Native assertions require actual Clang and
GCC; a dependency skip is recorded as native pending. The runner's
`--require-native` fails when that execution did not happen.

## Proof and trust boundary

This is a shared executable contract and finite conformance evidence, not a
full mechanized operational-semantics theorem. Most instruction execution and
LLVM code generation remain separate implementations. The existing selected
Lean and SMT proofs retain their exact scopes. Python, composite elaboration,
LLVM/Clang, the OS, allocator, hardware and admitted foreign wrappers remain
trusted boundaries. Native budget equivalence, arbitrary asynchronous
cancellation, general concurrent memory safety and whole-language soundness
are explicitly unproved.
