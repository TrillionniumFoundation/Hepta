# Guarded optimization: proof-to-native publication contract

## Correctness gap addressed

At baseline `192d2cbba7e49bde3b03af73685ecf96f6fb1b05`,
`build_guarded_native` checked the guarded Core proof and the hash reported for
the staged file, but did not compare the native receipt's Core, LLVM IR,
interface, target, or output identity with the proved candidate. A successful
compilation of different, independently valid Core could therefore be attached
to the original proof. Missing toolchain receipt data could raise an exception
only after the final output had already been published. An interruption inside
publication could also escape the previous withdrawal block.

`hia_guarded_native_binding.py` now implements the public guarded builder.
The guarded checker identity includes this helper. No accepted Core operation,
guard, loop invariant, ownership rule, or normal/trap behavior is widened.

## Admission and publication

1. Recheck the actual supplied proposal. A saved proof receipt is not accepted
   as a replacement for the proposal and its operations.
2. Freeze the proof and construct the original/fast guarded Core snapshot.
3. Independently regenerate its expected LLVM IR and exact export inventory.
4. Require the backend receipt to name that Core, original input identity, IR,
   implementation, profile, target, build kind, exports and staged pathname.
   JSON type equality is strict; a boolean cannot substitute for an integer.
5. Read actual staged bytes, check their digest and exact length, and require a
   complete compiler identity. Rehash the actual compiler file before and after
   final publication; recheck the solver, proof checker and backend identities.
6. Construct the complete returned receipt before creating the final pathname.
7. Include publication itself and post-publication checks inside withdrawal
   handling, including interruption exceptions. Withdraw only a link that still
   refers to this operation's staging inode; preserve another writer's replaced
   pathname.

The original optimizer's normal resource-operation ordering and guarded
fallback semantics are unchanged. This change binds their checked Core result
to the backend input and published artifact. It does not prove backend
refinement, arbitrary loop equivalence, complete resource soundness, compiler
provenance, immunity to later filesystem edits, or performance improvement.
The compiler, linker, loader, libc, host and their existing contracts remain
trusted. A consistent receipt from a malicious backend is not a machine-code
correctness proof.

## Verification

Run the isolated regression and native qualification command:

```sh
python tools/qualify_hia_guarded_native_binding.py --require-native \
  --output artifacts/guarded-native-binding/qualification.json
```

The boundary class deliberately injects a prover result and a compiler result.
It uses the real Core verifier, LLVM emitter, stable byte reader and hard-link
publication. Its payload is explicitly not native code. It tests wrong Core,
IR, target, interface and output receipts; malformed toolchain fields; byte
length/digest mutations; compiler drift; producer mutation; non-admission;
interrupted publication; and preservation of a competing writer's replacement.

The separate native class requires the pinned Z3 implementation and an actual
supported Clang driver. It compiles and runs an owned-buffer counted loop through
both guarded and original fallback paths. Its negative control actually compiles
a different valid Core program and requires that it cannot be published under
the original guarded proof. These tests are skipped when dependencies are absent;
the report records those skips separately and `--require-native` fails. A local
boundary-only success is never reported as completed native qualification.
