# Original C parameter type admission

C array parameters are adjusted to pointers in the function interface. That
adjustment does not erase evaluation of variable-length array bounds at entry
to a function definition. The C project migration path must inspect the
original parameter type before accepting a pointer/slice contract.

## Counterexample

```c
unsigned int probe(unsigned int n, const unsigned int data[++n]) {
    return n;
}
```

The previous project migration accepted this with a read-only slice contract
whose length was `n`. On commit `91225c023b3d61bd8b87bfbd16ac5990c3fb0a62`, an
actual Clang 20 reference returned **8** for `n = 7` and eight initialized
elements, while the generated native library returned **7**. The capture,
compiler identities, source, commands and native artifacts were retained in
the dedicated audit directory. This was an accepted defined-input semantic
mismatch, not an out-of-bounds C reference.

## Admission path

After the existing function signature and pointer contracts are checked, the
shared C collector checks original parameter types. This point also covers
record-view migration: its signature adapter may rewrite a record pointer to
a scalar record internally, but admission still uses the original declaration.
Scalar-only functions do not need this additional pointer/array probe.

1. Revalidate the unchanged build capture.
2. Use the captured compiler, ordered frontend flags, original lexical source
   operand and captured working directory to emit a serialized Clang AST.
3. Read that AST in a separate process using libclang from the selected
   installation. The reader does not reparse source under another driver.
4. Match every requested declaration to its JSON-AST identity: canonical file,
   source offset, name, complete function type, parameter count and parameter
   names in declaration order. Missing, duplicate and ambiguous bindings reject.
5. Obtain each original parameter type through `clang_getCursorType`.
   libclang restores `DecayedType` to its original type. Follow canonical types,
   pointers and array elements; variable arrays reject as `E_C_VLA_PARAMETER`.
   Any unmodeled type or exceeded traversal budget rejects as
   `E_C_ORIGINAL_TYPE`.
6. Revalidate AST/tool identities and the complete build capture before allowing
   emission to continue. Existing publication-time capture verification remains.

Ordinary pointers, fixed arrays and incomplete array parameter syntax remain
admitted under the existing pointer contracts. This does not infer new caller
obligations or turn an arbitrary C pointer into a proven safe reference.

## Identity and trust boundary

The build-capture schema is unchanged. A separate
`hepta.c-original-parameter-types.v1` receipt is included under
`source_type_admission` in project migration reports, including relevant
rejections. It records the capture digest, compilation unit, compiler identity,
reader binary hash/version, actual Clang argv/cwd, serialized-AST hash/size,
declaration/type observations and budgets.

The serialized AST is temporary and is removed after the probe. Its receipt
does not claim the binary AST was published as part of the migration bundle.
Reproduction requires the bound source/toolchain inputs; retained audit runs
may additionally preserve their own ASTs and native binaries.

Matching a version string is a compatibility check, not a proof that two
frontends are equivalent. The AST was produced by the selected captured Clang;
the independently hashed libclang must actually load it and agree with the
JSON declaration identities. Clang, its serialized AST implementation,
libclang's original-type reader and the host toolchain remain trusted
components. This is not a whole-compiler soundness proof or a general ABI
certificate. Clang 20.1.8 on the current Linux x86-64 host is the initial
execution profile; other installations need their own actual qualification.

No global library search or environment-selected libclang fallback occurs.
If the selected installation does not provide a compatible reader, pointer
parameter admission refuses with `E_C_ORIGINAL_TYPE` instead of assuming a
fixed original type.

## Process and input budgets

AST emission and AST reading are separate direct children of the existing
bounded capture runner. The emission wrapper replaces itself with Clang,
retaining the owned process group; there is no nested detached compiler group
that can outlive the outer timeout. Emission has a 35-second wall-time limit;
the reader has 30 seconds. Their stdin/stdout/stderr are separately bounded.

Serialized ASTs must be nonempty and at most 32,000,000 bytes before reading.
On POSIX, each subprocess also retains any stricter inherited resource limit
and caps address space at 2 GiB and file size at 32,000,000 bytes. Non-POSIX
hosts retain the runner's platform behavior and require separate qualification.
Declaration traversal is bounded at 100,000 nodes, parameter lists at 1,024,
and original-type traversal at depth 64. Exceeding a limit is a refusal.

## Regression coverage

`tests/test_c_parameter_types.py` contains actual original-native controls for
plain VLA entry effects, a source pragma suppressing `-Werror=vla`, a macro
bound and a `typeof`-hidden array. It checks rejection without publication.
Pointer, fixed-array and incomplete-array positives compare original and
generated native returns. It also covers record-view rewriting, lexical source
aliases, captured headers, post-probe dependency mutation, and missing,
duplicate, altered-command or unmodeled-type receipts.

The ordinary C project, record-view, configuration matrix and source-argument
regressions remain required. Test execution counts and source identities belong
to their retained run reports; the presence of a regression is not a pass.

## Primary implementation references

- [Clang 20 function-entry original type evaluation](https://github.com/llvm/llvm-project/blob/llvmorg-20.1.8/clang/lib/CodeGen/CodeGenFunction.cpp#L1326-L1342)
- [Clang VLA parameter regression](https://github.com/llvm/llvm-project/blob/llvmorg-20.1.8/clang/test/CodeGen/vla.c#L189-L193)
- [libclang original DecayedType handling](https://github.com/llvm/llvm-project/blob/llvmorg-20.1.8/clang/tools/libclang/CXType.cpp#L132-L174)
- [Clang C API declarations](https://github.com/llvm/llvm-project/blob/llvmorg-20.1.8/clang/include/clang-c/Index.h)
