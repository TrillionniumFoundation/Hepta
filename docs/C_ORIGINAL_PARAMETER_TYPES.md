# Original C result and parameter type admission

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

The shared C collector uses one admission path before signature adaptation or
body emission. It first checks the actual physical spelling of each adjusted
pointer parameter, then captures the original result and parameter types for
**every project function declaration** in the compilation unit. Scalar-only
functions and header prototypes are included. The record-view adapter therefore
cannot erase the original type by rewriting a record pointer to scalar state.
One serialized AST and one reader receipt per compilation unit cover all its
function declarations; signatures reuse that receipt instead of probing again.

1. Bind the declaration name and range endpoints to the hash-bound physical
   source dependency, using Clang's global JSON location-file state. Display
   names from `#line`, `presumedFile` and `includedFrom` do not select bytes.
   Require the finite supported pointer/array source grammar; computed types,
   ambiguous macro locations and ranges crossing files refuse before rewriting.
2. Revalidate the unchanged build capture.
3. Use the captured compiler, ordered frontend flags, original lexical source
   operand and captured working directory to emit a serialized Clang AST.
4. Read that AST in a separate process using libclang from the selected
   installation. The reader does not reparse source under another driver.
5. Match every requested declaration to its JSON-AST identity: canonical file,
   source offset, name, complete function type, parameter count and parameter
   names in declaration order. Independently bind every parameter's physical
   name location and full source range to the serialized AST. Missing,
   duplicate, moved and ambiguous bindings reject.
6. Obtain the result type and each original parameter type from libclang.
   `clang_getCursorType` restores `DecayedType` to its original type. Retain
   original and canonical kind/spelling, qualifiers, pointee/element shape and
   fixed array extent. The complete function type binds the adjusted signature;
   original array types are deliberately not compared to an adjusted pointer
   spelling. Variable arrays reject as `E_C_VLA_PARAMETER`. An unmodeled type,
   inconsistent shape or exceeded traversal budget rejects as `E_C_ORIGINAL_TYPE`.
7. Revalidate AST/tool identities and the complete build capture before allowing
   emission to continue. Existing publication-time capture verification remains.

Ordinary direct pointers and the finite fixed/incomplete array spelling profile
are admitted under the existing pointer contracts. The array form needs a
bound original-type receipt with a fixed `ConstantArray` or `IncompleteArray`
shape. A lexical `[...]` suffix alone never establishes that its bound is
constant or effect-free. Fixed macro bounds are supported when their physical
parameter range remains unambiguous. `typeof`, pointer-token macros,
parenthesized declarators, `static`/qualified array suffixes and includes inside
a parameter list remain refused with `E_C_PARAMETER_DECLARATOR`. This does not
infer caller obligations or turn a foreign pointer into a proven safe reference.

## Identity and trust boundary

The build-capture schema is unchanged. A separate
`hepta.c-original-parameter-types.v2` receipt is included under
`source_type_admission` in project migration reports, including relevant
rejections. It records the capture digest, compilation unit, compiler identity,
reader binary hash/version, Python executable and reader-worker file identities,
actual Clang argv/cwd, serialized-AST hash/size, all function result/parameter
observations, physical parameter locations/ranges and budgets. Type shape
booleans and integer extents have exact JSON types; a boolean is not an extent.

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
If the selected installation does not provide a compatible reader, function
admission refuses with `E_C_ORIGINAL_TYPE` instead of assuming a fixed type.
`original_type_reader_identity(clang)` provides the same actual compiler,
reader, Python and worker identities without emitting a program AST. Its
bounded subprocess loads the selected library and calls `clang_getClangVersion`;
it does not invent a `--version` command for a shared library.

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
duplicate, altered-command or unmodeled-type receipts. Result-type coverage,
parameter file/offset/range substitution, boolean extents, contradictory VLA
shapes and changed Python/worker identities have explicit negative controls.

`tools/qualify_c_original_types.py --expected-head HEAD --output-directory OUT
--clang PATH --rustc PATH` requires an exact clean source commit and retains
before/after source and tool identities. Its 13 source cases run independently
at `-O0` and `-O2`: seven positive pointer/array/record/header forms and six
entry-effect/physical-location refusals. Four live, initialized input cases
per configuration give 104 original C values and 56 generated native values
when all 26 configurations pass. These are native observations, not additional
unit-test methods. Refused cases retain the original C's observed entry effect
and verify that no migration bundle was published. The tool records actual
automatic migration and elapsed time; human review time, model tokens and total
migration cost remain unmeasured. A run is evidence only when its retained
report, source identity and actual tool results agree.

The ordinary C project, record-view, configuration matrix and source-argument
regressions remain required. Test execution counts and source identities belong
to their retained run reports; the presence of a regression is not a pass.

## Primary implementation references

- [Clang 20 function-entry original type evaluation](https://github.com/llvm/llvm-project/blob/llvmorg-20.1.8/clang/lib/CodeGen/CodeGenFunction.cpp#L1326-L1342)
- [Clang VLA parameter regression](https://github.com/llvm/llvm-project/blob/llvmorg-20.1.8/clang/test/CodeGen/vla.c#L189-L193)
- [libclang original DecayedType handling](https://github.com/llvm/llvm-project/blob/llvmorg-20.1.8/clang/tools/libclang/CXType.cpp#L132-L174)
- [Clang C API declarations](https://github.com/llvm/llvm-project/blob/llvmorg-20.1.8/clang/include/clang-c/Index.h)
