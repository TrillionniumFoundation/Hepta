# Source-derived const-reference GSL factory migration

The closed GSL migration profile now captures `gsl::finally` on a const
`GslCallback` lvalue in both pinned upstream releases. This is implemented in
the actual Clang AST lowering, not by linking the original factory or hiding
it behind an FFI wrapper. The generated migrated executable still links only
generated Hepta C and its independently compiled C caller.

## Two real source paths

| Upstream release | Captured template argument | Captured parameter | Actual factory body |
| --- | --- | --- | --- |
| GSL 3.1.0, `0f6dbc9e2915ef5c16830f3fa3565738de2a9230` | `GslCallback` | `const GslCallback &` | Direct trivial copy from its declared parameter |
| GSL 4.0.0, `a3534567187d2edc428efd3f13466ff75fe5805c` | `const GslCallback &` | `const GslCallback &` | `std::forward` of its declared parameter, followed by trivial copy into the unqualified owner |

Both return `gsl::final_action<GslCallback>` and execute one cleanup. The
generated adapter is `GslFinallyConstLvalue`. The importer checks the substituted
return/constructor types, exact parameter declaration identity, const/reference
template category and copy constructor. It records `direct_const_copy` or
`std_forward` in the source-bound lowering trace. Incorrect template categories
and references to unrelated parameters reject.

The compiler-owned probe captures the const path on both releases, retaining
raw ASTs and the complete standard-header dependency closure. The existing
nonconst-lvalue upgrade test remains: 3.1 rejects that source instantiation,
whereas 4.0 successfully lowers and runs it. Const-lvalue acceptance must not
be incorrectly described as another 4.0-only feature.

## Native signature and semantic evidence

`tools/qualify_cpp_gsl_final_action.py` checks the measured native Linux LP64
host against all three selected compiler targets. For every generated C
implementation, a separate C11 probe includes its actual definition and checks
the precise `u64(u64,u64,u32,u32)` export with `_Generic`. This detects return
width and argument signedness differences that an ELF symbol-name inventory
cannot detect.

Two negative controls change the real emitted export declaration and definition
while preserving `migrated_case`: one narrows its return to `u32`, the other
changes the third argument to `i32`. Both must fail the independent signature
assertion. Neither incompatible function is called. The previously existing
wrong-but-linear callback control is still compiled and run, and the independent
oracle must identify its incorrect result despite resource checks passing.

For each release the new const factory uses 416 input rows, including integer
boundaries and seeded random values. There are 164 distinct seed/tag pairs;
caller mode is ignored by this factory. Each row observes trace, cleanup count
and status through three separate real C ABI calls. Both original and migrated
implementations are checked against the independent scalar/event oracle.

The full qualifier covers six positive original/migrated pairs: two ordinary
release clients, the 4.0 nonconst factory, the two const factories and the
changed-source callback. With 416 rows per pair, this is 4,992 positive native
observation rows and 14,976 scalar C ABI calls. The wrong-but-linear control
has another 416 rows and 1,248 calls. Counts describe finite tests, not a proof
over all inputs or all ABI features.

```sh
HEPTA_CLANG=/path/to/clang-20 python -B -m unittest \
  tests.test_cpp_gsl_final_action tests.test_cpp_gsl_branching_callback -v
python -B tools/qualify_cpp_gsl_final_action.py \
  --clang /path/to/clang-20 --cxx g++ --cc gcc \
  --output /tmp/hepta-gsl-const-native
```

## Scope

The new C++ and Hepta observation clients are authored integration fixtures;
they are excluded from automatic translation counts. The new automatically
translated code is the real selected factory instantiation in each upstream
version. The callback remains trivial and synchronously bound to one state.
Arbitrary callback lifetimes, C++ exception ABI, public C++ class layout,
custom allocators and whole-library migration remain outside this profile.

The native comparison and compiler signature checks do not establish a full
translation-refinement theorem, universal resource safety, performance gains
or a labor-cost reduction. Full compiler/source hashes must remain stable
through each qualification run; a concurrent code edit invalidates that run
and requires fresh qualification after source freeze.
