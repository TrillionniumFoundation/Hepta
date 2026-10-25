# C import safety integration on `f593ef6`

This repair was prepared in an isolated worktree from root commit `f593ef6`.
The root worktree and its running release gate were not modified. The integrated
changes were transplanted as focused hunks from these upstream commits:

- `ba3758025a9e267885ed482f86cca778dbce09d0`: separate C tag/typedef namespaces
  and retain typedef const qualification at the correct pointer layer.
- `e0acefc51dcd884c182683f78435cef696309e12`: verify native prototype presence
  and type compatibility before the probe defines its own `main`.
- `d40f9b75ee6bbf4ce2d9634b3f28da6231f6cd80`: retain transitive raw-pointer
  obligations through HSIR nominal types.

The associated upstream regression tests and historical notes are retained.
Their historical full-suite counts apply to their stated upstream snapshots;
this integration has its own focused results below. No full release-gate pass
is claimed for this repair until the root reruns the gate on the new commit.

## Reproduced blockers and repair

The frozen root accepted this valid C header with a wrong generated ABI:

```c
typedef int Token;
struct Token { double x; };
Token inspect(Token value);
```

It generated a struct-valued `Token(Token)` binding. GCC confirmed that the real
declaration is `int(int)` and rejected the combined original/generated
prototypes. The repair emits `i32(i32)` while retaining the separate record.
`typedef const int Value` and `typedef int * const Value` also retain their
correct pointee qualification after expansion. No wrong-ABI call was executed.

An inactive guard could similarly invent a missing function or disguise a
conflicting native declaration:

```c
#ifndef _STDIO_H
#define _STDIO_H
int remove(int value);
#endif
```

The probe includes stdio first, where `remove` actually accepts `const char *`.
The frozen root still emitted `i32(i32)`. Native prototype assertions now reject
this input, and also reject functions absent behind a predefined `__STDC__`
guard. The assertion is deliberately placed before the probe's own `main`.

Integration review reproduced one remaining alias form after applying the
upstream prototype fix:

```c
#ifndef _STDIO_H
#define _STDIO_H
typedef int __gnuc_va_list;
int vprintf(const char *format, __gnuc_va_list args);
#endif
```

The original-spelling assertion compared the native `__gnuc_va_list` with itself,
while the parser generated an integer second argument. The real function takes
a va-list pointer on the tested host. The integration additionally checks each
simple typedef's native presence and compatibility with its parsed declarator.
Adding one pointer layer to that comparison preserves top-level const. Two
regressions cover this false acceptance and a typedef with no native declaration.
This is a rejection gate, not new preprocessor support.

## HSIR inventory and preserved behavior

`struct Wrapper { p: raw const u8 }` used as an `echo` parameter/return previously
produced an empty HSIR external-obligation list. The iterative nominal-field
walk now reports `raw_pointer_signature`. This is audit metadata completeness;
copying a raw pointer does not itself dereference it, and the omission was not
a demonstrated native safety-check bypass. All proof flags remain false.

The integration preserves the current borrowed-return metadata, captured import
manifest validation, and relative header relocation. It does not replace whole
files with older upstream versions. The only changed compiler modules are
`c_import.py` and `semantic_ir.py`.

## Focused closure evidence

Actual local runs on the integrated source passed **29 tests, zero skips**:

| Command scope | Count | Relevant executed behavior |
| --- | ---: | --- |
| `test_c_import*.py` | 15 | GCC native probes, qualifier/namespace rejection cases, original C functions linked and executed through the independent C backend with sanitization. |
| `test_semantic_ir*.py` | 12 | Nested/generic/array/recursive-pointer boundaries, raw-free controls, deterministic exports, no false proof flags. |
| Workspace `test_c_header_identity_survives_snapshot_relocation` | 1 | Captured relative header identity survives moving the snapshot and removing the original header; native Rust validation passes. |
| Cross-feature `test_imported_public_struct_crosses_module_and_real_c_abi_in_both_backends` | 1 | A real imported struct API links to original C and executes through both Rust and C backends. |

The exact test scopes, source hashes, reproduced before/after behavior and
tool paths are recorded in `evidence/c_import_safety/qualification.json`.
These observations close the listed defects on the recorded host. They do not
establish a complete C parser, arbitrary ABI support, foreign implementation
safety or language soundness.
