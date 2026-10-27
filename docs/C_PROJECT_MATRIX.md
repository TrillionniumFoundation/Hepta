# Separate native C build variants

The separate [contracted resource matrix](C_RESOURCE_MATRIX.md) now covers the
unchanged real Ring-Buffer module and a cross-unit caller using mutable record
and slice contracts. That route emits safe Hepta/Rust targets and keeps its
denominator separate from the standalone scalar HIA route described here.

`hepta.c_scalar_matrix.lower_c_project_matrix` uses the existing C project AST,
expression and statement translator to produce an independently checked HIA
program for every explicitly listed build. It adds build-matrix selection and
standalone emission; it does not add a second C language implementation.

The input is `hepta.build-matrix.v1`, the shared C/C++ matrix format, with
`"language": "c"`. Every command in the original compilation database must occur
in exactly one named variant. Each variant contains the same source-unit set,
with one command for each unit. Duplicate indices, overlapping variants, omitted
commands, repeated source units and inconsistent drivers reject. Original command
indices, compiler identity, build flags, macro state and compiler-discovered
dependencies are retained and replayed through `hepta.c-build-selection.v1`.

The admitted standalone profile has scalar integer/Boolean arguments and results,
locals, control flow and direct captured calls, as supported by the existing C
project translator. Externally visible scalar function names are preserved;
internal-linkage helpers receive generated private names. Record layouts,
pointer contracts and allocating implementations are rejected by this entry
point. The existing contracted C project migration remains a separate workflow.
Signed arithmetic equivalence remains restricted to defined source executions.
Inline declarations must explicitly use `static inline`. Other inline declarations,
including `extern inline` and an inline specifier appearing only on an earlier or
later redeclaration, reject with `E_C_MATRIX_INLINE`. A plain C99/C11/C17 inline
body need not provide an external definition; this adapter does not invent an
export or infer the full C inline-linkage rules. Inherited static linkage without
an explicit `static` on the inline declaration is also outside this finite profile.
This restriction applies only to standalone scalar matrix migration.

```bash
python tools/qualify_c_project_matrix.py \
  --workdir /tmp/hepta-c-build-matrix \
  --clang /usr/lib/llvm-20/bin/clang
```

The qualifier copies the complete module under `examples/c/project_variants`:
one macro-controlled local header and two source units, each compiled in two
configurations. It captures all four commands, translates both variants, and
checks each variant's 204 cases against an independent integer oracle. There are
408 interpreter results and 816 native results across the original C and HIA
libraries. Cross-unit calls execute under the original C scalar export names.
Each HIA target links only its own emitted object. Original C objects link only
into the reference library. The qualifier reads the actual defined function
symbols from every original C object and requires their union to equal both the
verified Core export list and the generated HIA object's defined function symbols.
Receipt validation rereads these objects; a declaration's storage-class spelling
alone is not treated as native export evidence. Five rejected partition/driver controls and all
invocation and output files are retained.

The JSON report is `qualification.json` in the new work directory and explicitly
identifies a **C** denominator. These observations are additional to the separate
C++ matrix experiment; they do not establish resource-contract correctness,
arbitrary C support, unlisted configuration coverage or a translation theorem.
