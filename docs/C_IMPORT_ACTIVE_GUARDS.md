# Reject inactive declarations behind an already-defined include guard

Stacked on PR #13 (`84ae11e2fb6611bcdb97e7319bbaca3a3e0d1a2e`).

## Reproduced record-only mismatch

A compiler configured with `-include actual.h` sees a guarded declaration of
`struct Packet { int value; double weight; };`. A second header reuses that guard
but lexically contains `struct Packet { double value; };`. C correctly skips the
second declaration, while the importer's subset parser previously discarded the
guard and generated a one-field `f64` record. The native probe found the existing
record and reported its facts without checking that the lexical declaration was
active.

The recorded GCC host reported original size 16 and field size 4; the generated
C header from the actual imported Hepta described a size-8 record with a double
field. Compile-only assertions verified different field types, different record
sizes, and the original field order. No call across this mismatched ABI was
executed. A system-header guard collision independently reproduces the same
class of failure. Matching size alone would not establish layout equivalence.

An independent review also found that a header could define its own guard before
its `#ifndef`, making the declaration inactive even though the guard was absent
before including the file.

## Minimal fail-closed repair

The subset already rejects general conditional preprocessing. Retain its one
supported include-guard identifier, and:

- Reject a guard already defined earlier in the same header's parsed macros.
- In the actual native probe translation unit, after standard includes and before
  the original header, reject a predefined guard when the parser found any
  records, aliases, prototypes or constant macros.
- Preserve a genuinely empty guarded header even if the guard is already set.

This prevents treating these skipped declarations as bindings rather than
attempting to implement preprocessing or infer a record layout. Ordinary active
headers, padded records, and record-only imports remain supported. This is a
conservative import boundary, not a general proof of record ABI equivalence,
foreign implementation correctness, ownership or arbitrary preprocessing.

## Validation

Five focused regressions include the configured preinclude collision, hidden
alias, same-header predefinition, ordinary padded record, and empty header.
Three rejection tests failed before repair; all five pass afterwards. The full
C-import suite has 18 passing tests. Static mismatch evidence used GCC 14.2;
compiler-specific facts are limited to the recorded native host.

The full local suite passed 447 tests with zero skips in 37.888 seconds, using
Python 3.12.14, Clang 19.1.7, GCC 14.2 and pinned Rust 1.90.0. `git diff --check`
passed. No remote CI was queried; earlier source-bound release evidence was
preserved and is not claimed for this new head.

Independent review found no blocking issue. All five new tests passed again;
26 extra native-probe cases covered record/alias/prototype/macro contents,
pragma/include prefixes, ordinary unclaimed guards, externally defined guards,
and same-header prior definitions. These checks do not expand conditional
preprocessing support or prove universal layout compatibility.
