# `c2hepta` — bounded C11 Clang AST migration, first prototype

This migration tool is *not* a C source transpiler or a proof that an arbitrary C/C++ program can be made safe. It is the first compile-database-independent, strict subset stage in P3. A separate narrow C++ L0 bridge prototype now exists as `hepta bridge-cpp` (see [CPP_BRIDGE.md](CPP_BRIDGE.md)); full P4/P5 C++ semantics remain open. The tool uses the real Clang AST, not regular-expression replacements of source code. Input must be a standalone C11 file: headers, macros, globals, pointers and external functions are deliberately rejected.

## Accepted first profile

- C `int` return type and `int` value parameters and initialized locals; target Clang must report 32-bit C `int` and 8-bit bytes.
- Separate ordinary global C function definitions; no `main`, public names must be representable in Hepta.
- Integer literals, local value references, `+ - * / %`, comparison, logical operators, unary plus/minus/not, parentheses.
- `return`, local declarations, direct assignments, `+=/-=/*=` to locals, `++/--` as standalone statements, `if/else`, `while`, and the restricted `for (int i=...; condition; ++i)` profile without `break`/`continue`.
- Output is `export "C" fn ...` with an explicit checked-panic effect and no heap allocation/blocking/spawn clauses. This is a **candidate**, not a proof that the source program has those contracts beyond the supported subset.

Clang rejects syntactically invalid input before AST conversion. The migrator then checks each AST node; an unsupported node aborts the **entire** migration. Signed overflow and `INT_MIN / -1` are undefined in C; the generated Hepta path uses checked arithmetic and aborts. This preserves results for the C-defined subset but changes behavior on C-undefined inputs. C comparison expressions are C `int`, whereas their direct Hepta counterparts have `bool`; results of comparisons are accepted only in conditions, not integer returns or arithmetic. No implicit bool-to-int conversion is invented.

## Commands

```sh
python -m hepta migrate-c examples/interop/c11_small.c --clang clang --module c_migrated -o /tmp/c11_small.hepta
python -m hepta check /tmp/c11_small.hepta
python -m unittest discover -s tests -p 'test_c2hepta.py' -v
```

Output is refused when the destination exists or equals the input; the migration file is created exclusively. Its JSON report binds SHA-256 of source and emitted text, Clang version, accepted functions, target-profile assumptions, and mandatory *unverified* safety/equivalence/ABI/native-test state. Clang is run with a timeout and finite captured AST budget; these subprocess bounds **are not a sandbox**. Feed untrusted code to Clang only inside an externally enforced isolation environment. No build scripts, arbitrary Clang extensions, or preprocessors are run by the migrator.

## Mandatory next steps for a qualified conversion

1. Freeze the original compilation database, macro expansions, conditional branches, target ABI and source graph (currently unsupported). Add a conservative risk report for every pointer/array/global and foreign call.
2. For the accepted subset, compile native Hepta and compare against a separately compiled original C implementation over a preregistered valid domain and negative tests. Report timeouts/crashes and semantic divergences, not only passed cases.
3. Add ownership/alias/region inference, preserve C ABI/layout precisely and expose residual `unsafe` as an obligation. Only a proof or justified set of runtime safety checks can upgrade a migration to L2 or L3.
4. For real C++ programs, start with a C ABI bridge; handle exception/RAII/destructor and ABI rules before translating templates or class hierarchies. No C header import implies C++ ABI correctness.

### Classification policy

- **L0:** unchanged library through audited interop.
- **L1:** mechanized source candidate, unsafe/behavior obligations remain.
- **L2:** candidate with a validated memory-safe dynamic runtime for unsupported static properties.
- **L3:** memory safety established by static proofs, with separately validated behavioral contracts.

This tool produces only **L1**. It never claims automatic zero-cost or fully safe C/C++ migration.
