# cpp2hepta v0: strict standalone C++20 migration

`python -m hepta migrate-cpp examples/interop/cpp_noexcept.cc --output /tmp/cpp_migrated.hepta`

This is an **L1 unqualified candidate**, not a general C++ compiler, drop-in ABI replacement or safety proof. The parser invokes real Clang++ C++20 AST and target macro probes, rejects every unsupported top-level declaration and every unsupported body node. No source fragments are forwarded directly to native backends. Current accepted subset: top-level distinct `noexcept int(int...)` free functions with **no default arguments or parameter attributes**, signed-int locals/expressions/conditions/loops whose AST supports the existing C subset lowering, and `auto` variables when Clang inferred ordinary `int` from an initializer. C++ method and class definitions, overloads, templates, namespaces, pointers, headers/macros, ordinary exception paths, external calls, constructors/destructors and STL are **rejected**.

`export "C"` emitted symbols **do not preserve C++ mangled ABI**. Code using the original C++ binary must keep an L0 bridge or rebuild callers against the new ABI. Input validity excludes C++ signed overflow and nonterminating exceptional behavior; Hepta's arithmetic checks may panic on inputs for which original C++ has undefined behavior. Successful translation does **not** set semantic equivalence or memory safety to passed. The JSON report has `cpp_abi_preserved=false`, `semantic_equivalence_proved=false`, and `native_hepta_validation=not_run`. Perform real Hepta native checks, differential testing with independently compiled C++ program and platform ABI checks before upgrading to any verified migration tier.

The Clang subprocess timeout and AST size limits are not an OS sandbox; untrusted C++ input requires true process isolation. Target writes never overwrite existing files and use same-directory temporary files plus atomic hardlink publication. The original source is rechecked before publishing.

Checks:

```sh
python -m unittest discover -s tests -p 'test_cpp2hepta.py' -v
python -m hepta migrate-cpp examples/interop/cpp_noexcept.cc --output /tmp/cpp_migrated.hepta
python -m hepta check /tmp/cpp_migrated.hepta
```

The last native validation depends on the pinned rustc and must be run separately. This prototype does **not** close full P5, which requires genuine C++ class/template/RAII/STL migration and end-to-end evidence.
