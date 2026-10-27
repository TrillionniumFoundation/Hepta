# C/C++ captured optimization and PIC semantics

Base: `209fa298127adf41b24d128d0291dcb4a0649c73`.

The common compilation-database importer previously omitted accepted `-O*`,
`-fPIC` and `-fpic` options. These flags affect compiler-provided preprocessing
macros, so the recorded source tree could differ from the actual listed build.
Replaying the same incorrectly reduced flags did not detect this mismatch.

## Reproduced counterexample

The same source bytes and Clang 20.1.8 executable were used before and after the
fix. C uses the following function; C++ adds `extern "C"` and `noexcept`:

```c
unsigned probe(unsigned x) {
#ifdef __OPTIMIZE__
    return x + 1u;
#else
    return x + 2u;
#endif
}
```

The compilation database selects `-O2 -fPIC`. With input `7`, the observations
for **both C and C++** were:

| Importer | Original native | HIA interpreter | Standalone HIA native |
| --- | ---: | ---: | ---: |
| Frozen base importer | 8 | 9 | 9 |
| Corrected importer | 8 | 8 | 8 |

`before-after.json` records source/module/program hashes and the identical
native toolchain identity. The original objects were compiled under the actual
database options and linked separately. Each HIA target linked only its directly
generated HIA object. For the before run, only `hepta/c_project.py` was restored
byte-for-byte from the frozen base, then restored to the corrected source before
the after run. No compiler version or native verification gate was relaxed.

## Fix and executed regression gates

The importer and ABI macro probe now retain accepted semantic driver options in
their original order. The C matrix, C++ template and C++ matrix qualifiers no
longer append overriding optimization/PIC modes when compiling their reference
objects. Older captures that omitted these flags must be recaptured; rehashing
such a record does not authorize the missing semantic configuration.

All following tests passed without skips using `/usr/bin/python3`, Clang 20.1.8
and the selected Rust 1.90.0 toolchain where Rust compilation is required:

| Tests | Result | Scope |
| --- | --- | --- |
| `test_c_project_semantic_flags` | 4 passed | 12 flag sequences in each of C and C++: 24 original native, 24 interpreter and 24 standalone HIA native observations; original option ordering; active-header inventory rejection; resealed omission rejection; unsupported `-fwrapv` rejection |
| `test_c_project`, `test_cpp_project_hia`, `test_c_project_matrix` | 44 passed | Existing C resource/ABI cases, C++ concrete templates and 454 native result observations, C++ matrix and 816 native result observations, plus rejection and capture-replay controls |
| `test_c_scalar_matrix` | 6 passed | C matrix's 408 interpreter and 816 native result observations, export inventory and inline-declaration rejection |

Reproduction, with Clang 20+ and the selected Rust compiler on `PATH`:

```sh
python3 -m unittest discover -s tests -p test_c_project_semantic_flags.py -v
PYTHONPATH=tests python3 -m unittest -v \
  test_c_project test_cpp_project_hia test_c_project_matrix test_c_scalar_matrix
```

This closes the reproduced captured-build semantic mismatch. It does not expand
the admitted C/C++ source subsets, target ABI support or whole-language proof
claims.
