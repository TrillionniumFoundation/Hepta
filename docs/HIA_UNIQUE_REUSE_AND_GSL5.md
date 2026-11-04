# Closed C++ ownership and real GSL 5.0.1 upgrade

This change extends two bounded source translators. It does not admit arbitrary C++, pointer escape, user-supplied ownership annotations, or an unverified library binary.

## Reusable empty unique_ptr slots

The default `cpp20-direct-unique-byte-array-closed-reset-v1` boundary remains unchanged. Callers explicitly select `reusable_released_owners=True` to use `cpp20-direct-unique-byte-array-reusable-reset-v2`.

In the admitted source, `destination.reset(source.release())` transfers the allocation and leaves the C++ source object alive as an empty slot. Re-adopting an owner into that slot creates a fresh Hepta binding. The compiler never revives a consumed linear value, retains an escaping raw pointer, or treats an empty slot as readable storage. Capacity and initialization facts follow the currently owned allocation. Continuing branches must agree on ownership.

The authored fixture moves one allocation between two owners three times, writes while the correct owner holds it, exercises empty self-reset and adoption, and then tests ordinary return, early return, throwing status paths and allocation refusal. An independent chronological oracle records allocation identities and ordered free/refusal events. Each of two callback-weight variants has 2,211 fixed cases. The native HIA executable links no original C++ implementation.

Seven fresh Clang source controls cover the unchanged default refusal, escaping release results, reads of either empty owner, stale length facts after changed ownership, get-based self-adoption, and inconsistent continuing-branch ownership. A changed destructor order must fail the lifecycle differential; a missing drop must fail Core admission before publication.

The fixture is authored. It is not counted as an upstream library release or a formal proof of all accepted C++ semantics. Human engineering time is unknown, rather than zero. Translation, validation, build and measured execution costs remain separately recorded by the qualification tool.

## Exact upstream GSL bytes

The optional `--include-current-upstream` qualification adds Microsoft's GSL 5.0.1 to the retained 3.1.0 and 4.0.0 cases. The default historical protocol stays available unchanged.

- Upstream tag: https://github.com/microsoft/GSL/releases/tag/v5.0.1
- Exact commit: `fbd20b8e8c52cba04dbc869cc9068a7800a5665d`.
- `LICENSE` Git blob: `aa58667a3fd3784b0dfa11bf17f05f5e8dbd7d02`.
- `include/gsl/assert` Git blob: `daa1a75c3cc1bb7817efc8015fe9bff562e0553f`.
- `include/gsl/util` Git blob: `2ce264d21edb5a3626161aec4d3296b28ef6ac23`.

Complete selected headers and their MIT license are vendored byte-for-byte. The dependency closure, actual compiler, AST captures and immutable lock identify what was translated.

GSL 5 uses two callback constructors (`const F&` and `F&&`) in place of the previous by-value constructor, renames the two private fields, and list-initializes the final_action in its factory. The new closed `cpp20-real-gsl-final-action-reference-constructors-v4` profile translates all four selected class method bodies and all three selected factory instantiations. It binds member and parameter references to actual captured declarations; matching a field name alone is insufficient. Trivial callback copying, moving and the activation flag are checked explicitly.

The coverage denominator is this class specialization and its selected factories, not the complete GSL library. The callback and exception-status client remain authored. `std::move`, `std::exchange`, Clang's AST and the backend are still explicit trusted boundaries. The original three-body profile remains separately identified.

## Reproduce

Run from the clean committed source with explicit Clang 20 paths:

```sh
python -B tools/qualify_cpp_unique_reuse.py --workdir /new/reuse \
  --clang /fixed/clang --clangxx /fixed/clang++ --cc /fixed/gcc
python -B tools/qualify_cpp_unique_reuse.py --source-refusals-only \
  --workdir /new/reuse-refusals --clang /fixed/clang \
  --clangxx /fixed/clang++ --cc /fixed/gcc
python -B tools/qualify_cpp_gsl_final_action.py --include-current-upstream \
  --output /new/gsl-upgrade --clang /fixed/clang --cxx /fixed/g++ --cc /fixed/gcc
```

Retain every output directory, including failures. Passing a native finite differential is not a general source-to-Core refinement theorem.
