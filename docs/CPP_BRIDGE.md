# C++ Bridge — narrow L0 interop prototype

Hepta's P4 bridge bootstrap is **not** a full C++ ABI implementation. It uses an actual Clang++ C++20 AST and accepts only translation units containing unoverloaded, defined, top-level `noexcept int f(int...)` free functions. No includes, macros, globals, classes, namespaces, templates, callbacks, overloaded functions, reference types, pointers or exception crossings are supported. The current tool assumes the target C and C++ compilers use 32-bit `int` and 8-bit bytes.

Parameter defaults and parameter attributes are rejected rather than silently dropped from generated C ABI signatures. The bridge generates an `extern "C" int hepta_cxx_NAME(...) noexcept` C++ wrapper that forwards to each eligible original function, plus a `bridge.h` compatible with C caller compilation. The original C++ function body is **not** translated or verified and must be built separately by the target C++ compiler. The wrapper and original must use a mutually compatible C++ ABI and exception specification; exceptions are not caught or converted. Violating a C++ `noexcept` promise may terminate the process. Ownership, destructors, object layout, foreign memory safety, and ABI suitability for other targets are **not established**.

## Usage

```sh
python -m hepta bridge-cpp examples/interop/cpp_noexcept.cc --output-dir /tmp/bridge
# writes /tmp/bridge/bridge.cc, bridge.h, manifest.json
clang++ -std=c++20 -c examples/interop/cpp_noexcept.cc -o original.o
clang++ -std=c++20 -c /tmp/bridge/bridge.cc -o bridge.o
gcc -std=c11 -c examples/interop/cpp_noexcept_consumer.c -I/tmp/bridge -o consumer.o
clang++ original.o bridge.o consumer.o -o consumer
./consumer
```

The output directory must not exist when the operation starts. On supported Linux hosts the three-file directory is published atomically after staging; other platforms reject this profile rather than publishing a partial bundle. The report contains exact source/bridge/header hashes, Clang++ identity, the selected symbols and negative claims, including `foreign_cpp_memory_safe=false`, `cpp_abi_qualified=false`, `exception_translation=not_implemented` and `status=candidate_unverified`. This **L0** bridge confers no safety certification on existing C++ objects or their code.

Run the implemented C/C++ runtime interoperability tests:

```sh
python -m unittest discover -s tests -p test_cpp_bridge.py -v
```

## Atomic bridge publication on Linux

The bridge CLI stages `bridge.cc`, `bridge.h`, and `manifest.json` in a
private sibling directory, synchronizes the individual files, then publishes
the completed directory via Linux `renameat2(RENAME_NOREPLACE)` relative to
an open parent directory descriptor. Publication is atomic and will never
replace an existing path (including a dangling symlink). Concurrent writers
cannot publish partial mixed bundles. A staging failure leaves the requested
destination absent and removes the private stage.

This profile **requires Linux `renameat2`**. Other platforms fail closed
with `E_CPP_BRIDGE_ATOMIC`; no unsafe fallback to ordinary `rename` is used.
Atomic visibility does not imply a durable power-loss transaction, and this
does not sandbox Clang or certify the foreign C++ code.

The generator also refuses a source symbol named `hepta_cxx_X` when the same
translation unit defines `X`. Without this guard, a second wrapper could
silently invoke the first `extern "C"` wrapper, compile and link successfully
but return the wrong result. Tests cover both exception modes.

## Opt-in exception containment (`catch_status`, experimental)

The default `noexcept_only` mode and its v0 wrapper ABI remain unchanged.
For a translation unit with ordinary `int f(int...)` free functions, including
functions that may throw, choose an explicit **different** C ABI:

```sh
python -m hepta bridge-cpp original.cc --exception-mode catch_status --output-dir /tmp/caught
```

Each wrapper uses the signature `int hepta_cxx_NAME(int args..., int *result_out)`:

- Return `0` on success and set `*result_out` to the original function result.
- Return `1` if any C++ exception escapes the called function; leave `*result_out` unchanged.
- Return `-1` for a null `result_out`; do not invoke the original C++ function.

Every wrapper has `noexcept` and catches with `catch (...)` **inside C++**.
The exception object/type/message is deliberately discarded: this is only a
lossy, opt-in status mapping, not a semantics-preserving C++ exception ABI.
C++ stack unwinding and destructors in the original function still execute,
provided the original is compiled with working exceptions and does not violate
`noexcept`, invoke `std::terminate`, or suffer undefined behavior.

The v1 manifest declares `exception_translation=status_without_exception_payload`
while continuing to assert `foreign_cpp_memory_safe=false`,
`cpp_abi_qualified=false` and `c_abi_qualified=false`. A C caller compiled with
GCC and an implementation/bridge compiled with Clang++ were executed at `-O0`
and `-O2`. The test covers thrown exceptions, unchanged out-parameters,
null-pointer refusal, and observable local RAII destructor execution. No claim
about cross-platform C++ ABI, general C++ safety or exceptions thrown through
callbacks is made. These wrappers are *not* directly callable through a
Hepta safe API without a separately validated pointer ownership contract.

## Blocking work for production P4/P5

1. Clang compilation databases, macro-expanded source graph, target ABI profiles, real-header import and function-pointer/callback retention contracts.
2. C++ object lifetime, constructor/destructor/RAII, moves, inheritance, virtual methods, templates, STL, exceptions, allocator identity, RTTI and symbol versioning.
3. External binary qualification with GCC/Clang/MSVC and Itanium/MSVC ABI targets, failure injection, hot reload and independent C/C++ linker/caller tests.
4. Only then can cpp2hepta begin L1/L2/L3 source migration with precise ownership/alias and behavior-preservation obligations.

Clang++ itself is not sandboxed by this prototype. Use an OS-level sandbox before feeding it untrusted third-party sources.
