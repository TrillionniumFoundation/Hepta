# C++ Bridge — narrow L0 interop prototype

Hepta's P4 bridge bootstrap is **not** a full C++ ABI implementation. It uses an actual Clang++ C++20 AST and accepts only translation units containing unoverloaded, defined, top-level `noexcept int f(int...)` free functions. No includes, macros, globals, classes, namespaces, templates, callbacks, overloaded functions, reference types, pointers or exception crossings are supported. The current tool assumes the target C and C++ compilers use 32-bit `int` and 8-bit bytes.

The bridge generates an `extern "C" int hepta_cxx_NAME(...) noexcept` C++ wrapper that forwards to each eligible original function, plus a `bridge.h` compatible with C caller compilation. The original C++ function body is **not** translated or verified and must be built separately by the target C++ compiler. The wrapper and original must use a mutually compatible C++ ABI and exception specification; exceptions are not caught or converted. Violating a C++ `noexcept` promise may terminate the process. Ownership, destructors, object layout, foreign memory safety, and ABI suitability for other targets are **not established**.

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

The output directory must not exist when the operation starts. Files in this directory are not published as a multi-file atomic transaction; callers must not consume it until the CLI exits successfully. The report contains exact source/bridge/header hashes, Clang++ identity, the selected symbols and negative claims, including `foreign_cpp_memory_safe=false`, `cpp_abi_qualified=false`, `exception_translation=not_implemented` and `status=candidate_unverified`. This **L0** bridge confers no safety certification on existing C++ objects or their code.

Run the implemented C/C++ runtime interoperability tests:

```sh
python -m unittest discover -s tests -p test_cpp_bridge.py -v
```

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
