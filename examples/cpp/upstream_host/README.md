# Real upstream C++ reuse on actual native hosts

This profile extends the existing `examples/cpp/upgrade` nlohmann/json experiment
with a persistent Hepta caller and a portable C++ compiler driver. The complete
upstream 3.11.3 and 3.12.0 single headers and licenses are already retained in
`tests/fixtures/cpp_upgrade`; their exact upstream hashes remain unchanged.
The common adapter, contract and consumer are identical between versions.

The executed route is a native caller using the emitted C header, the actual
`.hepta` frontend and generated Rust object, the generated C++ bridge, and the
unchanged upstream JSON library. The library and the small authored adapter
remain C++. This is library reuse; it is not full C++ source translation or a
foreign memory-safety proof. C++ ABI details are contained behind the generated
C ABI and each compiler/host must independently run the qualifier.

```sh
python tools/qualify_cpp_upstream_host.py \
  --cxx g++ --cxx-family gcc --rustc /absolute/path/to/rustc \
  --expected-system Linux --expected-machine x86_64 \
  --output-directory /new/absolute/evidence-directory
```

The native matrix selects Linux x86-64 and AArch64 with GCC/Clang, macOS
AArch64 with Clang, and Windows x86-64 with Clang/MSVC. A matrix declaration is
not an execution result. Only a successful job with its original report,
source identity, commands and binary bytes qualifies that host. `clang-cl`
is explicitly rejected because its command-line driver is not the GNU-style
Clang contract. MSVC uses actual C++20 predefined macros, not a permissive help
exit policy, and all compilation/link/execution steps must exit successfully.

For each library version the profile executes the existing finite JSON input
corpus through a direct C++ route and the Hepta scoped route, then 32 persistent
owner lifetimes. It overwrites the caller input after parse, reads the retained
document, checks rejected mutations preserve the document, destroys the owner,
and rejects stale reads and duplicate destruction. Four threads make 1,024
actual serialized calls per version. A seven-call work request is cancelled
between calls after exactly three committed mutations; the retained state is
107 and no completed operation is replayed. This does not interrupt an active
foreign call, prove cancellation latency, or roll back foreign effects.

The generated registry intentionally has process lifetime. The harness primes
it and reports its retained ordinary allocations separately. Per-operation
`operator new/delete` deltas are checked against that baseline; they do not
cover arbitrary foreign `malloc`, custom allocators or prove zero process
memory usage. Exceptions caused by malformed input and invalid mutations are
checked here. The separate upgrade qualification's allocation-failure and
foreign `noexcept` termination observations remain unchanged; this profile
does not claim all out-of-memory failures are recoverable.

Required negative controls compile a real wrong scoped return and demand the
same native oracle rejects it, and change the declared C++ return type and
demand native signature validation fails before a bridge is published. The
signature refusal must record the actual `cpp_compile` phase, exact command,
nonzero exit, the generated source bound to the changed contract, and the
specific method-result static assertion in original bounded diagnostic bytes.
Launch, timeout/capture, compiler-identity probe and unrelated compilation
failures cannot satisfy that control. Raw CRLF bytes are retained separately
from normalized UTF-8 text. Compiler-family claims are checked against original
identity-probe process streams, not only a mutable inline report. Raw
process streams, generated Hepta/Rust/C++ source, objects and executables are
retained. `validate_report` re-reads their bytes and reconstructs the actual
Hepta/bridge source and link commands without rerunning a compiler or native
program. No measured runtime is promoted into a development-cost claim.
