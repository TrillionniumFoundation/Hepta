# Actual host ABI qualification

`tools/validate_native_host.py` links an actual native C driver to a Hepta/Rust
`no_std` object on the executing host. The driver calls Hepta exports, which
call independently compiled C implementations. Values return through both
ABIs; separate Rust size/alignment/offset probes are compared with C layout.

The deterministic matrix has 36 generated record shapes, 12 scalar types,
12 nested pointer forms, three values per shape and a call with ten integer
plus ten floating arguments followed by a record: 181 foreign calls per run.
Both unoptimized and optimized builds execute (`-O0`/`-O2` for GCC/Clang,
`/Od`/`/O2` for Microsoft `cl.exe`). A separate, actually compiled wrong C echo
must fail the same driver. Padding bytes are not compared and foreign lifetime
safety is not inferred.

## Compiler implementations and C11 type checks

`--cc-family gcc|clang|msvc` requires that implementation, checked using an
actual C11 preprocessor invocation. The default `auto` selects the `cl.exe`
driver by executable name, or the GNU-style driver otherwise, and then checks
the real family, version macros, target OS/architecture and C11 mode. A renamed
MSVC wrapper should use explicit `--cc-family msvc`. `clang-cl` is not a
supported driver spelling; use `clang --cc-family clang` on Windows.

The probe checks `__clang__` before `_MSC_VER`, since Clang targeting the
Microsoft ABI also defines Microsoft compatibility macros. A Windows target
triple is therefore insufficient to claim that Microsoft `cl.exe` ran. GCC
and Clang retain their `--version` and `-dumpmachine` commands and verify the
version against the predefined macros. MSVC records `_MSC_FULL_VER` and
`_MSC_BUILD`, and derives its Windows target from the actual architecture
macros. Every compiler binary has its own SHA-256 identity.

Function and field type assertions use C11 `_Generic`, independently composed
typedefs and `_Static_assert`. The field check takes its address, so the type is
a pointer to the complete field; this preserves array extents and nested
pointer qualifiers instead of applying value/array conversions. No GNU
`__typeof__` or `__builtin_types_compatible_p` is needed by the matrix. Three
negative compilations deliberately change one valid header declaration at a
time: a function parameter, an array extent and an inner pointer's `const`.
Each must fail with its specific static-assert diagnostic. A missing compiler
or an unrelated syntax error cannot satisfy that control.

The `cl.exe` adapter uses `/std:c11`, `/W4`, `/WX` and `/MD`. It names the C source
with `/Tc` and gives every C object an explicit `/Fo` path, separate from the
Rust `matrix.obj`; `/Fe` selects the executable. The positive C driver and Rust
object are linked and executed on that Windows host, with no emulation fallback.
Microsoft documents the required [C11 features and language mode](https://learn.microsoft.com/en-us/cpp/build/reference/std-specify-language-standard-version?view=msvc-170),
[`_Generic` support and SDK requirement](https://learn.microsoft.com/en-us/cpp/c-language/generic-selection?view=msvc-170),
and the [`/Fo`](https://learn.microsoft.com/en-us/cpp/build/reference/fo-object-file-name?view=msvc-170)
and [`/Fe`](https://learn.microsoft.com/en-us/cpp/build/reference/fe-name-exe-file?view=msvc-170)
output options.

## Execute and retain evidence

```sh
python tools/validate_native_host.py --cc gcc --cc-family gcc \
  --expected-system Linux --expected-machine x86_64 \
  --output artifacts/native-host-gcc.json
python tools/validate_native_host.py --cc clang --cc-family clang \
  --expected-system Linux --expected-machine x86_64 \
  --output artifacts/native-host-clang.json
```

With the pinned Rust compiler available and a Visual Studio developer
environment initialized, the Windows invocation is:

```powershell
python tools/validate_native_host.py --cc cl.exe --cc-family msvc --expected-system Windows --expected-machine x86_64 --output artifacts/native-host-msvc.json
```

The `hepta.native-host.v2` JSON report retains the actual OS/architecture,
C compiler family/version/target and macro probe, Rust identity,
generated-source hashes, build/link commands, executable hashes and process
outcomes. Expected-host arguments refuse a host mismatch. The validator binds
every command to its compiler family, exact object/executable paths, two
optimization profiles and four real negative controls. A compile, launch,
bounded-capture or post-execution validation failure produces `status: failed`
with unqualified raw observations, including the failing command and available
bounded stdout/stderr. Historical v1 files are left intact; they cannot serve
as fresh v2 compiler-family qualification.

`.github/workflows/hepta-native-hosts.yml` requests separate native jobs on
Linux x86-64 and AArch64 for both GCC and Clang, Windows x86-64 for Microsoft
`cl.exe` and Clang separately, and macOS AArch64 for Clang. On Windows it uses
the installed system `vswhere.exe` to locate Visual Studio and invokes
`VsDevCmd.bat -arch=x64 -host_arch=x64`, following Microsoft's
[tool discovery and environment initialization workflow](https://github.com/microsoft/vswhere/wiki/Find-VC).
Only compiler/SDK search paths enter that job's environment; the complete
environment is never printed and no machine settings are changed.

Jobs check out the exact PR head, retain distinct per-compiler artifacts and
do not cancel one another on failure. An initial failed result and setup log
also survive an interrupted setup, before the qualification tool can run.
The workflow is an execution request. Only a successfully executed, retained
v2 report qualifies its actual host/compiler pair. This driver's development
machine is Linux: its GCC/Clang runs and adapter tests do not constitute an
MSVC execution result. Windows `cl.exe` must pass its own remote job.

Hosted runners may be VMs. Their native execution does not establish physical
board startup or MMIO, DMA, IRQ, GPU device/driver qualification. Packed
records, bitfields, varargs and broader platform/compiler combinations remain
outside this finite matrix.
