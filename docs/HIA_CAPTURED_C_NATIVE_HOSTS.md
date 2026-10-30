# Captured C post-test application: native Linux hosts

The opt-in `hepta.hia.c-posttest-native-host-protocol.v2` extends the existing
Ring-Buffer/musl application qualification to native Linux x86_64 and AArch64
LP64 processes. It uses the existing verified HIA Core and direct LLVM emitter.
The implementation adds a native AArch64 **object build and executable call
path**; it does not add an AArch64 shared-library admission profile.

## Protocol identity and execution boundary

`tools/qualify_hia_c_posttest.py` keeps its default v1 protocol and x86_64 shared
library path. Selecting `--native-host x86_64` or `--native-host aarch64` opts
into the new v2 report schema. Historical v1 observations keep their original
identity and scope.

The v2 inputs remain the locked Ring-Buffer and musl comparison source, the
already authored checksum integration translation unit, and the authored HIA
client. Only the checksum integration loop receives the existing documented
eight-iteration `for` to `do-while` edit. The migration inventory remains 12
translated C bodies (11 upstream and one authored) plus one HIA client body.

Three independently linked executables run the same fixed cases:

| Executable | Implementation link inputs | Compiler |
| --- | --- | --- |
| HIA | Reverified HIA LLVM object only | Actual selected Clang 20+ |
| Original C / Clang | Captured original C sources and authored C client | Actual selected Clang 20+ |
| Original C / GCC | Same original C sources and authored C client | Actual selected native GCC |

Each executable also links the fixed scalar ABI call driver. That driver has no
checksum or queue implementation. HIA execution does not link original C
implementation bodies, use Rust code generation, or replay C source at runtime.
The driver declares the existing scalar boundary:

```c
unsigned long long legacy_checksum_chunk(
    size_t count, unsigned long long packed,
    unsigned int state, unsigned int polynomial);
```

The qualified data model measures 8-bit bytes, 64-bit pointers, `size_t`, `long`
and `long long`, 32-bit `int`, and little-endian byte order. The compiler's real
architecture macros and C static assertions reject a mismatched call driver.
The driver prints the compiled ABI measurements before returning case results.
The HIA LLVM object uses the existing SysV AMD64 scalar ABI on x86_64 and the
existing AAPCS64 scalar ABI on AArch64. In particular, AAPCS64 does not inherit
the x86 narrow-integer `signext`/`zeroext` LLVM parameter attributes.

## Checks required for a passing report

The exact requested source commit must be clean before capture and unchanged
after execution. Captured dependencies and original project inputs are retained
and checked again. The requested CI machine must match the measured host; a
foreign target label does not select an emulator or a cross execution command.

The report binds the actual Python executable ELF identity, compiler executable
hashes and versions, each compiler's default triple, selected linker identities,
captured C target and data models, generated LLVM triple and hash, verified Core
identity, HIA object receipt, original implementation inputs, driver source,
linked executable hashes and ELF machine, runtime ABI probes, and raw command
outputs. The linker trace records its observed link inputs. Executables and the
HIA object are checked for identity again after the calls.

The finite functional cohort contains 48 cases: two CRC polynomials, eight
lengths including zero and over-capacity cases, and three packed byte inputs.
All three native executables must match both the independent Python CRC oracle
and the HIA interpreter. The 16 resource cases use four lengths and four
allocation-refusal positions. Separate original-C and HIA native allocator
observers must match the interpreter's result, attempts, allocations and frees,
and leave no live allocation. A passing host report therefore contains 144
functional native calls and 32 resource observer executions.

Host, target, ELF, missing-result, wrong-result and dirty-source controls are in
`tests/test_hia_c_posttest_hosts.py`. A Clang default triple for another machine,
ILP32, non-Linux or big-endian hosts, mismatched ELF machine/type, and wrong ABI
probe are rejected. ARM shared-library requests and forged LLVM target origins
remain rejected under their existing contracts.

## Running and interpreting evidence

On an exact clean x86_64 source checkout, with output outside that checkout:

```sh
python tools/qualify_hia_c_posttest.py \
  --native-host x86_64 --clang clang-20 --cc gcc \
  --expected-source "$HEPTA_SOURCE_SHA" --output "$HEPTA_EVIDENCE_DIR"
```

Use `--native-host aarch64` on an actual admitted AArch64 Linux host. The command
does not accept an emulator prefix. The dedicated
`.github/workflows/hepta-c-posttest-hosts.yml` uses separate `ubuntu-24.04` and
`ubuntu-24.04-arm` runners, checks their measured machine and package
architecture, installs LLVM 20 from its signed architecture-specific repository,
and executes from the same exact clean source SHA. Both successful and failed
raw observations are uploaded. LLVM's Noble 20 repository publishes separate
amd64 and arm64 indexes; the installed binaries are identified again at runtime.

The result qualifies only the actual machine named in that result. Local x86
success, AArch64 object emission, and existing AArch64 QEMU finite-runtime
results are separate observations. None substitutes for a successful direct
ARM host application report. The existing seven-host C/Rust workflow also
remains a different route; its host coverage is not HIA LLVM application
coverage. Physical hardware attestation is not claimed by process observations.

The compiler/linker, loader, libc and host environment remain trusted. These
finite application and resource comparisons are not a source-equivalence or
backend-refinement proof, do not infer arbitrary foreign pointer contracts, and
do not establish general C/C++ migration. No performance comparison is part of
this qualification.
