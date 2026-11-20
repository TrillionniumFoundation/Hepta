# Explicit native executable release builder

## Status and scope

This is a new, explicitly invoked Linux x86-64 executable path. Its implementation and qualification sources are statically prepared; generation, compilation and the new runtime gates have not been executed by the author. The two generated HIA files have no claimed output hash until the root executor generates them twice and compares the complete bytes.

The public Python CLI, its existing 15 actions, public interpreter, existing source builder and default selection remain unchanged. This component does not resolve an existing cold, GC, traceback, resource or whole-stack HOLD. It is a bounded vertical path from source bytes to an executable release, not a general replacement for the public language or every compiler mode.

## Runtime command and native chain

```text
hia-exec-release assembly SOURCE_SHA256 < source.hepta > release.hiarel
hia-exec-release core-json SOURCE_SHA256 < source.json > release.hiarel
```

Exactly two arguments follow argv[0]. The source digest is an independently supplied, lowercase 64-digit SHA256 value. The HIA policy checks the entire stdin byte sequence against it before invoking the frontend or compiler.

The single native process performs this sequence:

1. HIA validates syntax selection and digest syntax, requests bounded input and classifies every actual syscall result.
2. The embedded HIA SHA256 stream checks the entire source. Assembly goes to the admitted compiler; Core JSON goes through the existing HIA frontend and then the same compiler.
3. The existing flat HIA compiler emits the declared selfhost-exec Linux x86-64 profile. HIA checks the complete canonical two-program-header ET_EXEC structure and actual extent.
4. HIA hashes the image and writes an HIAREL01 package with exactly two ordered members: source.hepta mode 0400, followed by program mode 0500. The source member is the complete original input, including its original JSON serialization if that mode was selected.
5. HIA hashes the package, requests read-only package storage and writes the package plus a complete stderr receipt.
6. The existing separately invoked native hia-release installer installs or verifies the package using the operator's expected package SHA256. Execution of the installed program is a separate explicit operation.

The builder never executes the input program. It does not start Python, a compiler child, a shell, a linker or another process. The embedded compiler, frontend, policy and SHA implementation are already admitted HIA-generated images. The bootstrap builder and qualification driver remain hosted Python; they are not runtime fallbacks.

A package hash is content identity. It is not a signature, a release authorization or permission to select new code. Installation still requires the existing explicit expected-package argument; no new default activation is introduced.

## Ownership of decisions and mechanical ABI

The generator authors two complete HIA graphs:

- exec_release_policy.hepta owns argument checks, source limits, EOF and partial-I/O progress, errno classification, syntax choice, frontend and compiler sequencing, digest checks, the executable profile, package layout and modes, diagnostic JSON and exit classes.
- exec_release_packer.hepta owns the standalone ELF construction, full image extents and four fixed rel32 call bindings. Its four embedded executable dependencies are policy, Core JSON frontend, compiler and SHA256 stream.

tools/hia_exec_release_syscalls.S is a fixed three-buffer ABI and Linux syscall transport. It checks actual allocation bounds before pointer formation, captures the issued action and sequence in private stack storage, invokes one selected mechanical action and returns the actual full u64 result to HIA. It does not parse source, calculate SHA, choose members or modes, construct package or success JSON, decide source policy, execute an input program or select retry behavior.

The fixed syscalls are read, write, mmap, mprotect, rt_sigaction and exit. The only assembly branches outside mechanical dispatch/bounds are whether a mmap result is a dereferenceable address and a final malformed-transport exit after one HIA refusal attempt. Raw negative errno values and successful values reach HIA unchanged. Transport corruption exits 70; it is not classified as an ordinary source refusal.

The original _run, Popen, waitid(WNOWAIT), child ownership and original deadlines are untouched.

## Fixed bounds

| Item | Bound |
| --- | ---: |
| Assembly source | 1 MiB |
| Core JSON source | 8 MiB |
| Frontend assembly output | 1 MiB |
| Compiled executable | 1 MiB |
| Bootstrap packer input/output | Existing 1 MiB ABI |
| Policy workspace | 4096 bytes |
| Source allocation | 8 MiB + 4096 bytes |
| Output allocation | 16 MiB |
| Frontend arena | 64 MiB + 4096 bytes |
| SHA workspace | 8192 bytes |
| Complete anonymous allocation | 92,295,168 bytes |
| HIAREL01 package | 91 + source bytes + executable bytes |

The source allocation becomes read-only after EOF. The package region becomes read-only before output. The frontend arena and original 1 MiB compiler workspace share an allocation at different times; the compiler's original zero-workspace precondition is explicitly restored before entry. The SHA state is separate.

No language, SSA, function, block, register, compiler output or VM limit is increased. Source3 records actual generated maximum function and block parameter counts. Generation or compilation may reject this authoring; that result must remain a real failure rather than trigger smaller source, hidden fallback or a changed bound.

## Bootstrap authority

The strict builder consumes a compiler from a completed cold qualification of the exact current complete source contract:

```sh
"$PY" -B tools/build_hia_exec_release.py \
  --compiler "$CURRENT_COMPILER" --cold-report "$COLD_REPORT" \
  --output "$FRESH_BUILD"
```

The existing admit_cold_build gate runs before output creation. All four compile receipts, actual full input/output files, complete return values, captured compiler, sources and current contract are checked before publication. The final HIA packer output must be a complete canonical ET_EXEC.

For development diagnosis only, the explicit alternative is:

```sh
"$PY" -B tools/build_hia_exec_release.py \
  --compiler "$DEV_B3" --development --compiler-sha256 "$EXPECTED_DEV_B3_SHA256" \
  --output "$FRESH_DEV_BUILD"
```

The expected digest must be an external full 64-digit binding to the actual image, including when using root's R24 B3. A completed-cold report and the development choice are mutually exclusive. A failed cold admission never falls back to development. Development records say EXPLICIT_DEVELOPMENT_BUILD_ONLY and cannot establish matching-source cold qualification.

The full Native5 qualifier, rather than a prebuilt candidate from these convenience commands, must be used to establish original-first qualification: its two fresh original children and complete input freeze precede its candidate compilation and invocation.

## Complete new qualification

Source3 is the entire ExecReleaseSourceTests class. It compares actual generated graphs with the generator, checks the full fixed layout and records parameter counts; executes all 11 declared policy witnesses; compares every byte of the HIA ELF packer against an independent fixed-ABI oracle; and preserves real authority refusal and typed DATA comparison controls.

Native5 is the entire ExecReleaseNativeTests class. The complete qualifier always plans these 44 owned commands:

| Group | Commands | Scope |
| --- | ---: | --- |
| Originals | 2 | Fresh complete original CLI reference plus nine original public-VM executions, full first/second bytes equal |
| Source to installed executable | 18 | Three sources; each native build, install, verify and three installed executions |
| Refusals | 11 | Exact original-derived bytes and fixed argument cases |
| Kernel errors | 3 | Actual closed stdin, full stdout and mmap refusal |
| Existing release and corruption | 4 | No replacement, read-only verify, actual known-inode corruption refusal, restored verify |
| Copied native runtime | 6 | Copied builder and installer, build/install/verify and three installed executions |

There are 12 actual installed-program executions. The original flat echo body and original CLI reference function remain unchanged. The declared executable header variation, constant-42 variation and original Core JSON serialization are recorded independently. The historical original reference's before_B0 field is retained as a field of that original; it does not assert that the externally supplied development compiler did not yet exist.

The 11 new refusal specifications are empty input, bad header, bad UTF-8, unsupported flat output profile, invalid JSON, mismatching source hash, uppercase hash, unknown syntax, extra argument, assembly overflow and JSON overflow. No producer-selected substitute with the same exit code is accepted by the independent reader.

Each new owned command has 120 seconds plus the original 3-second cleanup bound through the unchanged subreaper owner. Actual compiler invocations retain the existing 20-second API. The complete new Source and Native scopes use the existing 1800-second outer qualification limit. Existing tests retain their own original limits; none is enlarged or removed.

```sh
"$PY" -B tools/run_hia_unittest_gate.py tests.test_hia_exec_release.ExecReleaseSourceTests

HEPTA_HIA_EXEC_RELEASE_COMPILER="$CURRENT_COMPILER" \
HEPTA_HIA_EXEC_RELEASE_COLD_REPORT="$COLD_REPORT" \
HEPTA_HIA_EXEC_RELEASE_EVIDENCE="$FRESH_EVIDENCE" \
"$PY" -B tools/run_hia_unittest_gate.py tests.test_hia_exec_release.ExecReleaseNativeTests
```

For the separately labelled root development attempt, remove the cold variable and provide HEPTA_HIA_EXEC_RELEASE_DEVELOPMENT=1 and HEPTA_HIA_EXEC_RELEASE_COMPILER_SHA256 with the exact external compiler digest. Every other case, command, assertion and bound is unchanged. Clear inherited HEPTA_HIA_ and Python selection variables before binding either run.

A failed independent group is recorded and later independent groups are still attempted. A missing prerequisite is a real incomplete command inventory, never a fabricated command or a PASS. The five methods read the same full run; one failed complete run is not converted into five unrelated successful fragments.

## Independent DATA readback

```sh
"$PY" -I -S -B tools/read_hia_exec_release.py \
  --repo "$PROJECT" --report "$FRESH_EVIDENCE/report.json" \
  --report-sha256 "$REPORT_SHA256" --report-bytes "$REPORT_BYTES" \
  --output "$FRESH_READBACK"
```

The reader imports no producer, candidate, VM, compiler or test. It captures each raw file once, computes its hash and parses that exact capture, and rereads every consumed file before its terminal result.

It checks all 44 ordered commands and exact fixed original/setup scripts with -I/-S/-B, the exact three owner/setup/original source pins against the full current map, original process-owner request/log/receipt bindings, natural terminals and real cleanup evidence. It independently derives all 11 refusal payloads and arguments from the frozen original and fixed specification. Every executable pathname is bound to the actual built, installed or copied location, as well as to its full bytes.

It consumes full original records, all native compile and pack inputs, complete output allocations and raw receipts, the complete current source contract, the HIAREL01 bytes, native install/verify receipts and actual installed names/modes/bytes. Duplicate JSON keys, nonfinite tokens and bool/int substitutions are rejected. All receipt and result fields are retained; successful parsing is not a substitute for equality. It validates the explicit corruption preimage, changed bytes, restored bytes and same recorded inode.

The independent reader is a finite evidence validator, not proof of arbitrary simultaneous filesystem interference, every possible OS failure, every signal schedule or all public-language inputs. Complete raw receipts are preserved even where the declared JSON contract is compared as typed structured data rather than JSON whitespace.

No new runtime claim is made for EINTR, partial output, SIGKILL, arbitrary MemoryError, reflective Python histories or unbounded source programs. The HIA implementation contains its explicit I/O transitions, but these 44 cases do not establish every transition. Existing complete OS, lifecycle, compiler and resource suites remain separate required evidence.

## Registration and retained source

This slice adds nine ordinary source files and two root-generated HIA files. It appends all eleven to the actual current SOURCE_FILES literal and to explicit sdist support. The exact installed-resource test's SDIST_SUPPORT_FILES constant first receives the twenty caller/source paths already present in the R24 MANIFEST but absent from that constant, preserving their actual MANIFEST order. The R24 complete Core718 log independently exposes this pre-existing mismatch. The same eleven new release-builder paths follow those twenty. All test methods, assertions, requests and limits remain byte-identical. Existing Agent RESOURCES, setup.py, wheel package resources, 50 helper keys, public CLI entries, native selectors and production Python modules are unchanged.

The new executable is delivered through the existing native installer. It is not silently added as a Python-wheel default command. Full source release uses the existing BOOTSTRAP_FILES inheritance from SOURCE_FILES. Registration supplies exact R24 before/after text and inverse splices so later additions are not overwritten.

The package also records the complete retained source-builder, native-CLI, native-installer, release-selection, stdio, installed-resource and source-contract test inventory. Their original methods and budgets remain authoritative. Existing cold 17-reference/38-phase qualification remains a separate original 180+3-second gate; this new finite path does not turn its HOLD into PASS.
