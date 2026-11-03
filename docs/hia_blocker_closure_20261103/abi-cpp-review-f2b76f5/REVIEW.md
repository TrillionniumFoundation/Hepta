# Independent host evidence review — f2b76f5, retained ABI originals

## Result

All **7 conventional ABI and 7 real upstream C++ artifacts** pass the existing finite host qualification and independent artifact checks at commit `f2b76f5741c83822be2e12cf5a50b50a8d27b96a`, tree `0e2e8c982dada17251e9c97c746689ee85f69f37`.

The ABI matrix object/executable retention gap identified at 23af is now closed for these seven observed host/compiler combinations: the new v3 artifacts contain the actual declared files, and their bytes were independently rehashed against the original report and manifest. This is a narrow evidence-retention result, not whole P0–P7 closure or a new ABI safety theorem.

Review method: existing GitHub Actions metadata and ZIP bytes only. No CI rerun, compilation, executable launch, model request or timing experiment was performed by this audit. ZIP members were read in memory, never executed or extracted.

## Exact source and matrix

- [ABI workflow 41615741238](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41615741238): all 8 jobs completed successfully. The standalone HIA AArch64 job/artifact is handled separately by the integrator.
- [C++ workflow 41615740747](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41615740747): all 7 jobs completed successfully.

| Actual host | Compiler | ABI ZIP artifact | C++ artifact |
| --- | --- | --- | --- |
| Linux x86-64 | GCC | 13220797757 | 13221571169 |
| Linux x86-64 | Clang | 13220962696 | 13221366540 |
| Linux AArch64 | GCC | 13220209805 | 13221685617 |
| Linux AArch64 | Clang | 13221057505 | 13221521357 |
| Windows x86-64 | MSVC | 13221825260 | 13220722932 |
| Windows x86-64 | Clang | 13221566593 | 13220698110 |
| macOS AArch64 | Clang | 13221501717 | 13220239658 |

All ZIP byte counts and SHA-256 values match GitHub artifact metadata. The seven ABI ZIPs are saved create-only in this directory as `artifact-<id>.zip`, totaling **24,249,719 bytes**. `abi-zip-manifest.json` and `FILES.sha256` identify them for long-term evidence preservation. C++ ZIPs were inspected in memory and not saved locally.

## ABI v3 original-byte verification

The audit rehashed **300 retained files, 16,962,071 bytes**, across the seven ABI archives. It checked the exact manifest/file set and rejected path aliases or ZIP symlinks in the verification logic. The retained manifest bytes, bytes/SHA-256 declarations and source identity agree with the original `native-host.json` report.

For every host, the audit cross-checked all four native roles against their original report identities: the Rust matrix object, O0 executable, O2 executable and compiled wrong-echo executable. That is **28 native role originals**. The object byte count also matches the native backend receipt; the retained `native-build.json` is identical to that original structured receipt. Original temporary-directory/path identity is preserved separately from the archive-relative file names.

Source roles are independently matched to the report's positive Hepta/C/header/layout hashes, canonical Rust input hash, three distinct changed-header hashes, C compiler-probe hash, and wrong-echo source hash. This distinguishes positive inputs from the files modified later during negative controls.

The full original C command list matches `commands.json`. **164 raw C stdout/stderr streams** match their per-command identities and the original decoded command observations. The Windows Clang archive retains 6 streams containing 24 CRLF sequences; Windows MSVC retains 11 streams containing 49 CRLF sequences. Raw bytes are not rewritten. Applying the same universal-newline decoding as the capture implementation reproduces the original text exactly.

| ABI host/compiler | Retained files | Rehashed bytes | Raw C streams |
| --- | ---: | ---: | ---: |
| Linux AArch64 GCC | 43 | 1,955,823 | 24 |
| Linux x86-64 GCC | 43 | 1,882,917 | 24 |
| Linux x86-64 Clang | 43 | 1,863,401 | 24 |
| Linux AArch64 Clang | 43 | 1,956,519 | 24 |
| macOS AArch64 Clang | 43 | 2,003,306 | 24 |
| Windows Clang | 43 | 2,594,216 | 24 |
| Windows MSVC | 42 | 4,705,889 | 20 |

**Rust boundary remains explicit.** `inputs/matrix.rs` contains canonical UTF-8 source passed to the backend. The backend's platform-materialized temporary `program.rs`, internal Rust compiler argv and raw Rust compiler stdout/stderr are not retained by this patch. Their scope flags remain false. The new original raw streams are those of the qualifier's C probe/build/execution calls. Actual Rust matrix object bytes and the structured backend receipt are retained and checked.

## Unchanged observations and controls

Every ABI host executes two optimization profiles with **181 foreign calls per profile**. All three ill-typed declaration controls and the actually compiled wrong C echo reject as before. The original workload and denominator were not reduced to obtain the retention result.

Each host's finite stb-divide qualification retains 21,453 distinct inputs, 42,906 input/configuration pairs, 514,872 native function observations, 696 separate HIA interpreter observations and 24 native target-only trap processes. Three whole-bundle refusals, the wrong-code exit code 2 and `E_CPP_PROJECT_PROFILE` refusal remain intact. These generated native targets use Rust; this cohort does not execute the HIA native route.

Each of the seven C++ hosts runs nlohmann/json 3.11.3 and 3.12.0. Per version, the observations remain 98 direct/Hepta cases, 32 lifecycle cases, 1,024 concurrent calls and ordinary live allocation delta zero. Registry allocations retained are two on Linux/macOS and three on Windows; this is not a zero-allocation claim. All **12 exact negative evidence controls** reject on each host, as do actual wrong-code execution and incompatible signature controls.

C++ original-byte verification rehashed the complete retained manifest: **514 files, 30,480,988 bytes**, including all 14 consumer objects, 14 executed native programs and their original process streams. Each actual execution stdout equals the reported observations. Windows native execution is backed by retained executable bytes and matching native process output; it was not substituted by a unit-test fixture.

## Clean source and platform qualifications

All ABI before/after source logs bind the exact commit/tree, and their tracked-status files are empty. All C++ before/after source identities are equal, with empty tracked status and no casefold collisions. The independent Git-tree listing contains **8,659 paths** and is saved as `tracked-paths.nul` (655,309 bytes), SHA-256 `62e8d12878e48bb864679944f90b36aa84d3d8a71da0fe26be4ad4e7c165044b`. Every C++ path-count/hash declaration matches that complete listing. An independent check of file names and all directory prefixes found no casefold collisions.

Each ABI report's 403 implementation files and 6 migration fixture files match their exact Git blobs. C++ reports bind 197 inputs. Linux/macOS match all 197 raw blobs; the two Windows hosts have the same eight recorded LF-to-CRLF example-file materializations as before, with no other mismatch. These differences are listed in `review.json`; tracked-clean does not mean those physical Windows example files equal raw Git blobs byte-for-byte.

Every ABI host retains **17 adapter tests, 16 capture tests and 4 original-type/process tests, all OK without individual skips**. The five POSIX ABI hosts additionally retain 20 ownership/capture tests, all OK. Every C++ host retains 16 tests, all OK without individual skips. The two Windows ABI jobs still conditionally omit the POSIX-only ownership step, and non-Windows jobs omit Visual Studio setup; these are explicitly preserved in `workflow-metadata.json`.

## Files and remaining boundaries

- `review.json`: 14 detailed qualification observations, raw member identities, source/role checks and scoped claims.
- `member-sha256.tsv`: **438 distinct selected raw member identities**, including all ABI retained-original files and their manifest/command/native-build records.
- `cpp-native-identities.json`: independent C++ original-byte and native process verification.
- `workflow-metadata.json`: actual job outcomes, conditional steps and artifact metadata.
- `abi-zip-manifest.json`, seven `artifact-*.zip` files and `FILES.sha256`: original ABI archives and their immutable byte identities.
- `tracked-paths.nul`: complete exact-source path inventory.

Prior 23af artifacts remain receipt-only for their temporary ABI matrix binaries; this new result does not retroactively add original bytes to them. Earlier 5c dirty-checkout and d562 Windows-preflight failures likewise remain unchanged in their independent review directories. The retained native targets here are Rust-backed Hepta consumers; standalone HIA LLVM/native and captured-C evidence remain separately assigned to the integrator. Foreign memory safety, all ABI features, physical-board/MMIO/DMA/IRQ/GPU qualification, arbitrary third-party receipt authenticity, whole-language safety and production activation are not established by this audit.
