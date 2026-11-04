# Native CI evidence for the frozen seven-track source

These are new executions on published source `9435f04887757e403b6caf67e09f113079356e12`, tree `514b607bd5661abe5ac516ee77d80638c939749c`. That tree exactly matches the desktop measured source `98bdbe9f859b5caf95356fbfb1254448d9b583d0`; the commit IDs differ because publication used an explicitly recorded GitHub App projection. These CI machines and compiler versions are separate observations, not substitutions into the fixed desktop composition.

## Executed scope

| Lane | Actual execution | Evidence boundary |
| --- | --- | --- |
| Selected C ABI and complete declared `stb_divide` variants | Seven platform/compiler combinations: Linux x86_64 and AArch64 with GCC/Clang; macOS AArch64 with Clang; Windows x86_64 with MSVC/Clang | Hepta's Rust backend; not direct HIA LLVM on every platform. Each host ran both ABI profiles, three type refusals, a compiled wrong echo, 21,453 distinct component inputs across two configurations, and 24 target-only trap processes. |
| Real C++ library reuse | The same seven combinations, both unchanged nlohmann/json 3.11.3 and 3.12.0 | A compiled Hepta consumer calls a native C++ bridge; the original library is not rewritten. Each version/host has 98 functional observations, 32 lifecycle cases, 1,024 concurrent calls, stale/double-destroy refusals and cooperative cancellation. |
| Captured bounded C application to HIA LLVM | Actual Linux x86_64 and AArch64, with direct native process execution | Each host has 48 functional cases / 144 native functional calls and 16 resource cases / 32 native resource calls. This is a bounded authored integration application with upstream components. |
| Standalone HIA AArch64 | Actual Linux AArch64 host, not QEMU | 17 return comparisons, two wrong-Core controls, one actual bounds abort, one null-allocation refusal, four allocations/frees and zero outstanding allocations. |

The C++ observations retain process-lifetime registry allocation separately from completed owners: two registry allocations on the Linux/macOS observations and three on Windows. Zero ordinary live-owner delta does not mean zero runtime retention. Cooperative cancellation stops after three of seven requested operations without replay; it is not arbitrary asynchronous cancellation or foreign-side-effect rollback. Device/DMA support, hardware attestation, general race freedom, complete foreign memory safety, performance superiority and whole-language soundness are not established.

## Original runs

- [Actual host ABI qualification](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41774368025)
- [Real upstream C++ host qualification](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41774368067)
- [Captured C application on native Linux hosts](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41774368021)

All 17 original ZIP archives were downloaded and their complete SHA256 values and sizes verified against GitHub's artifact metadata before collection. `ARTIFACT_INVENTORY.json.gz` preserves those metadata and all 2,133 member paths, sizes and SHA256 values, including the original artifact URLs and observed expiry dates. The 1,983 UTF-8 text/source members are retained byte-for-byte in the split archive. The remaining 150 binary members have inventory records here; their actual bytes remain in the original CI artifact ZIPs. This is not described as a complete binary archive.

`SUMMARY.json` is a descriptive extraction from the actual reports, with their original claim flags. `collect_native_ci.py` is the collection/audit implementation; it does not run downloaded programs. The text archive was independently read back and all 1,983 member hashes verified against the inventory.

## Inspect retained evidence

Run `python3 verify_retained.py` from this directory. It validates each ordered archive part, the reassembled archive hash and size, and every retained member against the original inventory without extracting or executing files. The archive is 12,124,143 bytes with SHA256 `93259debd1654d55aeddf9f3a6c16c394f927935ec56a397bf74d90e96b1d5cf`.

To reconstruct the gzip archive after verification, concatenate the filenames in the exact order of `ARCHIVE_PARTS.json`. Any missing, changed, reordered or extra retained member fails verification. The inventory describes omissions explicitly; qualification claims must keep their original per-host, per-backend and per-profile scope.
