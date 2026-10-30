# Recovering the original local 699de39 evidence

**The complete second package was recovered byte-for-byte from four previously uploaded GitHub blobs.** It is the original 16,084,731-byte archive, SHA-256 `5f460c4e1e2165b1752d4cc6c5143ef86d483459e7697043573a715ee66da0a2`. This record preserves recovery after automated workspace maintenance removed the local copies. No language test, native binary or qualification workflow was executed by this recovery.

The final third package, SHA-256 `9bcc40d851b7b6bc16ad7b11a9f6d27e2ed27afbf322463bc89d203159d53de2`, was **not recovered**. All four specified blob candidates returned 404 in the bounded recovery queries. The prior attempt to upload them was interrupted before completion was confirmed. The second archive is not renamed or presented as the third archive, and missing original bytes are not reconstructed from prior summary text.

## Verified original bytes

| Second-package part | Bytes | Original Git blob |
| --- | ---: | --- |
| `part0001` | 4,194,304 | `fd67940303e6a79015c992ad796be2a9cefef322` |
| `part0002` | 4,194,304 | `e51cf3120992b0db0a2e69c2a533e91ffff26c7d` |
| `part0003` | 4,194,304 | `ec0066e186d172087f6c2c165a306d57b0bbc523` |
| `part0004` | 3,501,819 | `bb8c73d10e5c4a9377bb17e28ad5b198832c5fc6` |

Each raw download matched its original length, SHA-256 and Git blob identity. Ordered concatenation matched the original whole-archive SHA-256. The full streaming readback then verified **476 original files / 36,992,139 bytes**, 28 directories and five generated control members: **509 TAR members** in total. Every selected path, type, mode, length, SHA-256 and Git blob matched the archive's original `MANIFEST.json`. The complete gzip stream, EOF and CRC were consumed. The original archive was unchanged by verification.

`known-original-identities.json` binds both sets of original candidates. `recovery-summary.json` and the eight per-part receipts retain actual HTTP outcomes and byte checks. `second-package-readback.json` and `second-package-member-inventory.json` retain the independent member readback. The recovery does not grant new qualification or production authority.

## Explicit retention correction

The recovered second archive contains both original full-run directories, the 95-method safety run, preflight, the complete **nine-file second independent audit**, the corrected current-status JSON, the strict blocker ledger, selected NDU binaries and tool/Boost provenance.

Its selection omitted the **16-file first independent audit**, even though an archived status README described both audits as included. That retention statement is corrected here; it is not silently treated as true. The omitted audit and original first failure remain separately published at [the original first-attempt evidence commit](https://github.com/TrillionniumFoundation/Hepta/tree/2b13d233bf6070a8e2a5850b04c5e7361384fa41/evidence/hia_core_closure_20261029/first-attempt-699de39). The unretained third package was prepared to add that directory, but its missing exact bytes are not claimed restored.

Original runtime reports retain source `699de39a8e92e0f083df316ecc5333fb3ecf8571`, tree `592b6114f659fb18b13ad3fa5ed5e213ecdb92b5`, and their actual timestamps. The first local full run remains a failure; the second is the original bounded eight-gate pass. Old in-progress CI observations remain historical snapshots. This recovery does not update them to later workflow states.

Python remains production authority, optimization policy remains `no_change`, and the eight broad P0–P7 stages remain open. A successful byte recovery does not prove general language soundness, backend refinement, general ABI, representative performance, model productivity or full historical migration.

## Restoring the original archive

Keep `known-original-identities.json`, `restore_second_package.py` and the four raw parts under `second-package/` in this directory layout. Run:

```sh
python3 restore_second_package.py --output recovered-second-package.tar.gz
```

The destination must be new. The helper verifies all four part identities, writes a unique temporary file, verifies the complete written archive, and promotes it without replacing an existing destination. It does not extract or execute the archive. The recovery process separately restored the verified files into an isolated local namespace for continued review; it did not overwrite the source checkout.

The whole archive and its expanded local recovery copy are not additional publication payloads: the four raw parts retain all original bytes. Publication maps include the original parts plus the small recovery records, scripts and raw logs. No private download credential or signed transport URL is used by these public-blob requests.
