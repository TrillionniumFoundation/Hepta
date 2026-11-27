# Component wheel terminal custody

This follow-up supersedes the terminal-custody coverage of the initial 0b62 component qualification. The earlier real build and 540-file installation result remains preserved; independent review then found two return boundaries that did not reread every captured input.

## Actual counterexamples before the fix

On unchanged source 0b62b7a5ea1c4710373210f92ee78eda5b78458d, a real setup build, offline pip wheel and pip install completed. Three physical mutations were injected only after the original validation function had really returned: changing the install custody sidecar after the actual installed-file validator, changing the caller's partial source stage after cached wheel validation, and changing a tracked Git source after cached wheel validation. Every old public API returned success despite a different physical SHA-256. All three exact results, before/after identities, the changed sidecar, reproduction script and raw subprocess output are archived. Every mutation was restored, the positive verification passed again, and Git status was clean.

## Fix and actual verification

The cached component return now repeats the partial-stage and full Git/native/packaging snapshot checks and rereads the exact wheel and custody sidecar. The installed return now rereads the exact custody sidecar after its original terminal source verification. APIs, component-only classification, the original ordinary_wheel/default-native fixture, and every 60-second packaging-command budget remain unchanged.

Source f765709ba3dc5e95878ec25ffd5e8d9c4b3675d1 passed all five original methods in 31.122 seconds with the original CI Python 3.14 environment. Real construction and offline installation verified all 540 physical files. All 14 previous rebound controls and five new physical late-mutation controls passed: installed sidecar, cached partial stage, cached Git source, cached wheel, and cached custody. Each late control first executes the real prior validator, proves the actual boundary and mutation occurred, then requires rejection and restores bytes and modes. Final positive readback matches the initial result and the checkout is clean.

The raw archive contains 30 complete members. The two real wheels and the same raw members are preserved in the separately pinned 16,128,499-byte archive on both ROG and Mac; all 32 members were independently read and checked after transfer. The physical manifest covers 8,526 files and 853,568,592 bytes for these exact old-source counterexamples and the fixed-source actual qualification. Previous initial-attempt evidence remains in its original committed location.

This remains DEVELOPMENT_COMPONENT_INSTALL_ONLY. It grants neither native cold qualification nor the 19-role whole-native delivery gate.
