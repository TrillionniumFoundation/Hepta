# Native source bootstrap after cold qualification

```
hia-source-bootstrap --source ABSOLUTE_SOURCE --cold ABSOLUTE_COLD_RUN --bootstrap ABSOLUTE_BOOTSTRAP --output NEW_ABSOLUTE_OUTPUT
```

This independent HIA entry accepts exactly nine argument words. It captures the
current source tree, the seven independent bootstrap roots, its own actual
executing image, and two outputs of the named cold run:

- `qualification/base/B3.flat`
- `final-cold.json`

The source tree remains read-only. The two cold results are separately captured
assets, not members added to the source inventory. This avoids a circular source
identity that includes the results of compiling or qualifying that source.

The entry reuses the qualified capture, sealed transport, native process owner,
stage driver, publication, original-file recheck and installed-file verification
of `HIA_COLD_BUILD_ENTRY.md`. Its HIA implementation is
`cold_source_bootstrap_entry.hepta`; its native packer is
`cold_source_bootstrap_entry_packer.hepta`. The exact same
`tools/hia_cold_build_entry_syscalls.S` trampoline serves both entries. No second
mechanical implementation is needed.

## Production construction boundary

The pinned production recipe must first convert the actual captured source
manifest to `HIASPI01`, compute the actual B3 digest, and invoke the native strict
cold admission gate with `HIACLD01`, the actual report, inventory, captured
support contract and B3 digest. It checks the exact `HIAADC01` result, including
the B3 digest and source count, before using the target compiler to construct the
source-build seed or ordinary-build capabilities.

After admission, the production plan constructs and verifies the source-build
seed generations and the ordinary bootstrap capabilities. It also rebuilds this
entry with the independent HIA profiles and compares its entire executable with
the actual captured entry image. The recipe is source-pinned executable policy;
the generic entry never treats an arbitrary report filename as proof of cold
qualification. Its component transport tests deliberately use a clearly labeled
non-qualification report fixture, and do not claim that fixture passed admission.

## Capsule and recipe

The native packer uses magic **`HIASBP01`**. Its remaining layout is the same
312-byte capsule header and nine pins as the pre-cold entry: policy size, SHA
size, authority SHA256, post-cold recipe SHA256, then the seven bootstrap-root
SHA256 values, followed by the two native flat bodies. The resulting ELF is at
most 1 MiB.

The source authority remains
`examples/hia_bootstrap/cold_build_sources.hiadat`. The recipe path is
`examples/hia_bootstrap/cold_source_bootstrap_recipe.hiadat`. That recipe remains
`HIATBR01` with the same header, tables, counts, reserved fields and limits. In
this independent entry, two further binding kinds are accepted:

| Kind | Value | Required index |
| --- | --- | --- |
| 0–5 | Same definitions as the pre-cold build entry | Same bounds |
| 6 | Actual sealed `qualification/base/B3.flat` | 0 |
| 7 | Actual sealed `final-cold.json` | 0 |

B3 must be nonempty and at most 1 MiB; the cold report must be nonempty and at
most 64 MiB. The two files are opened without following symlinks, must be ordinary
single-link files, and receive the same independent original/captured hash,
identity, timestamp and seal checks as every other input. Stage imports are fresh
sealed clones. After all children are reaped, the outer command recaptures both
original cold files and rejects content changes, replacement and changed-then-
restored files.

The variant uses transport magic `HIASBX01`, inner receipt `HIASBIK1`, and public
128-byte receipt `HIASBOK1`. The pre-cold entry's transport and receipt identities
are unchanged. The public receipt binds the actual source and installed-tool
manifests. The production plan additionally installs a receipt containing the
actual cold-report digest, actual B3 digest and native admission receipt so those
inputs are bound directly by the installed-tool manifest as well as by the full
retained stage journals.

## Unchanged bounds and component evidence

The private asset table accommodates two additional captured files. Adjacent
private tables move by 512 bytes without changing their counts or the 8 MiB
workspace. The source limit remains 4096; stage count remains 64; bindings remain
2–64 per stage and 4096 overall; publications remain 4096 overall. The aggregate
sealed transport remains at most 2 GiB. Execution retains the existing
180-second deadline, three-second cleanup budget and owner event/process bounds.

The generated policy uses 96 functions, 1497 blocks and 7222 operations, with at
most 89 blocks in a function. It stays within the established 128-function,
1536-block, 8192-operation and 256-block-per-function compiler limits.

`HIA_COLD_SOURCE_BOOTSTRAP_ENTRY_QUALIFICATION.json` records 14 actual public-entry
cases plus 345 native helper, owner-field and capsule checks. The positive case
uses all eight binding kinds, two real stages, native construction and execution,
temporary and installed publications, exact manifests and owner cleanup. The
negative cases include missing or substituted cold inputs, invalid binding kinds
and indices, invalid metadata, occupied output, and live mutation or ABA
restoration of each cold input. In all four live-mutation cases the sealed inner
construction succeeds, then the outer command refuses public success.

These are component results. Full closure additionally requires a matching real
sixty-phase cold success, the production post-cold plan, ordinary build and
package checks, native installation and an installed whole rebuild against the
same final source identity.
