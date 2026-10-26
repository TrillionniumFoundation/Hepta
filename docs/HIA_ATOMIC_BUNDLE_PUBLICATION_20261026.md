# HIA L1 bundle: Linux atomic no-replace publication (2026-10-26)

## Concrete defect

Before this patch, `hepta.hia_migrate.migrate_scalar_to_hia` created
the final output directory, then hard-linked `candidate.hepta`, native
`candidate.so/.o` and `migration-hia.json` separately. A process death
between links made the final path visible with an incomplete bundle. An
existing empty directory race could not be safely resolved by checks alone.

## Real implementation

New `hepta.hia_bundle_atomic.publish_hia_bundle` receives the already
validated, private TemporaryDirectory on the **same filesystem** as the
requested output. It verifies the exact three-file inventory, regular-file
type and bytes, fsyncs each file and the staged directory, checks source
identity again, and invokes the Linux kernel's `renameat2` with
`RENAME_NOREPLACE` using directory FDs (no unsafe stdlib rename-over-existing
fallback). The final directory becomes visible in **one atomic rename**.
Fsync the parent after rename and independently re-read every published
artifact and the source before returning success.

If any pre-rename check fails, no destination is created by this command.
If the rename succeeded but a later file/source/durability check fails,
report `recovery_required`; **never** blindly remove a directory already
visible to readers. The already published data may need independent
inspection. A terminated process before the parent fsync also cannot
promise persistence across sudden power loss, even though the rename
is atomic as observed by concurrent processes.

This is a Linux host-only publication profile. An absent `renameat2`,
unsupported filesystem or non-Linux host **rejects** rather than falling
back to partial per-file publication. The target .o may still be a cross
target artifact (ELF/COFF/Mach-O); host publication and target execution
are separate claims.

No changes to C/C++ parsing, canonical HSIR, Resource IR, SSA, native
codegen, Rust native reference, ABI and symbol inspectors, or device
qualifications are introduced.

## Actually executed local evidence

The exact `hepta/hia_bundle_atomic.py` and
`tests/test_hia_bundle_atomic.py` Git blobs match the local Python
3.13 tested byte-for-byte sources. **10/10 filesystem tests passed**,
including a real Linux `RENAME_NOREPLACE`, empty-dir/symlink collisions,
destination name race, mutated/symlink staged files, pre/post-rename source
changes, injected parent fsync failure, TemporaryDirectory teardown after
rename, and **actual child process death immediately after successful
rename** (all three files were visible together).

This evidence is an isolated publication helper test, not a full Hepta
migration/compiler/native/ABI test. `tests/test_hia_migrate.py` has three
new wrapper-level regression methods, but they have not been run in the
exact integrated repository checkout here due to unavailable full toolchain.

Run in an exact checkout:

```bash
python -m unittest tests.test_hia_bundle_atomic tests.test_hia_migrate -v
python -m unittest tests.test_hia_core tests.test_hia_oracle tests.test_resource_ir -v
```

## Explicit unclosed blockers

- The new directory publication is atomic on the supported Linux
  filesystem, not a transactional snapshot of an uncooperative source writer
  and not a cryptographic authenticity proof for the system toolchain.
- Arbitrary C/C++ L2/L3 behavior equivalence, general pointer provenance,
  full executable Owner/Loan/Drop/Memory SSA, native backend refinement,
  physical target execution, real Agent A/B and production performance
  remain OPEN.
- No CI state or old-commit receipt is used to claim this source qualified.
- `whole_project_blockers_closed=false`.
