# P0 HIA schema audit: pinned no-follow source read

Based on PR #282 exact `0dd3d212a3d01a1f69b075dddc1519d987219e7d`. This patch changes only the existing
`tools.audit_hia_schema_collision` source reader and its adversarial tests.
No HIA opcode, compiler/verifier authority, version registry, ABI or execution
semantics changes.

The old `lstat → Path.read_bytes → lstat` sequence could open a different
inode via a symlink inserted after the initial `lstat`. The new read requires
`O_NOFOLLOW`, opens once, uses `fstat` before and after reading bounded bytes,
and checks that the path still identifies the same ordinary inode and size.
If `O_NOFOLLOW` is absent, the audit refuses rather than falling back.

Tests cover a normal ordinary file with `Path.read_bytes` prohibited,
a symlink refusal and replacement between pre-open and descriptor open.

Run on the exact source snapshot:

```sh
python -m unittest tests.test_hia_schema_collision tests.test_hia_schema_binding_audit -v
python -m unittest tests.test_hia_schema_unification tests.test_hia_p0p1_v7_guard -v
```

This is source identity hardening, **not** a formal absence-of-TOCTOU proof
against arbitrary privileged adversaries or external library mutation.
It does not close source/Core/native refinement, general Memory SSA,
C/C++ L2-L3, real-agent A/B, hardware or production blockers.
`whole_project_blockers_closed=false`.
