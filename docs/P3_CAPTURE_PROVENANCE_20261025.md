# P3 strict C-project capture provenance and replay

This increment is stacked on PR #113 at `0f972b9753e42055e7e9e0dda64c1f1e26f1be1a`. No new parser or C lowering authority is introduced.

## Closed, typed capture metadata

`verify_capture` now checks the exact reviewed key inventory for the build database, selected compiler, each translation-unit configuration, measured target model, and each dependency. This is evaluated **after** binding the serialized bundle SHA-256, not replaced by a checksum.

The independent current compiler dependency discovery defines both:
- `all_dependencies`: complete active dependency inventory for each captured translation unit.
- `local_dependencies`: project-local file membership under the same exact frontend flags.

Every dependency `project_input` bit must match the union of current local dependency memberships, and `bytes` must equal the actual file size. A forged capture cannot demote a local header to a system dependency or claim an arbitrary file length by resealing its JSON. Boolean target char-signedness and the project-input flag must retain JSON boolean types; numeric fields must retain exact integer types. In particular, Python's `False == 0` does not authorize these representations to be interchanged.

Nine rehashed negative mutations are included in `tests/test_c_project.py`: local provenance inversion, wrong byte length, float length, integer Boolean, integer char signedness, float pointer width, unknown compiler authority, unknown configuration authority and unknown dependency proof.

## Actually executed bounded external compiler observation

On the local host, Clang 17 successfully preprocessed a real C11 translation unit with one local header and generated both `-M` and `-MM` dependency lists. Both included the two expected project files; the macro-expanded expression contained `n + 5`; target reported `x86_64-unknown-linux-gnu`. This standalone observation is **not** a completed Hepta migration or regression suite.

Repository-native tests require a mounted checkout and remain not-run in this session. No complete C/C++ migration equivalence or L2/L3 certification is claimed. `whole_project_blockers_closed=false`.
