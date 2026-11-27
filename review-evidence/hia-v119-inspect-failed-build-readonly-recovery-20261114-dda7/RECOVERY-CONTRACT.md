# Read-only admission after the real CLI build-parent failure

## Original outcome remains unchanged

The unique reviewed build launch `aae2f30a22f34546e24749577552f163e331690d`
executed once. Session 87486 terminated with outer exit 1 after
11.477230491 seconds. Its parent `build-cli-attempt-r1/RESULT.json` is FAIL.
No second build is authorized or implemented by this recovery contract.

The original frozen build child, wrapper, and owner completed successfully.
The real control and format compilations produced 321294 and 371721 bytes,
respectively, under their original 20-second, 1-MiB output and workspace
limits. The enclosing owner retained 180+3 seconds and complete ECHILD cleanup.
The complete 3177-file base and 3187-file inspect source guards passed.
Those are observations within a failed parent stage, not a replacement PASS.

The failure occurs only when the parent calls the generation source helper
`assert_capture(captured, file_map)` for build artifacts. That helper requires
all non-executable source files to have POSIX mode 0644. The unchanged frozen
support helper `publish` uses `create`, which opens new evidence with 0600.
Consequently `INSPECT-RETAINED-BUILD.json` has the correct producer mode 0600;
the remaining eighteen build files have 0644. All nineteen Git modes are
100644. The recovery must neither chmod that file nor relax source permissions.

The failed parent did not publish its local `captured` value because the
assertion preceded `guard.cas`. That exact in-memory object is unavailable.
`FAILED-PARENT-RAW-INDEX.json` is explicitly a new post-terminal capture. It
contains the existing 53 original files, 13011219 bytes, their full identities,
POSIX modes, and inode/stat records. Its two complete reads matched. It does
not claim to reconstruct the unpublished in-memory capture.

## Separate admission

`admit_existing_cli_build.py` has an explicit `--admit-existing` action and a
new exclusive `admission-attempt-r1` directory. It never calls build,
compile_stage, invoke, a Native entry, VM, tests, or a process owner. A
process-local audit hook rejects process creation. The helper imports the
frozen read-only custody routines to validate their actual recorded inputs;
module import and file admission do not grant current-cold or machine authority.

The admission plan pins the complete original runner and plan, original raw
index, current source identity, and this helper and contract. It reuses the
same full base/view byte, mode, inode/stat guard that passed generation and
Source10. That guard remains unmodified and continues to require source
permissions 0644/0755 exactly.

The separate build capture instead requires the exact nineteen-name inventory,
every complete byte identity, the single 0600 evidence file and eighteen 0644
files, plus the post-terminal inode/stat identities. It is not a generic
permission exception or a caller-selected mode policy. Missing, extra, changed,
nonregular, or symlink evidence fails the admission.

The helper freshly validates all 53 failed-stage files before and after its
readback. The original raw owner must equal its returned owner with only the
producer's two documented return fields, retain actual return 0 and full
180+3 cleanup, and equal the embedded stage owner. Original wrapper and frozen
child requests/results must remain exact. The parent must still be FAIL.

For each of control and format, the unchanged strict `admit_compilation`
rechecks the actual fixed ordinary B3, complete current source, actual request,
receipt, stdout/stderr, complete 1-MiB output, and produced image. The returned
records and ordered bindings must equal the original frozen child record.
The original builder's before/after host source identities must equal fresh
current identities. Its source_manifest and cold_report_sha256 remain null.

The original compiler child retained complete source/output files and its
workspace header, not a complete post-call workspace image. No missing full
workspace is synthesized or claimed here. The readback is bounded by the
actual producer's existing observations.

Only a new result may say `READ_ONLY_BUILD_ADMISSION_PASS`. It must also say
`original_parent_status_unchanged: FAIL` and identify the original failed
result. New compile, Native, VM, test, and subprocess counters remain zero.
Every exception retains a separate FAIL and forbids further stages. No old
result or raw file is written, replaced, chmodded, or deleted.

## Retained regression successor

The R2 retained runner is a separate harness. Its parent and child entry
guards permit only the original3 and original-cli43 groups; a build-cli entry
is explicitly rejected. Its fresh build binding consumes only the distinct
admission result at its fixed path and an explicitly supplied actual SHA.
It reruns the same file-only receipt and byte/mode admission before and after
each original group. An unexecuted admission plan or the original failed
parent can never satisfy this prerequisite.

The original frozen unittest child, three and forty-three ordered IDs,
subtest observer, source/runtime guards, full raw/returned owner checks, and
180+3 per-group limits remain intact. The duplicate method remains in both
groups: 46 executions and 45 distinct IDs. The original packaging interpreter
and test subprocess behavior remain unchanged. No source or hardlink is made.

The R2 launch remains a template until an actual separate admission result
exists and its SHA is frozen. Root must review and authorize that next launch.
The original 1-GiB regression storage floor remains unchanged. Neither the
old FAIL nor a successful readback authorizes running the retained tests.

Inspect Native17, VM12, the machine-entry busy negative, current-cold, default
activation, CLI op10, and whole-CLI qualification remain outside this recovery.
