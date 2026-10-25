# Reconstruct reviewed source

Review reports identify local commits and file hashes. Those local commit IDs
need not exist on the published remote. Each patch here reconstructs the tracked
source files of its reviewed commit from public base
`cbb03dfd6efbe68253c2be1e59eacdeb93f9dfc5`. Generated evidence and artifacts are
excluded, as they are excluded from the release source snapshot.

Use a fresh detached checkout of that base and apply exactly one selected patch
with `git apply /absolute/path/to/the.patch`. Then run the matching replay script
and compare the implementation/source hashes recorded by the review. Do not
apply multiple patches in sequence: each patch starts at the same public base.

Historical failing implementations are retained for reproduction, not recommended
for use or accepted as release candidates. Final code and unified qualification
are recorded in the published branch and `../../next_blockers_final/manifest.json`.
