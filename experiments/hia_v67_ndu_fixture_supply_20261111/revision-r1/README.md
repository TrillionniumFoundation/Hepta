# Fresh supply of three NDU fixtures for exact608

This revision supplies missing `ranking`, `raw`, and `dynamic` executables in
`/home/qian-qi/he26v67fixturesr1`. It leaves the original formal attempt,
`/home/qian-qi/he26v67r1`, its source and HOLD reports, and the old fixture
targets/receipts unchanged. The new stable key is
`hia-e26e-desktop-v67-608-three-ndu-fixtures-supply-r1`.

The original formal job `1a1cb8bb359-2564-bcc` completed materialization and an
independent clone, then stopped at fresh prerequisite preparation. Its original
972d preparer found three absent executable paths after its upstream, adapter,
builder, lock and build-input checks. The other three fixtures remained
available. This supplier does not relabel that original HOLD and does not run
the retained suite or cold qualification.

## Actual inputs and new outputs

The source is exact commit `608157e52b0b94e0d294f6b99c4e809869f183aa`, tree
`e7c29a60796a1a78946a2c667aa80df86529e532`, in the prior independent complete
checkout. Its original `hia_core_source_identity.py` checks all 3,925 tracked
file bytes and executable modes against the raw Git tree before and after.
The original builder `tools/build_hia_ndu_bridge.py` remains byte identical at
SHA256 `c4702a063f45b8a75973dc2978c38f414d43121dde7968af165c51b43241e6e8`.

| Fixture | Exact608 adapter | Pinned upstream | Profile |
| --- | --- | --- | --- |
| ranking | `rust/hia-ndu-bridge` | `d3c2d760eca5065fc966820379c35c6e8d56e855` | debug |
| raw | `rust/hia-ndu-raw-model` | `8e52e1187f47f6d4edc8d942fc7cb7eca4bc447d` | release |
| dynamic | `rust/hia-ndu-dynamic-model` | `8e52e1187f47f6d4edc8d942fc7cb7eca4bc447d` | release |

Each call uses the original `build()` with an independent fresh output and
`CARGO_TARGET_DIR`. The fixed Cargo/Rust 1.90 executables, formal CPython 3.14.4,
all 12 existing tools, all 6 old receipt files, and the original manifest's 55
crate archives are hash checked. Cargo uses the existing private cache with
`CARGO_NET_OFFLINE=true`, committed locks and two build jobs. Git is read only,
replace objects and lazy fetch are disabled, and network transport is denied
through the child Git configuration. The controller is not an OS network
sandbox; it invokes the reviewed builder and pinned original Rust sources.

The cache may acquire lock/index metadata. Only the fixed 55 archive bytes and
their observed file identities are asserted unchanged. Old missing target
paths must still be absent at the end. Cargo's newly built executable may be
hard linked to its own fresh dependency output; executable admission keeps
the original preparer's regular-file/hash contract rather than requiring a
single link. No old executable hash is substituted for a new actual build.

The actual original 2,092,116-byte materialization report is copied unchanged
and fsynced into `old-originals/source-materialization.original.json`, bound to
SHA256 `7451e4517a2a00731f8019924127179ff1a4a952e005636b3352edef00efa7e7`.
All original compiler output, failure reports, new receipts, and before/after
source/input snapshots remain in the new root.

## Ownership and acceptance

The original guardian, process owner, and workflow helper are unchanged.
Each original builder has its own 900-second guardian; the supply controller
has a 3,600-second outer guardian. These are supply deadlines. The product's
10800 overall, 180-second cold, two-worker, 38-phase, and 5400-suite gates are
not executed or altered here. Ordinary home filesystem storage must meet the
existing 8 GiB and 100,000 free-inode check.

`report.json` can only reach
`THREE_FIXTURES_READY_PENDING_OUTER_GUARDIAN_NOT_QUALIFICATION`. Independent
`verify_terminal.py` requires that report, three actual original builder
receipts and binaries, complete source/input preservation, and the final
outer guardian's natural completion. Killed live descendants, overflow,
interruptions, errors, missing cleanup fields, or missing ECHILD prevent
acceptance. Hard SIGKILL of the guardian or host loss remains an honest
unknown boundary. No product task or uncertain old job is replayed.

## Control evidence

`local-controls-r1/OBSERVATIONS.json` contains nine actual local controls.
Two run the original guardian: a normal child is accepted; a leader that
leaves a live child in another session is rejected even though the guardian
has cleaned it and emits its generic completed status. Both actual runs
reap all owned children. Five receipt mutation controls reject missing or
bad ownership evidence. Two file controls reject an existing destination
and a wrong hash while retaining the original bytes.

The three exercised helper functions are AST identical in the final source;
`FINAL-HELPER-BINDING.json` binds that comparison and the original tested
common source, whose byte hash is reproduced exactly. Later static changes
only strengthen complete build-input/log and command/cwd binding. These
controls do not claim a Rust build, remote execution, or HIA qualification.

`PREEXECUTION.json`, `request.frozen.json`, `payload.frozen.json`, and
`launch.frozen.json` are the reviewable exact launch bytes. The launch is
create only and uses the formal Python with an explicit argument vector.
Current preexecution metadata records no remote dispatch; an eventual real
job acknowledgment and terminal receipts will be preserved separately.
