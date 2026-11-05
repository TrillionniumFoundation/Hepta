# Typed package migration on exact composed source

This finite P12 integration composes existing capabilities rather than implementing
another resolver, codec, typed Result or compiler lowering.

- Base #710: `0594a85f2f1e05ef50a61bf9c5a18ae191499502`.
- Resolver/lock supplier #709: `653b508336a470151b94f5e1c0448654c4782030`.
- 277 of all 281 base files remain byte-identical. Two production files
  (`hepta/cli.py`, `hepta/packages.py`) are replaced by exact supplier bytes;
  `package_resolution.py` and `lock_diff.py` are also exact supplier files.
- Twelve supplier files retain their original Git blob and SHA-256 identities:
  four production files, three test modules, three oracles, the 65-method
  inventory and the package-integration contract.
- Original compiler files and two original provenance manifests are retained
  under `tools/versioned_typed_origins`. The store provenance changes exactly
  two compiler hashes. The typed provenance changes those two identities and
  the adapted store manifest identity. Structural inverse checks recover the
  original manifests, including their exact bytes. No inherited test or checker
  code changes, and no inherited workflow is removed, disabled or weakened.

`tools/verify_versioned_typed_sources.py` verifies the supplier inventories,
originals, narrow adaptations and three byte-identical copied example sources.
The inherited typed and store provenance checks remain active. The composed
compiler includes no new implementation edits.

## Example and migration contract

`examples/packages/versioned_typed_text` uses explicit package names, bounded
requirements and local candidates to select `versioned_typed_packet`, which
selects all four existing source libraries. All are unchanged 0.1.0 sources.
The application entry, typed adapter and packet source are byte-identical to
#710. Seven modules in six packages load under a checked-in content lock.

The typed result is still `Result<Committed<Bounds>, PacketError>`, with ordinary
Copy records and Unit. Errors distinguish Decode, ShortHeader, LengthMismatch,
InvalidText and ScalarCapacity. The latter retains the complete caller scalar
slice length. Decode errors leave scratch unchanged; later errors retain decoded
scratch; every failure preserves scalar backing. The marker is an ordinary
value, not authority, durability or a transaction receipt.

Disposable tests create low/high package candidates with synthetic version
numbers. They really resolve, lock, compile and execute the selected real source
libraries and typed application. They are not published package releases.
Migration and rollback are explicit fixture actions, not automatic migration or
an atomic filesystem operation. `lock-diff` keeps `compatibility: not_assessed`.
A valid content lock can describe behaviorally wrong code.

Twelve joint methods cover complete transitive upgrades, root-driven backtracking,
all errors and complete physical backing, selected/unselected edits, unsatisfiable
refresh with original lock preserved, equivalent ranges, same-version retargeting,
relocation and public CLI execution. Two deliberately wrong candidates (ordering
and typed error payload) compile with valid locks but fail native assertions.
Restoring the exact earlier manifest and lock selects the working low graph.

## Reproduction and strict qualification

Run from a clean source export with GCC and assertions enabled:

```
python -B tools/verify_versioned_typed_sources.py
python -B tools/qualify_versioned_typed.py --verify-only
python -B tools/qualify_versioned_typed.py
python -B tools/versioned_typed_oracle.py --root . --native
python -B -m hepta run examples/packages/versioned_typed_text --locked --backend c --json
```

The complete C-mode inventory is 484 unique methods: the entire 407-method typed
inventory in unchanged order, all 65 original package methods, and twelve joint
methods. The three package-specific modules are fully discovered; nine original
module/package controls retain their explicit selected identities. Missing,
duplicate, skipped, expected-failed and unexpected-successful tests fail the gate.
Planned, started, finished and passed identities must match exactly, and every
materialized file must retain its pre-run digest. `--verify-only` runs provenance,
compiler availability and inventory checks, not test bodies or native consumers.

Thirteen oracle scripts are required: all nine inherited typed/compiler/library
oracles, the three original resolver/lock oracles and a new independently authored
migration oracle. That oracle builds its complete expected lock snapshots directly
from the known fixture graph and independently hashes every input. It checks
selection order, stale refusal, low/high/low transitions, eight typed vectors with
all six outcomes and complete backing state. Its unchanged inherited Python typed
model supplies the payload/storage expectations. Four actual valid-lock mutations
(wrong bound, wrong error tag, wrong error payload, modified scratch canary) must
abort, and exact source+lock restoration must execute successfully. O0 and O3 use
nonrecovering UBSan. This is internal aggregate/process observation, not public
aggregate C ABI qualification. Counts from overlapping oracles are not additive
whole-language evidence.

Required-Rust mode uses `HEPTA_ENUM_REQUIRE_RUST=1` and the pinned real Rust 1.90.0
compiler, requiring the original eight additional methods for 492 total. The
library/native test backend is selected with `HEPTA_VERSIONED_TYPED_BACKEND`.
The nine inherited C oracles and the new C migration oracle still require GCC
in either mode, as in the inherited typed gate. Missing selected tools fail.
Native Rust, AArch64 and Python 3.11 have not been executed locally for this
composition; C/Python 3.12 and 3.13 results are separate exact-source evidence.

No new hosted workflow or matrix is added or manually dispatched. Existing
path-triggered gates remain intact; parent greens and queued jobs do not qualify
this head. The new union gate currently has local evidence only. Future hosted
coverage can be added separately when appropriate rather than expanding the
existing backlog by another broad matrix.

## Limits

This is a bounded integration qualification, not general resolver correctness,
API/ABI compatibility, compiler refinement, performance improvement, registry,
distribution/signing, installer packaging, or a production standard-library release.
No recursive execution, literal admission, signature audit, C-import publication,
or output/alias behavior is changed or qualified. The source provenance checks
are identity/inverse checks, not cryptographic authority against a malicious editor.
P01/P11/P12 remain PARTIAL, and unrelated blockers remain open. Draft only; no
merge, release, deployment or activation.
