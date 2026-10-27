# Agent workspace transactions

`hepta.patch.v4` publishes a complete, natively validated project snapshot.
It extends the body-only v1/v2 protocol and the read-only v3 preview without
claiming that multiple ordinary file replacements are atomic.

## Reader and writer contract

The workspace has immutable `versions/<content-and-profile-hash>/tree/` directories and a
single `CURRENT` reference. A writer captures all candidate files, checks the
complete import graph with Hepta and the pinned Rust compiler, writes and
fsyncs the complete version, then atomically replaces `CURRENT`. Readers call
`pin` once and use the returned entry for their entire build or query. A
reader holding the old version can continue to use it after publication.

POSIX `flock` serializes cooperating writers; expected-version comparison is
performed while holding the lock. Each snapshot is content checked on access.
Files, containing directories, and the commit reference are fsynced in order.
The guarantee depends on a filesystem implementing those POSIX durability
operations. This is not a sandbox against malicious same-user filesystem
mutation. Mutable editor checkouts are not silently rewritten: the published
version tree is the build input and the unit of consistency.

The journal distinguishes a prepared candidate from a published version.
Recovery trusts `CURRENT`, verifies its complete tree, and records whether the
last transaction committed or aborted. It never publishes an abandoned
candidate. Actual process-death tests cover both sides of the publication
point. An I/O failure after possible publication reports `recovery_required`
and an observed `applied` value, or `null` when it cannot be determined.

## Commands

```bash
python -m hepta workspace init /tmp/project-versions \
  --root /path/to/project-bundle --entry src/main.hepta
python -m hepta workspace inspect /tmp/project-versions
python -m hepta workspace patch /tmp/project-versions \
  --request /tmp/change.json --apply
python -m hepta workspace pin /tmp/project-versions
python -m hepta workspace recover /tmp/project-versions
```

Run ordinary `check`, `build`, or `run` on the **pinned** entry returned by the
workspace. Pinning separately before reading each source file would violate
the reader protocol. Historical versions remain available; garbage collection
is not implemented because deleting a version could invalidate an active reader.

## Semantic editing and interface migration

Inspection returns snapshot-bound node IDs for declarations, function bodies,
statements, and expressions. IDs include the source content hash, relative
path, node kind, and exact source span. They are stable for that snapshot, not
permanent symbols after arbitrary edits. An edit identifies the node and its
replacement; overlapping edits and a replacement that introduces extra syntax
outside the node are rejected.

Only modules in the validated import closure can be edited. Other files in
the explicit bundle are captured and hashed but are not advertised as checked
Hepta modules. The manifest lists the actual `validated_sources`.

```json
{
  "schema": "hepta.patch.v4",
  "expected_version": "<snapshot version>",
  "expected_interface_sha256": "<inspected interface hash>",
  "interface_policy": "migrate",
  "edits": [
    {"op": "replace_function", "target": "src/api.hepta",
     "node": "<function node ID>", "replacement": "<one complete declaration>"},
    {"op": "replace_body", "target": "src/main.hepta",
     "node": "<body node ID>", "replacement": "{ /* updated caller */ }"}
  ]
}
```

`preserve` rejects any change to the full declared interface. `migrate`
explicitly permits a changed interface and still validates every imported
caller together. Returned-borrow modes participate in the interface hash.
Successful native validation proves neither behavioral equivalence nor that
downstream projects outside the captured dependency graph were migrated.

## Captured inputs and current limits

The explicit bundle must contain the complete local dependency graph. Symlinks,
non-regular files, escaping dependencies, and missing foreign headers are
rejected. The current bound is 1024 files and 16 MiB; Git metadata and Python
bytecode caches are excluded. Stores and source bundles must be disjoint.
Captured C import metadata is rewritten to a package-contained relative header
reference while preserving the probed header hash; native-host import rules
still apply. Package content locks are regenerated inside the candidate tree.

The target and compiler identity are fixed for a workspace. After changing the
compiler, initialize a new workspace to obtain fresh validation. Adding or
removing modules and changing package topology are not v4 edit operations;
initialize a new explicit bundle for those changes. Foreign implementation
contracts remain external obligations. These limits are visible rejections,
not claims of complete arbitrary-project migration.
