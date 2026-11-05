# Read-only package upgrade review

P12 still lists compatibility and migration tooling as an open roadmap goal.
`hepta lock-diff BEFORE AFTER` adds one bounded review tool: compare the recorded
package graph and file hashes in two existing `hepta.lock.v1` snapshots. It does
not parse source, invoke a compiler, resolve versions, download dependencies,
change either lock, or assess source/API/ABI/behavioral compatibility.

## Usage

Save the existing lock before making an intentional package change. Regenerate
the candidate lock with the existing `hepta lock DIRECTORY` command, then compare
the two saved files:

```sh
python -m hepta lock-diff before.lock candidate/Hepta.lock
python -m hepta lock-diff before.lock candidate/Hepta.lock --check
```

Comparison needs only the two named lock files. They may be copied elsewhere;
the original source trees need not exist. Recorded `../dependency` paths are
identifiers relative to each snapshot's original root, not paths opened by the
comparison. The command does not rewrite or approve a migration.

Default success exits 0 whether snapshots differ or not. `--check` exits 1 for a
valid comparison with differences, 0 for unchanged snapshots. In both cases the
report has `ok: true`. Invalid lock documents reject with `E_LOCK_INVALID`,
`status: rejected`, exit 1; ordinary file I/O failures retain the CLI's `E_DRIVER`
error and exit 2. Consumers must distinguish a changed report from a rejection,
not rely on exit 1 alone.

## Report contract

The deterministic JSON report uses schema `hepta.lock-diff.v1` and includes:

- `before_sha256` / `after_sha256`: verified recorded content identities.
- `changed`: whether the decoded snapshots differ. JSON spacing, object order,
  and supported JSON byte encodings do not themselves constitute changes.
- `packages`: path-sorted `added` and `removed` complete records, plus `changed`
  records with old/new name, version, kind or entry fields.
- `dependencies`: package/alias-sorted `added`, `removed`, and `retargeted` edges.
  Edges from added/removed packages are included as well as their package records.
- `files`: path-sorted `added`, `removed`, and `changed` content hashes, including
  manifests, unused source files, and C-import sidecars already in the locks.
- `compatibility: "not_assessed"`, always. An unchanged or newly incremented
  version is not a claim about compatibility or correctness.

Packages are matched by recorded path, not inferred name, version, or content.
A move is therefore removal plus addition; a dependency alias changing its target
is explicitly retargeted even when both target packages already exist. Same-path
source changes are reported even if the package version stays the same. Equal
snapshots from unrelated source trees mean equal recorded content, not a shared
provenance or authenticated publisher. No timestamps or absolute input paths
appear in a successful report.

## Admission and limits

The reader requires the exact v1 top-level and package-record fields, root
package, canonical relative recorded paths, valid identifiers/versions/kinds,
SHA-256-shaped file hashes, package manifest hashes, existing library dependency
targets, a reachable acyclic graph, and the v1 canonical content digest. Duplicate
JSON keys, non-JSON numeric constants, malformed encodings, and unknown schemas
reject instead of being silently normalized.

It does not reread recorded source paths or establish snapshot completeness,
authenticity, or current filesystem state. Existing loader snapshots remain
readable, including its unusual accepted `source_root`-is-entry-file case, whose
inventory contains only the manifest. No new promise of entry/source coverage is
inferred from digest validity. Use the existing `--locked` project validation
for its separately documented current-tree checks; this command does not replace
those checks, fix their known limits, or establish atomic observation.

The original comparison increment #691 was based on main
`125d11c5454835a7df1dc51915fc49901fbede5b`. This integration adds the exact #690
local resolver without changing either component's production bytes or the v1
wire format. See [the bounded composition qualification](PACKAGE_INTEGRATION.md). Registry
resolution, semantic compatibility analysis, automatic language migration,
signed distribution, production standard library, native/proof/performance
qualification, and broad P12 completion remain open.
