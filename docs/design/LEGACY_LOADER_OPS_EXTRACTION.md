# Mechanical legacy loader extraction: isolated differential candidate

> Historical snapshot note: The following experiment describes #621. Its recipe now uses immutable pre-extraction baseline inputs after the normal-source implementation; see NORMAL_LOADER_EXTRACTION.md. Production never executes this recipe.

Status: executable experiment stacked on #620 at
`cbc6e494b4c2c52608586c15dfd1ca843e57529f`. No production `hepta/` file changes,
production import, CLI switch, default limit or bounded-loader claim.

## Why a recipe instead of a third handwritten loader fork

`experiments/legacy_loader_ops/candidate.py` reads exactly pinned production
`modules.py` and `packages.py`, checks their SHA-256 hashes, then applies explicit
old/new/count substitutions. Any source drift or occurrence mismatch refuses to
construct the candidate. The resulting modules use a fresh experiment namespace;
production `hepta.modules` and `hepta.packages` are never replaced. This dynamic
compilation is a test harness, not a proposed production loading mechanism.

The unchanged source is the sole domain-algorithm definition. The recipe exposes
precisely the extraction edits without adding another copied 400-line loader.
It introduces `LegacyLoaderOps`, threads one instance through recursive packages,
lock snapshots/verification/write rechecks, graph loading and unchanged(), and
uses it for eager bytes, inventory, JSON/TOML decoding, tokenize and parse.
The original lock staging/fsync/replace/cleanup algorithm is retained exactly.

A future production change would apply the reviewed edits mechanically in normal
source modules and import a normal operations implementation. Do not ship runtime
source rewriting, relax the pins, or use this recipe as a fuzzy auto-updater.
The legacy operations object intentionally has no counters, deadline, owner-thread
checks or input bounds. A falsey supplied object is retained; only None chooses
a fresh legacy instance. No global mutable operations instance is installed.

## Deliberate behavior preservation

- Byte reads remain `Path.read_bytes`, inventory remains `Path.rglob` followed by
  the existing sort, and JSON encoding detection/TOML decoding remain unchanged.
- Parsing still tokenizes twice: once for reserved-name screening, again in parse.
  Removing the duplicate requires the admitted-token proposal and a separate
  regression review. Do not combine it with this extraction.
- Existing errors stay at the same catch boundaries. RuntimeError-like operation
  refusal propagates through load and unchanged instead of turning into stale.
  This verifies exception propagation only, not a complete budget error model.
- Legacy overrides retain None/empty behavior, eager conversion of all entries,
  alias last-wins behavior, source identity and disk revalidation semantics.
  The stricter bounded-editor model from #620 is not used here.
- Existing source/file-symlink and directory-alias behavior, package locks,
  generated C sidecar/header identity checks and race diagnostics are preserved
  in the tested corpus. Lock race leaves the prior destination intact and removes
  the temporary staging file.

The experiment adds a private `_ops` dataclass field to its LoadedProject with a
fresh legacy default, excluded from repr/equality, preserving old constructor
arguments. Its report schema does not expose it. This is NOT Python object ABI
compatibility: dataclass field enumeration/asdict, class identity, pickling and
third-party direct introspection differ. Before production extraction either
review those consumers explicitly or keep session ownership in a separate
internal handle. No claim of drop-in compatibility across those surfaces is made.

## What remains outside these operations

Path.resolve/is_file/is_dir/is_symlink, ancestor manifest discovery, graph edges,
depth admission, digest/serialization/deepcopy, atomic filesystem publication and
native Prepared processing still use the original algorithms. The read role
`revalidation` is a label, not the retained narrow source/header/sidecar role needed
by a bounded implementation. It is deliberately insufficient for a bounded
session. Package objects also do not carry a session: standalone snapshot callers
must pass ops explicitly. The graph handle retains it for unchanged checks.

Consequently this interface cannot yet host #619's full policy safely. Future
steps need explicit path/edge/depth checkpoints, role provenance, token ownership,
request lifetime and diagnostics before any bounded adapter is admitted. A type
conforming to these six methods does not prove it bounds any resource. No public
API is offered for untrusted custom operations; callbacks are ordinary Python.

## Differential oracle

`python -m unittest experiments.legacy_loader_ops.test_differential -v`

The oracle calls original and extracted loaders on the same frozen fixture and
compares full reports, complete AST dataclass structure, source bytes, unchanged
results, full Hepta diagnostics or ordinary exception type/message. A reader/
lexer spy compares actual read order and duplicate lexing. Spies are scoped test
contexts, never part of candidate initialization or persistent production patches.
For mutation cases the fixture is reset for each side and mutation is injected at
the same ordinal read, so the second loader does not see the first loader's work.

26 controls include all 80 repository .hepta examples (68 graph loads and
12 matching E_MODULE_READ failures from missing import/generated inputs), six
explicit representative graph cases, None/unused/used/aliased
overrides, malformed/invalid-UTF8/missing sources and manifests, valid/missing/
invalid/stale locks, locked overlays, diamond/private/cyclic graphs, file and
directory symlinks, C sidecar/header identity, operation ownership, falsey ops,
error propagation, lock bytes, postload mutation/except_paths, load race,
lock-publication race, recipe drift and forbidden direct read/parser call sites.

This finite corpus is useful counterevidence, not a proof of all programs, all
Python versions, all OS/filesystem failures or native ABI behavior. C sidecar
fixtures exercise loader metadata checks, not a real imported foreign call.
No native compiler is required by these new differential tests.

## Review and promotion gates

Independent review must challenge the recipe and oracle, especially assertions
that accidentally compare two failed results, source mutation between runs,
diagnostic phase/path preservation, recursive ops forwarding and stage cleanup.
The focused CI requires 81 unique controls on exact PR HEAD with zero skips.
The previous #620 55 controls remain part of this gate; native #619's164-per-host
qualification is separate evidence and is not rerun or claimed here.

Before production editing: expand differential coverage to supported Python/OS
versions, malformed metadata representations, package dependency cycles/diamonds,
path retargeting during loads, write/fsync/rename failures and consumers of
LoadedProject dataclass identity. Then independently review the actual production
source diff. Do not equate the isolated recipe's pass with permission to remove
legacy entry points or enable bounded defaults. No merge or deployment.
