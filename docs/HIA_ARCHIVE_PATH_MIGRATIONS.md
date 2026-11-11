# Historical evidence paths on case-insensitive filesystems

Two archived directories contained both `BASE.json` (program) and `base.json`
(native receipt). These names collide on common Windows/macOS filesystems.
The program snapshots now use `BASE_PROGRAM.json`. Their original bytes and
both receipt bytes are unchanged; the JSON migration ledger binds all four
sizes and SHA-256 values. Active generators use the distinct program name too.

The original 611-file evidence index also includes its original `VERIFY.py`.
Both remain immutable historical evidence. On the current source, run:

```sh
python -B tools/verify_hia_retained_evidence.py
```

The current entry point pins the exact original index and migration ledger,
resolves only the two declared moves, and checks every original size/hash,
including the original verifier bytes. It retains all 611 logical file identities
and 26,120,286 bytes. Missing unmodified rows, changed bytes, ambiguous paths,
symlinks, traversal and modified contract bytes are rejected. Metadata is read
under an explicit bound; archived programs are never executed. No old experiment
is rerun or rescored, and this check grants no safety or performance certificate.


## Current materialization limit

The frozen index describes 611 files and 26,120,286 bytes; it does not establish
that every indexed file is present in a later checkout. A read-only replay on
the published `ec4841212fa97ae98c576b48f8ba1b4815df6122` checkout and on the
subsequent documentation-cleanup worktree returned the same result: 611 indexed
rows, 2,026,763 bytes actually read, and 574 missing/nonregular-path failures.
The cleanup changed no evidence, experiment, fixture or original index bytes.
This historical collection is therefore **not completely materialized in the
current source tree**, and working-tree integrity verification remains failed.
The original Git snapshot remains independently verifiable as described below.

The original five tests in `tests/test_hia_retained_evidence.py` exercise the
verifier's path-migration and refusal behavior on independent fixtures. Their
success is not a replay of all 611 historical files. A complete working-tree
replay requires every original indexed member at its admitted physical path,
with the original size and hash; missing rows must not be filtered out or
relabeled as passed.

## Verify historical bytes without restoring old files

The explicit Git mode checks the original manifest paths directly from retained
Git objects. It does not restore earlier source or generated outputs into the
active tree:

```sh
python -B tools/verify_hia_retained_evidence.py \
  --git-revision 5c3741da1d36e8c1f79ec728ec325b8d973c899e
```

The [recorded actual replay](../review-evidence/hia-native-cleanup-20261111/retained-history-verification.json)
read **611/611 original files and 26,120,286 bytes**, with no size or SHA-256
mismatch. This closes access to that historical byte collection without adding
574 old paths to the current source tree. It does not confer native product
qualification or change the failing working-tree observation.

The selected revision must already exist in the local repository. The tool
never fetches objects or falls back from current files to Git. A supplied ref
is resolved once to a full commit identity, which is returned in the report;
all later reads use that identity. Git replacement objects are disabled.
Historical reads use the original paths, because the two later case-collision
mappings describe the working-tree layout rather than the original tree.

The same pinned manifest and migration hashes are checked before either mode.
Git mode requires ordinary file blobs, rejects symlink/tree entries, checks
sizes before requesting payloads, and checks every payload's original SHA-256.
It admits at most 4,096 members, 16 MiB per member and 64 MiB total; local Git
command output is bounded and each owned command has a 30-second deadline.
Archived programs are read as bytes and never executed.

Eight additional tests use real temporary Git repositories to check old-source
reads with changed or missing working files, exact-size content mutations,
missing historical paths, wrong revisions, symlink entries, oversized members,
replacement refs and a partial clone whose missing blobs must not be fetched.
The original five path-migration controls remain. Both the thirteen-test result
and the separate 611-file replay are needed to describe the observed verifier
and historical corpus accurately.

The original verifier describes the original layout and is not rewritten to
interpret later layouts. The pinned migration entry point preserves that
original byte oracle. Native-host jobs independently require clean, stable tracked Git
state, and C++ qualification rejects casefold collisions before compilation.
