# Exact current-commit Git source delivery

This transport exports the **unchanged original commit object and its complete
root-tree, subtree and blob closure**. It deliberately excludes ancestor history.
The original parent headers remain inside the commit bytes; `.git/shallow`
declares the selected HEAD as the only boundary when that commit has parents.
This is a complete checkout of one exact commit, not a complete history export.
No HIA compiler, product test, cold budget or retained-suite budget is changed or
executed by this transport.

The original `tools/hia_core_source_identity.py` is executed without modification
from the selected source, using `python -I -S -B`. Its `_source_state()` hashes
every raw HEAD leaf against its Git blob and owner executable bit. The transport
additionally hashes every raw Git object, retains empty subtrees, requires exact
object-database equality, reads every working leaf independently, runs strict
full `git fsck`, and exercises a second real Git clone from the reconstructed
repository. The synthetic controls use the existing helper bytes with SHA256
`24d88246cac15b63ec93203cf8789742cd801f7dc12c335aba81becddbbd1a87`.
The final selected repository's own helper identity is recorded in its manifest;
the synthetic helper pin is not substituted for the selected source.

## Operator sequence

1. Review this script and `.github/workflows/hia-source-custody.yml`, integrate
   them into the intended candidate, and freeze its canonical commit/tree.
2. Create a new `codex/hia-source-custody-*` ref pointing at **that same commit**.
   The narrowly scoped push workflow exports exact `GITHUB_SHA`. It uses one
   depth-one checkout with `persist-credentials: false`; it does not resolve a
   second arbitrary branch. `workflow_dispatch` is also available once GitHub's
   default-branch workflow requirement is satisfied.
3. Require the workflow to succeed and inspect its exact run/attempt/commit and
   artifact metadata. Download the artifact with the official
   `github_download_workflow_artifact` connector, not a second Git fetch.
   The tool arguments are `artifact_id`, `repo_full_name`, and optional
   `file_name`. Its returned temporary reusable download reference is transport
   material; do not publish an authenticated or signed URL in evidence.
4. Preserve the original artifact ZIP, its observed size/SHA256, run identity and
   extraction inventory. Extract only into a fresh private directory with path,
   duplicate and file-kind checks. Do not treat an artifact filename as a pin.
5. Read the externally verified `IDENTITY.json` and manifest pins. Run the
   artifact's exact, reviewed `package/source-package.py` against two separate
   new directories and a new report path outside both. Retain a failed partial
   import as evidence; do not merge it into an existing checkout.

```sh
python -I -S -B package/source-package.py materialize \
  --package package \
  --destination /new/private/root/source \
  --reproduction-destination /new/private/root/clone-reproduction \
  --expected-commit FULL_REVIEWED_COMMIT_SHA1 \
  --expected-tree FULL_REVIEWED_TREE_SHA1 \
  --manifest-sha256 EXTERNALLY_VERIFIED_MANIFEST_SHA256 \
  --report /new/private/root/materialization.json
```

The manifest pins the complete ordered tree inventory, each raw object's type,
length and SHA256, all leaf paths/modes/blob IDs/SHA256 values, pack bytes, the
unchanged source helper, the transport program, and before/after source-state
receipts. Both exporter and consumer require clean exact-source states. Consumer
pins are required inputs, not values silently trusted from the same unverified
package. The original commit SHA1 and tree SHA1 independently constrain every
object reachable in the source snapshot.

The pack is generated from an explicit object-ID list, without revision traversal,
thin packing or excluded bases. Import uses `index-pack --stdin --strict`, a
declared shallow boundary and full strict `fsck`. No replace refs, graft file,
object alternates, inherited Git namespace/object/config overrides or lazy object
fetch are accepted. The package contains no original repository Git config,
credentials, hooks or parent-history substitution. The second clone uses the
local file transport with `--no-local --no-hardlinks --no-tags --no-checkout`; it
is independently checked and its object-storage inodes must not overlap the
first reconstruction.

## Supported source and trust boundary

The transport follows the existing `_source_state` profile: SHA1 Git repositories,
UTF-8 paths, directories and regular `100644`/`100755` leaves on Linux. Symlinks,
submodules/gitlinks, unsafe paths and other modes are rejected explicitly. It does
not filter such entries out. The current HIA source must satisfy this same
existing profile; changing that profile requires a separate review.

The selected commit, source identity helper and transport program are reviewed
repository code. Running `_source_state` executes that source helper. This is not
a sandbox for arbitrary hostile repositories. The detached reconstructed HEAD
has no parent objects, and tools requiring ancestor history must not infer that
history exists. Source custody PASS does not grant language, native execution,
performance, cold or full-regression qualification.

Both destination directories are create-only. The workflow timeout is a transport
job limit; the project's original 180-second cold and 10800-second retained-suite
limits are unchanged. The workflow retains the package and available original
failure receipts even when its transport verification fails. It uploads only the
object package and receipts, not duplicate reconstructed checkout bytes.

## Actual controls and their limits

`test_source_package.py` creates a real synthetic merge commit, makes a genuine
depth-one `file://` clone, exports it, and invokes the standalone artifact consumer
in a separate isolated Python process. The tree includes an executable, an empty
blob, an empty subtree, a binary of 2 MiB plus 7 bytes, and a UTF-8 path containing
spaces, a tab and a newline. The final local run, `controls-r3`, executed 13 controls
in 2.046599086 seconds on Python 3.12.14 / Git 2.52.0 with all controls passing.

The controls include exact raw commit/parent preservation, absence of ancestor
objects, complete source equivalence and real clone reproduction; wrong external
manifest pin; changed shallow boundary; missing large blob; missing empty tree;
extra unreachable object; changed executable mode; truncated pack; occupied
destination preservation; and original-helper rejection of byte drift hidden by
`assume-unchanged` and mode drift hidden by `core.fileMode=false`.

`controls-r1` is retained as HOLD after five controls: its assertion expected the
missing empty tree to be rejected by `index-pack`, but Git actually rejected it
at the subsequent full strict `fsck`. It was never accepted as a valid package.
The control was corrected to check that actual rejecting gate, and Git failures
now retain both stdout and stderr. The earlier wrapper did not retain fsck stdout
inside its exception text; its original report is not retroactively embellished.
`controls-r2` passed 12 controls; `controls-r3` adds mandatory real clone
reproduction. These small controls do not claim a completed Actions export of
the full HIA repository or a desktop source materialization.

A separate, subsequent `runner-local-clone-r1` control passed in 0.288444281
seconds. It uses the original v7/v8 commands verbatim:
`git --no-replace-objects clone --quiet --no-hardlinks --no-checkout SOURCE COPY`,
then `git --no-replace-objects checkout --quiet --detach HEAD`. Its complete
original `_source_state` before/clone/after records, raw commit bytes, object set,
shallow HEAD boundary and strict fsck agree, with no shared object-storage inode.
This is one additional control, not a rerun or relabeling of the original 13.
The exporter and workflow algorithms were unchanged by this compatibility check.

To run the controls against an unchanged copy of the original helper:

```sh
python -I -S -B experiments/hia_git_source_package_20261111/test_source_package.py \
  --original-helper /exact/source/tools/hia_core_source_identity.py \
  --evidence-dir /new/private/control-evidence
```

## Primary references

- [Git pack-objects](https://git-scm.com/docs/git-pack-objects): explicit object
  lists, self-contained packs, and the distinct revision-traversal mode.
- [Git shallow repository semantics](https://git-scm.com/docs/shallow): explicit
  shallow commit IDs and missing-parent handling without rewriting commit bytes.
- [Git index-pack](https://git-scm.com/docs/git-index-pack) and
  [Git fsck](https://git-scm.com/docs/git-fsck): pack validation and complete
  object/connectivity checking.
- [actions/checkout](https://github.com/actions/checkout) and
  [actions/upload-artifact](https://github.com/actions/upload-artifact): checkout
  depth, credential persistence and artifact publication. The workflow uses
  immutable action commit pins resolved from the official repositories.
- [GitHub manual workflow requirements](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/manually-run-a-workflow):
  the default-branch requirement for ordinary manual dispatch. The narrow push
  trigger avoids needing a premature main-branch merge just to export a candidate.
