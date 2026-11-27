# Component Git object custody controls

The prior helper accepted an altered loose blob under its original object filename when the working copy was marked assume-unchanged. It also accepted an altered intermediate directory tree under the unchanged link in its parent tree. `git cat-file` and `git ls-tree` labels alone did not establish the raw object identity.

The repaired helper recomputes the existing SHA-1 Git object ID for the raw HEAD commit, every directory tree traversed to a captured input, and every captured blob. It reads the root tree from the verified commit body and follows each path through verified binary tree records. Directory objects are cached within one capture; no whole-repository fsck or history traversal is required. Existing exact source hashes, clean tracked tree, regular file and no-symlink checks, executable modes, native source membership, and post-construction rederivation remain required.

`before.log` runs the four new corruption cases against the original helper at base `060ce11be28009e3769633bf43aeee16aa9a5414`. The blob and intermediate-tree cases expose false acceptance. This Git version already rejects the altered commit and root tree, so those two cases remain refusal regressions rather than newly discovered false acceptance. `after.log` runs all 15 test methods, including the previous custody controls, against the repair; all pass.

The tests create disposable, independently initialized Git repositories. Their synthetic compiler and incomplete cold records exercise only this custody reader. They are not evidence of a real HIA cold build, installed product execution, or complete native delivery. `report.json` retains exact file hashes and the original blob counterexample, including Git fsck's independent hash-path mismatch.
