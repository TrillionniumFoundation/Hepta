# Baseline-preserving local merge preflight

This is a local Git merge and ancestry review. It creates no remote references and runs no compiler, solver, native program, or project tests. It establishes a candidate tree and ancestry, not release qualification.

## Exact observed inputs

| Role | Commit |
| --- | --- |
| PR821 current head | e0c1ac3c97bb296e288de3d37b01f65d87772832 |
| PR822 current head | ff456fd8a4df2b61f34b479c89f96ffcf65a9e5f |
| Actual source5 branch | 20eace37747fde9aa0fc9c14cdb0159db30f5161 |
| Actual source6 branch | 2598f4309791d3a023cd5df585ad26810b20c744 |
| Previously qualified PR817 head | 6a8c297b3f8f21506d11c2cb093c1c58d84ffe55 |

All five heads were read from actual Git ref endpoints. PR817, PR821, and PR822 metadata were also retained. The final observations still report the pinned values. These are time-specific observations; a later publisher must recheck its expected heads.

## Ordinary merges and proposed parent order

The existing ordinary e0 + ff merge produced tree 4c51962e030e9ea39c6498224c99eb40fbdd2f35 without content conflicts. That exact pending merge was recorded as local commit 00bd5a20522608ae2b3c8fb03e2965e679480dc4, with parents e0 and ff.

Actual source5 commit 20eace is not an ancestor of e0 or ff. An ordinary merge of 20eace into that fusion succeeded without conflicts or content changes. The reverse parent order was then independently exercised by an ordinary merge of the fusion into 20eace. It also produced exactly the same tree.

For the proposed source5-first-parent publication, the local review node is 183644501a7736baeaac21b1bdfab61e4dbc76eb, with parents 20eace37747fde9aa0fc9c14cdb0159db30f5161 and 00bd5a20522608ae2b3c8fb03e2965e679480dc4. Its tree remains 4c51962e030e9ea39c6498224c99eb40fbdd2f35.

Source6 commit 2598 is already an ancestor of both e0 and ff. No additional merge is needed to preserve it. Explicit git merge-base --is-ancestor checks establish that e0, ff, 20eace, 2598, and 6a are all ancestors of the final local node.

Local commits were recorded with git commit-tree only after ordinary merges produced and checked their trees. They are local review objects. Publisher-created A and B commits will have their own identities; this package does not predict or substitute those SHAs. The proposed graph is A(parents e0, ff), then B(parents 20eace, A), with the verified tree for both.

## Reusable tree updates

tree-updates-from-ff.json contains exactly 11 existing blob entries for Git tree creation from ff base tree 955dcedbd30924e5815bb106b506ec28262545e3. Each mode, path, and blob SHA was checked against the resulting tree, and each blob equals the existing e0 blob at that path. All remaining ff entries are unchanged.

The expected reconstructed tree is 4c51962e030e9ea39c6498224c99eb40fbdd2f35. The publisher must verify the actual returned tree and actual commit parents before updating any ref.

## Content preservation and qualification

The final tree is identical to the Git tree reviewed in the preceding e0 + ff preflight. Relative to 6a it has 64 changed paths and no deletions; changes-relative-to-6a.tsv lists every path. Both baseline merge orders change zero paths relative to the e0 + ff fusion.

All 380 existing review-evidence blobs remain unchanged. The e6 current-compiler cold-consumer CI step, c36 clock-anchor correction, e0 SQLite state artifact exclusion, and ff implementations remain present in the identical reviewed blobs. This ancestry-only merge changes no capacity limit or strict Agent gate.

No earlier head or prospective merge checkout's CI qualification transfers to this new final commit. The published candidate must obtain its own required CI results and original exact-source artifact. The separately observed 6a terminal inventory is 19 successful workflows and 114 jobs comprising 113 successes plus one unrequested conditional skip; it must not be described as zero skipped jobs.

The candidate ancestry permits a future nonforce fast-forward from either observed source branch. Source5 and source6 were not moved. The publisher must check then-current expected heads and the exact final candidate's own qualification before any such update. A later content or ancestry change requires recording its actual final commit identity.

## Retained evidence

git-operations.json records actual local commands, outputs, and exit codes. merge-result.json retains the intermediate pending-merge state; final-preflight.json records the final local node, alternate parent order, and ancestry checks. Before/after API JSON files retain source-ref and PR observations. files.json binds package bytes.

The independent review checkout ends clean. No author working copy, remote ref, online configuration, original evidence package, or historical failure record was changed.
