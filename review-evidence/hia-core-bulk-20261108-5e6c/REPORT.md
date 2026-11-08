# Native selfhost bulk buffers: 37 of 50 Core operations

Adds buffer.fill, buffer.fill_range, buffer.copy, buffer.copy_range and
buffer.move_within to the native HIA selfhosting compiler. Range guards check
offset before subtraction and check every range before writes. Overlap uses
forward/backward byte copies and restores DF. No external bulk routine is called.
Existing SSA, block, instruction, source, output and workspace bounds remain.

The new independent Core VM/Python oracle has 58 byte cases and 34 invalid
signatures. Both B3 and mutated M3 execute them; five flat/ELF comparisons per
compiler bind the object writer. The language inventory includes all five new
operations and all 34 rejected signatures. Ownership, borrow creation and chain
operations remain open: 37/50 is not whole-Core selfhosting or a refinement proof.

During this turn, the first attempt correctly failed the unchanged SSA ceiling.
Moving dispatch to its own HIA function fixed it. A separate inventory test
caught the five declared operations missing from its own witnesses; that was
fixed by adding them. The next full native run passed 557/557, cold replay
10/10 (full inner run), and language coverage 812/812. Independent review checked
machine branches and DF restoration and requested explicit source-unchanged
checking; all 64 earlier successful bulk receipts met the added predicate.

The executor then reset and discarded its transient filesystem before those
raw local reports could be published. Their earlier tool outputs remain session
observations; unavailable raw files are not claimed as retained public evidence.
The source was recovered from the SHA256-verified GitHub CI artifact for
2598f4309791d3a023cd5df585ad26810b20c744, whose 229 source files each match its
contract. Reconstructed assembly is byte-identical to the earlier reviewed
assembly: 1f8bcdf1c541d5f8ee7595dfc3905746874fd89455ca32c46ec329233030f68b.
The 58/34 independent references and 23 source tests passed again. Final exact
published-source CI must rerun and retain the complete evidence before release.

The first exact-source GitHub run
[42503706647](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42503706647)
subsequently retained fresh original evidence for source
`d93fa40dab62261c9184dc6f6c3dca5878add134`: direct native 173/173 with no skips,
selfhost native 557/557, cold replay 10/10 and language coverage 812/812.
Original and mutated generation hashes exactly match the earlier observations.
The run still failed at release-lock freeze: the new bulk helper was declared
in the selfhost closure but missing from the release entry's explicit file
inventory. No lock was produced or admitted by that run. Its uploaded artifact
is 16,948,400 bytes, SHA256
`ef93e178a190de7a4eb8d5b930b26d54c6e0be41b8b62adf41d1b613a832fc7c`.
The [retained observation](first-ci-result.json) binds exact report member hashes
and the [original refusal](first-ci-release-freeze.log).

The follow-up adds the missing release inventory member and a regression that
compares the complete selfhost source closure with the public freeze inventory.
This repairs the publication input; a later successful exact-source CI is still
required to qualify the integrated source and its release lock.

This source builds on 2598f4309791d3a023cd5df585ad26810b20c744. Public entry and
online installation have separate identities; the PR806 readback of 321daf28
is not transferred to this candidate. Full Core/compiler/ISA/loader correctness
and the original Agent/NDU acceptance criteria remain independent obligations.
