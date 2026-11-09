# Independent NDU review of source 6a8c297b

**Native integration and offline ledger replay pass for their stated subjects;
stable incremental value and economic benefit remain HOLD.** This review uses
the original successful [scalar selection run 42558245656](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42558245656),
attempt 1, for source `6a8c297b3f8f21506d11c2cb093c1c58d84ffe55`, tree
`635d02f8f2b8151ae4697365e1962b070e4015a3`. It does not transfer qualification
to a later merge commit or public installation.

## Original artifact and retained records

GitHub artifact `13648987153` is 8,085,898 bytes; its official and locally
recomputed ZIP SHA256 is
`b115dda0b04c35f9fb60a6d26eacd4aa74cb479af27c7179c165e5a2d93057b0`.
[github-artifact.json](github-artifact.json) retains the official artifact
metadata without a temporary signed download URL.

[original-ci-members.tar.xz](original-ci-members.tar.xz) retains all 475 original
file member byte streams, 37,744,634 uncompressed bytes. It is a deterministic
1,267,908-byte tar.xz with SHA256
`8ee3b255d4b1803b3b05709e198370738ab54724a0a3e9837eabacf89b834aff`.
This is a new container, not the original ZIP byte stream. The original ZIP
identity, member attributes and each member's size and SHA256 are retained in
[original-ci-members.json](original-ci-members.json). Every retained tar member
was read back and compared with its original ZIP member.

The original CI records report 172 integration tests, zero failures, errors or
skips, and three successful required Rust controls. Source observations before
and after the run bind the stated commit and tree and report a clean checkout.
The retained native binary was rehashed, not executed by this reviewer:
2,345,848 bytes, SHA256
`494d198e94f533c8a894dc141a42be2890fa12bce14d9b4b2c849ee5fbf46cb5`.

## Independent replay

Only the exact-source standard-library ledger replayers were executed locally.
They read the original records; they do not launch a native program, compiler,
solver or model. Both returned exit 0 and reproduced the original CI replay JSON
byte for byte. Each campaign contains 72 complete cells, with zero failed or
unstarted cells and zero automatic retries. Each replay checks 1,020 original
native responses and 510 ordinary calls; these are retained observations, not
new evaluations.

| Campaign | Frozen registration SHA256 | Exact-source replayer SHA256 |
| --- | --- | --- |
| Prepared | `44f2ce2a68964c803039e53a9cad66548fe6db6ac794b25302f1b9d1659b8f98` | `9f4fb093932821f81c454015187d66dc8b77898bd713899184bc15df95bdcbfb` |
| Persistent | `6acc816bdb201bd6e76cb562240d1d08c32cd9be903b445145dda42f61cf272e` | `c0433f4acb1a03002f963e46309f40db09ab1d39013cb7b312691cb92be5ad09` |

The independent replay JSON and stdout are retained alongside this report.
[summary.json](summary.json) contains the complete recomputed counts, medians,
source identities and qualification boundaries.

## Results against the ordinary implementation

Each horizon has six pairs. Values below are median recorded cell time in
milliseconds; the two campaigns are separate observations.

| Horizon | Prepared campaign: ordinary | Prepared | One-shot | Persistent campaign: ordinary | Persistent | Prepared control |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 0.110056 | 7.065453 | 9.504652 | 0.120953 | 7.137351 | 6.791329 |
| 4 | 0.404795 | 12.823321 | 38.462826 | 0.466184 | 10.995410 | 13.196719 |
| 16 | 1.522504 | 36.592985 | 156.384932 | 1.818265 | 25.381835 | 37.848693 |
| 64 | 5.769050 | 131.698792 | 616.035230 | 6.988952 | 81.687930 | 134.855405 |

Ordinary is faster in all 24 pairs in each campaign, with identical selections.
Prepared beats one-shot in all 24 transport comparisons. Persistent beats
prepared in all 18 comparisons at horizons 4, 16 and 64, but only one of six at
horizon 1; its horizon-1 median is slower. Improved transport does not establish
incremental value against the ordinary implementation.

Original campaign time through summary construction is 6,207,722,543 ns for
prepared and 2,083,449,526 ns for persistent. These timers exclude caller startup,
source acquisition, retained native build and final summary writing. Nested
times are not added to campaign wall time.

## Scope and remaining blockers

Replay establishes record identity and internal arithmetic consistency; it does
not independently authenticate original timing measurements. The host was shared
and nonexclusive. These were synthetic finite cost tables with no real Agent task
or model invocation. Prepared and persistent use an admitted immutable executable
snapshot; a persistent round is advisory until its owner closes successfully.

Full authoring, provider/model, engineering, monetary and energy costs remain
unknown. Missing costs are not zero. Machine refinement, whole-lifecycle cost,
stable incremental value and economic benefit are not established. Historical
failures and the separate earlier campaigns remain in their original reports.
