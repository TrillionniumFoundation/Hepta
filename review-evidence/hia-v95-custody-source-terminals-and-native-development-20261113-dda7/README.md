# HIA V95: completed custody, formal Source terminals, and Native development

This is an append-only evidence publication. It does not change a product source tree or turn development results into whole-system qualification. `whole_native=false`; the old production stack has not been removed.

## Formal results

| Scope | Actual result | Evidence |
| --- | --- | --- |
| R10-R2 formal Source, run 43463604848 | 1,319 PASS; exact 3,083-file generated tree `1d52f28fa841599b9f1be028098a99e6a7a522b8`; complete original artifact independently restored | [formal terminals](formal-terminals/README.md) |
| R11 formal Source generation, run 43468679071 | FAIL at generator 122 `cli_parser_context`: `_colorize.Argparse`; zero product tests; complete failed partial artifact independently restored | [formal terminals](formal-terminals/README.md) |
| R7-R4 product, run 43459534648 | Source 1,274 PASS; Native FAIL with three original namespace-budget failures; 103 later Native steps skipped | [original terminal evidence](r7-r4-terminal/MOUNT-RECIPE-ROOT.json) |
| R12 source and normalized plan | Source integration only; generation and tests not executed; inherits the known R11 generation blocker | [source](r12-source/MOUNT-RECIPE-ROOT.json), [plan](r12-plan/MOUNT-RECIPE-ROOT.json) |

## Completed custody

[R6](r6-complete/MOUNT-RECIPE-ROOT.json) includes all 434 exact base64 transport wrappers and the original metadata. Independent full readback verifies 10,060 logical files totaling 787,835,354 bytes. The original decoder restored all bytes and modes. Its outer wrapper failed a directory-set assertion because the restored layout also requires two synthetic mount parents; that real failure is preserved. A separate read-only verifier proves the recorded 1,570 directories plus exactly those two required parents, without rerunning or relabeling the failed wrapper. Original POST/GET transport errors, the interrupted local ACK persistence, and their read-only or exact-byte recovery records remain preserved. The four original outer ZIP wrapper byte streams are not claimed to be archived in this Git recipe.

The [process cold archive](process-cold/MOUNT-RECIPE-ROOT.json) and [native CLI archive](native-cli/MOUNT-RECIPE-ROOT.json) preserve their scoped original files and actual restoration records. Their component scopes do not imply a matching current-source whole-system cold qualification. The [process public component](process-public/MOUNT-RECIPE-ROOT.json), [Linux stdio cold component](linux-stdio/MOUNT-RECIPE-ROOT.json), and [CLI JSON component](cli-json/MOUNT-RECIPE-ROOT.json) retain their own exact registration and qualification boundaries.

## Native development and open blockers

The [frozen V95 file-render candidate](v95-file-render/MOUNT-RECIPE-ROOT.json) has 24 passing kernel cases and 7 passing Source tests. It still rejects the documented original-valid Core v6 and empty-exports cases. A later independent semantic-checker candidate is under development and is not substituted into these original results. Its raw binary archive is not represented as completely sealed in Git.

[Native phase and source-scan diagnostics](native-phases/MOUNT-RECIPE-ROOT.json) retain the actual original failures and the guarded observation runs. The namespace diagnosis observes 47 distinct public calls with 47 required fresh scans; intervening publication effects forbid merging those calls. The original 3-second context, 1-second Native limit, and less-than-5-second timeout assertion remain unchanged. Instrumented timing is diagnostic evidence, not a replacement qualification. The rejected narrow guard optimization and the native-entry double-wrapper observation defect are explicitly preserved. Exact-byte SHA memoization remains an unadopted experiment.

Whole native closure is still open for the shared hosted orchestration, services/journal/report paths, SQLite write/transaction authority, the remaining CLI file actions, and the complete general Core compiler/checker behavior. Current-source Source, Native, installed-package, cold-start, and bootstrap identities must continue to be verified separately before removing old implementations.

## Publication and history

[MOUNT-INDEX.json](MOUNT-INDEX.json) pins all 13 subtrees and 1,020 file entries. Each subtree was independently hashed and fully read back. The existing 51 review subtrees and all 19 non-review top-level entries remain unchanged. The initial 489-entry tree request timed out; its error and subsequent absent-object read are preserved, and smaller staged tree writes produced the identical final expected tree.

The exact prior PR 889 body is preserved in [formal-terminals](formal-terminals/MOUNT-RECIPE-ROOT.json). Updating the PR summary does not discard its history. The append operation does not change main, the product branch, or the PR head, and executes no product tests.
