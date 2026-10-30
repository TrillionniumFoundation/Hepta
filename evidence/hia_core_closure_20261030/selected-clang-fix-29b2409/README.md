# One selected Clang identity in both qualification environment names

## Exact change

Local frozen commit `29b2409a75c5f0df082c9ae64e993a0879f929c7`, tree `a4f6eb52470fdce0601872be6e3814af9f83992c`, has public parent `5a0d1997b0bba8f8cb674b317ae1f56f0afcb22a`. Four files change. The two production changes each add the `HEPTA_CLANG` name alongside `CLANG`, using the same compiler that was already explicitly selected:

- The full-release workflow persists both names for subsequent candidate and standalone steps.
- `tools/qualify_hia_unified.py` sets both names from its existing `clang` argument. Its existing `old_environment` capture and `finally` restoration now cover the added name as well.

The other two files strengthen existing protocol tests. No method is added or removed, and the canonical selector set, zero-skip policy, original native-test decorator, source checker, Core, Machine and backend are unchanged. There is no additional compiler-selection rule or fallback.

The original failure is retained separately in the official full-release triage package. Both official e0 and b121 workflows remain failed. In the b121 originals, candidate and standalone ran 4,335 tests and ended `OK (skipped=2)`, correctly failing the strict no-skip gates. The candidate verbose log names the two native convergence methods whose decorator requires `HEPTA_CLANG`. The same b121 integrated producer configured both names and actually completed its 4,335-method population with zero nonordinary outcomes.

## Actual red and green observations

| Source / observation | Actual result |
| --- | --- |
| Clean public parent 5a0d, original two native methods through the original standalone qualifier environment | Two methods selected, both skipped, process exit 0, original qualifier rejects the selected population; no native graph invocation. |
| Parent production implementation with the two strengthened protocol methods | Both methods fail: the persisted next-step process inherits a stale native compiler override, and the standalone command boundary sees the wrong native compiler name. The uncommitted test-only patch and both failure traces are retained. |
| Clean frozen 29b, same original two native methods | Two ordinary passes, zero skips/errors/failures/expected failures/unexpected successes; original qualifier accepts this selected population. |
| Clean frozen 29b, related protocol/workflow population | 17 distinct methods, each once with an ordinary pass; complete source inventory remains unchanged. |

The two-method collector calls the real standalone qualifier with an explicitly narrowed external plan. It leaves the qualifier's subprocess runner, environment construction, result parser and cleanup unchanged. This is **one selected two-method plan**, not a complete 37-gate standalone run or a replay of the 4,335-test population. The original full plan and its production API are unchanged.

The green invocation begins with a conflicting ambient `HEPTA_CLANG`. The real child receives the explicitly selected compiler under both names, and the parent environment and working directory are restored afterward. The existing protocol method also checks restoration when an observed command boundary raises. The workflow test executes the actual export shell block and reads its persisted environment in a real subsequent Python process; its test-only tool placeholders are not native compiler qualification.

## Retained native observations

The original native test class invokes the original eight-arm graph producer exactly once. All eight episodes complete and all outputs are correct: `fixed-base`, `fixed-small`, `fixed-wide`, `fixed-best-plan`, `light`, `ndu`, `q32-dp` and `ndu-compact`. The two native sessions remain distinct, each reports 13 sealed-image identity checks, closes successfully and reports no cleanup errors. The tiny original protocol exercises composition and establishes no performance advantage.

The observer forwards the original producer arguments and returns its original result. It copies the original graph directory before the test's existing cleanup and checks each copied byte against its still-present original. The retained graph includes actual source identities, protocol, native build identity, compiler artifacts, controller ledger, eight episode records and final result. A new Rust crate build is not performed; the existing NDU stream binary and its unchanged path-only transport manifest are reused explicitly.

The source wrapper checks **1,024 materialized tracked files** against raw Git bytes and modes before and after each red/green run. The declared full tree has **7,699 files**; the 6,675 unmaterialized paths are explicitly listed and do not become runtime input coverage. Selected Clang bytes, the NDU stream executable and transport manifest, and the Z3 native library remain unchanged. Original source tests and graph results remain bound to their actual local or public-parent commit; they are not relabeled as executions of a future publication commit.

## Reproduction and release boundaries

`source-export/manifest.json` contains all four exact UTF-8 Git file exports and identities. Its 7,691-byte full-index patch applied to an isolated index at public 5a0d reconstructs tree `a4f6eb52470fdce0601872be6e3814af9f83992c` exactly. The producer scripts, original red/green records, both protocol failure traces, successful 17-method records and full retained native graph are included in the owner package.

The coordinator published the same source tree as `a6cfb7e00a1c08276d27459bdcc5628aa7622079`, with the same public 5a0d parent. The exact source-publication receipt is retained as `public-source-publication.json`. The executions in this package remain bound to their original 29b or 5a0d identities.

Public-source re-execution and later official full workflows are separate evidence. This local correction does not convert either older official failure into success. Python remains production authority, optimization policy remains `no_change`, and all 27 original strict P0–P7 obligations remain open.
