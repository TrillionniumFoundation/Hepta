# Registered NDU and Agent studies — 2026-10-30

Both one-time studies completed on registration `e223932a8bf25521db4204883af925dd64acc57a` and source `71aff3e9dbaa89601e0e0acacacac6c775e9f7f1`. The formal results are negative for the proposed efficiency advantages: native NDU did not beat exact Q32 DP or the lightweight controller, and HIA required more requests, registered token charge and elapsed cell time than Rust despite equal task success.

## NDU: eight arms, two groups

All 16 episodes completed, all native results matched their independent checks, all actual budgets passed, and four transitions executed. The wrapper took **18.990028649 s**. Each standalone arm is charged the same shared preparation; the arm totals below consequently must not be added to estimate the one shared experiment duration.

| Arm | Startup, including historical native build where applicable (s) | Prebuilt marginal total (s) | Standalone total with original native build (s) | Actual transitions |
| --- | ---: | ---: | ---: | ---: |
| fixed-base | 4.275274091 | 5.318917443 | 5.318917443 | 0 |
| fixed-small | 4.275274091 | 6.414860756 | 6.414860756 | 2 |
| fixed-wide | 4.275274091 | 10.400829587 | 10.400829587 | 2 |
| fixed-best-plan | 4.275274091 | 5.332587656 | 5.332587656 | 0 |
| light | 4.276211344 | 5.367453911 | 5.367453911 | 0 |
| q32-dp | 4.277269104 | 5.287006205 | 5.287006205 | 0 |
| ndu | 25.677128791 | 5.401191507 | 26.788522143 | 0 |
| ndu-compact | 25.672672100 | 5.394100221 | 26.781430857 | 0 |

Full and compact NDU cost **0.114185302 s** and **0.107094016 s** more than exact Q32 DP even with the native bridge already built. Charging the original observed empty-target native build of **21.387330636 s** raises those deficits to **21.501515938 s** and **21.494424652 s**. That build cost comes from the original retained build envelope; this run did not repeat the native build.

Fixed-best-plan, light, Q32 DP and both native variants all stayed on the base candidate in both episodes. This is evidence of no independent NDU benefit in the registered finite problem, not evidence that more complicated future planning problems cannot benefit. The two observed episodes give only short-run amortization: Q32 DP **2.6435031025 s** per episode, full NDU **13.3942610715 s**, and compact NDU **13.3907154285 s** when startup/build are included. Long-run amortization was not measured.

The bank, initial information, budgets and zero-capacity advisory caches were common. Each arm could observe its own completed executions; evolving measured cost/request/path hashes can therefore differ. Frozen future seed observations were withheld until their actual episodes. Shapes were disclosed equally and same-shape calibration was permitted. `fixed-best-plan` is the strongest calibrated plan in this candidate bank; it is not a strongest C/C++/Rust/LTO/PGO baseline. NDU is a finite evaluator here, not a trained planner or a proof of global instruction optimality. Safety decisions remain with independent verification; native NDU has `DENY_ALL` authority.

Preparation, proof, compilation, decisions, switching/loading, execution, graph serialization, native startup/shutdown and the observed wrapper overhead are charged. Toolchain/dependency acquisition, human work, persistent evidence retention and final wrapper-result encoding/write are disclosed exclusions or unknown costs. No lifetime net gain, statistical superiority, cross-language superiority, global optimality or safety-from-NDU claim is made.

## Agent: four fresh tasks, HIA and Rust

Both languages achieved **4/4 accepted tasks**. Each final candidate passed 6 public and 72 terminal hidden native cases; HIA also passed its VM/oracle checks. The buffer task retained actual HIA VM resource events and Rust audited safe-Vec events. All **20 real CLI requests** have complete reported usage, confirmed process cleanup and removed empty model working directories. There were no human answer repairs and no post-observation reruns.

| Task | Requests HIA / Rust | Registered token charge HIA / Rust | Cell wall time HIA / Rust (s) | Failed public checks HIA / Rust |
| --- | ---: | ---: | ---: | ---: |
| quota_clip | 3 / 2 | 54,893 / 30,536 | 20.455582 / 8.726252 | 0 / 0 |
| rotate_lane | 3 / 1 | 55,482 / 15,252 | 21.776438 / 6.406860 | 0 / 0 |
| weighted_prefix | 4 / 2 | 77,108 / 30,743 | 30.530471 / 12.006178 | 1 / 0 |
| buffer_lane | 3 / 2 | 56,705 / 32,759 | 22.802531 / 11.218485 | 0 / 0 |
| **Total** | **13 / 7** | **244,188 / 109,290** | **95.565022 / 38.357775** | **1 / 0** |

HIA used **2.2343×** the registered token charge and **2.4914×** the total cell wall time. The full study took **136.001399127 s**, including **2.078602907 s** of observed shared overhead outside cell totals. Per-cell totals include model requests, public tools/compilation, terminal hidden evaluation, protocol work and process cleanup. The negative descriptive HIA-advantage gate is preserved unchanged.

All four HIA cells actually called the complete selected-version instruction catalog. The HIA `weighted_prefix` candidate first failed with `E_HIA_SSA: SSA value count is defined more than once`; the model used the public diagnostic to repair the candidate and passed its next check. This original failed candidate, feedback and additional request/usage remain in the raw archive. Rust had no failed public checks.

The registered token charge is `input + output + reasoning`; cached input is already a subset of input and is not added again. It is not a monetary invoice: output/reasoning overlap and provider prices are not inferred. Raw usage fields are retained. The CLI alias was `gpt-6.1-sol`, with the frozen executable hash; routed model weights, service scheduling and cache state were not controlled or attested. Four author-prepared tasks and the restricted Rust lexical/API profile do not establish population-level productivity. Human review time remains unknown, so no human-cost advantage is claimed.

Resource evidence covers the exercised cases and selected interfaces. HIA VM events do not prove machine-code refinement. Rust audited Vec events do not count every process allocation or prove every machine store; mutable access plus correct readback cannot distinguish zero-to-zero assignment from merely taking a mutable reference. These qualifications were frozen before generation.

## Reproducibility and retained negatives

`SUMMARY.json` is the compact machine-readable readout, `AGENT_RESULT.json` is the unchanged full Agent result, `NDU_COSTS.json` is the unchanged NDU cost ledger, and `COMMANDS.json` records the two formal invocations. `evidence.tar.gz` preserves all formal raw text, source snapshots, prompts, request/response streams, usage, actual compilation/execution records, hidden reports, proof/transition records, freezes, amendment histories, independent review and historical native build receipts. `EVIDENCE_MANIFEST.json` inventories every included file and every omitted ELF/native archive by SHA-256 and byte count. Native binaries are retained at their original run paths but omitted from this compact archive; no text/raw model stream is omitted.

The `pre_generation/` archive tree preserves earlier controls, real acceptance-bypass probes, integration test failures and successful follow-ups. These are author-written/no-generation controls, not human or model benchmark successes. The final independently reviewed controls passed on all 8 reference cells and reject wrong values and signatures. Pre-generation repairs closed actual Rust comment/dead-helper resource bypasses, HIA uncalled-helper resource bypasses, incorrect Rust ABI acceptance, RPC-type crashes, and the HIA parameter-name restriction. The review contributed the Rust audit fixture and is an internal separate-reviewer check, not an external audit. Historical failed results and unpublished registrations remain identifiable and are not replaced by the formal run.

Export is a post-run file/hash operation only. It invokes no model, compiler or benchmark, and it does not change the registered results or source. The exact export script is retained inside the archive.
