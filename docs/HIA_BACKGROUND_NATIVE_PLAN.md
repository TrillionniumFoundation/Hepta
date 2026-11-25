# Background optimizer native implementation boundary

This is an implementation plan, not a whole-product qualification. The companion JSON pins the exact original sources and enumerates every original test by owner. No source is retired by this checkpoint.

## Ownership and fixed dependencies

The background implementation owns the multiversion_background_* and background_optimizer_* prefixes. The root agent owns the independent ndu_rank_* implementation. The multiversion owner supplies the actual HIAMVBQ1 runtime provider, including snapshot, conditional publication and native reference lifetimes. Neither an application nor a test fixture can supply an admitted/verified boolean as production authority.

The already qualified in-process Future owns its token, condition/futex state, callback order and strong closure/result lifetimes. Its workspace is the same 512-byte object passed to conditional publication. The runtime takes its writer, selection and token locks and commits the token last. Background code only cancels or observes; it never calls token commitment while that lock is already held.

Public job, generation, epoch and cumulative accounting integers remain complete decimal values through the existing unsigned-decimal HIA role. Queue indices, which are private and bounded by eight outstanding jobs, are separate from those public values.

## Native owner composition

| Owner | Responsibility | Actual effects |
| --- | --- | --- |
| Background values | Typed constructor/submit admission, immutable JSON capture, tracked baseline/current program, original diagnostics | Actual native Core admission and current runtime snapshot |
| Background queue and worker | One worker, eight outstanding slots, FIFO order, cancellation settlement, interruption drain, shutdown | Actual thread creation/join and futex locks, using the existing Future |
| Background economics and decision | Fresh ranking identity checks, original exact integer limits, selected-source reverification, robust net/resource margin | Original complete selected candidate and ranking source admission |
| Background accounting | Settle once; retain 64 immutable receipt byte strings; separate queue waiting and paid worker time | Actual clocks and one consistent Future observation |
| Native rank owner | Full original rank_candidates workflow | Fresh candidate proof, actual admitted native evaluator call, final selected proof |
| Multiversion provider | Conditional preparation and atomic selection | Fresh proof/build/load/probe/retirement and the same cancellation token |

An internal effect-provider boundary may be used while independently qualifying queue control. Such a fixture does not qualify the production ranking or runtime path. Final composition uses captured native owners, and retains each original gate.

## Required sequencing

Submission first checks closed/capacity under the coordinator lock, then bounds and freezes caller values, checks target/current source/observation identity, creates the Future and job, and enqueues. The active job counts toward capacity. Cancellation does not free that slot until the worker processes it.

The worker records its start before invoking the rank owner. A stale captured generation or epoch returns stale without ranking. It checks cancellation before and after ranking, independently verifies the complete ranking bindings and selected source, checks current generation/epoch again, then charges surrounding coordinator work once before requesting conditional publication. A successful rank is advisory and does not bypass the runtime's fresh proof.

Accounting reads one consistent Future state and stores detached bytes before completing the Future. Later cancellation cannot rewrite this historical observation. Reported prior search costs remain context and are not added a second time to the cumulative submission/worker ledger.

Completion callbacks run outside coordinator and token locks. A fatal worker interruption closes admission, captures all accepted jobs, attempts every token cancellation, accounts each job at most once and settles all accepted Futures. An already committed generation is never replayed or treated as unselected. A second callback interruption cannot strand the remaining queue.

Shutdown flags retain exact boolean checks. Shutdown can cancel or drain; it attempts every cancellation before propagating the first abrupt exception, and a callback running on the worker never joins its own thread. Closing the coordinator does not close the caller's runtime.

## Native rank gap and gates

The original rank caller is more than the NDU numeric evaluator. It admits up to 32 complete candidate sources, checks unchanged unselected functions, obtains a fresh proof for each eligible candidate, shares one actual search budget, performs exact ties-to-even Q32 conversion, admits and seals the bridge bytes, invokes the bounded native process, checks the complete response and caller Pareto tie policy, re-proves the selected candidate, and finally charges actual total work.

Its bridge identity currently reads the original Rust adapter/lock/source set and Python builder hash. That is a concrete provenance migration edge. The native implementation must preserve actual source/build/executable custody; these checks cannot simply disappear when final Python/Rust author files retire. The root-owned rank implementation fixes that boundary explicitly.

The gate table in JSON retains all original NDU semantic, budget and transport methods separately from the background lifecycle methods. Background tests that inject a controlled ranker are used only for repeatable lifecycle races; native product qualification must also execute the actual rank owner. The original publication-interruption methods beginning with worker settlement belong to this background owner, while image registration/retirement interruptions remain owned by the multiversion runtime.

## Remaining qualification

The existing Future and decimal component evidence is reusable. The new queue/worker, value and accounting owners still require actual construction and differential qualification. Final gates must use the actual native runtime, native rank owner, original concurrent cancellation/commit interleavings, full immutable receipts, allocation/futex/thread errors, callback BaseException paths and independent strong-reference lifetime checks. This plan grants no final installation or production activation authority.
