# Owned-state runtime: final qualification and full local cost

**The final correctness/resource controls pass. The final complete local cost
profitability gate does not pass.** `FINAL_ACCEPTANCE.json` and
`attempt05/qualification.json` are the authoritative final result. Historical
positive, narrower measurements are retained and are not selected as the final
performance result.

The implemented profile uses a real exclusive native `u64` array, checked lease
handles, a stable opaque allocation identity and pure verified scalar native
transitions. It rejects switching/closing with live aliases or active native
work. Committed finite queues execute each actual transition once; partial
cancellation and a host exception after real native progress are terminal and
cannot replay the original queue. Sealed native versions and a private native
owner adapter preserve actual identity across safe-point switches. This is not
whole-heap/live-frame migration, external transactions or crash recovery.

## Final fixed queue and measured outcome

All performance attempts use the same pre-registered queue: initial state
`[29,31]`, slot 0, delta `0xD7A192456BBEFE51`, 400,000,000 transitions. Each
transition performs the same four modular additions. The candidate replaces
an MBA helper with wrapping addition; original and candidate `transition`
machine code are actually different (17 instructions/53 bytes versus 2
instructions/5 bytes in the retained disassembly). The checker proves the
scalar correspondence; native execution and resource observations are separate.

| Final attempt05 measurement | Seconds |
| --- | ---: |
| Full local deployment wall time | 4.019186453 |
| Original native counterfactual execution | 3.307593459 |
| **Complete local measured net** | **−0.711592994** |
| Entire post-decision audit API | 3.309256422 |
| Full performance experiment wall time | 7.328442875 |
| Internal receipt intervals | 4.018315858 |
| Additional measured outer-envelope overhead | 0.000870595 |

The outer timer starts before this fixture constructs the base/proposal and
ends after `close()` returns. It includes initialization, candidate preparation,
compilation, verification, calibration, switching decisions, dispatch, actual
execution, receipt/API return tails and final owner/library release. The only
subtracted interval is the separately timed **whole** post-decision audit API,
which uses a distinct owner and never replays application state. Both the
subtracted audit and the complete experiment wall time remain recorded.

This is a fresh runtime object in an already running Python process. Process
startup/imports and an external LLM/NDU search that this fixture does not execute
are outside this stated experiment. It is not a whole AI-session benchmark.

### Why the final attempt retained the baseline

The minimum observed paired saving projected to the actual immutable queue was
990,020,000 ns. Initial/candidate preparation was 930,240,703 ns and calibration
alone was 24,079,105 ns, so the inexpensive initial forecast admitted further
selection work. Actual calibration, verification and switch/restoration planning
then cost 134,071,418 ns in total. Preparation plus that phase was
1,064,312,121 ns, exceeding the projected saving. The policy restored the baseline
before application work: `automatic_selected=false`,
`selection_reason=forecast_exhausted_by_actual_preparation_and_switch_cost`.
Application work was executed once on the baseline, and all failed optimization
preparation and switching costs remain in the deployment ledger.

Attempt04 remains a complete local-cost negative observation of −0.805389844 s.
Its 711,733 ns added timer tail did not itself explain its difference from the
older internal-interval positive results: actual forecasts and selection outcomes
changed across observations. Attempt05 likewise reports its actual costs; it was
required by the loader identity fix, not by an attempt to obtain positive timing.

## Why earlier attempts remain but are superseded

| Attempt | Actual observation | Why it is not the final gate |
| --- | --- | --- |
| 01 | Automatic selection; internal-interval net +0.534215440 s | Superseded by immutable-stdin/private driver staging and failed-selection cost/rollback hardening. Exact historical source bytes are retained and their original execution hash verified. |
| 02 | Automatic selection; internal-interval net +0.627590126 s | Superseded by charging commit bookkeeping before the near-zero rollback decision, plus binding the queue digest solely to immutable copied work. |
| 03 | Automatic selection; internal-interval net +0.354192625 s | Valid historical execution on the then-frozen runtime source, but its narrower timer omitted API tails and final close. Superseded for the complete-cost claim by the outer wall-clock measurement. |
| 04 | Baseline retained; complete local net −0.805389844 s | Complete-cost observation retained. Superseded only after the production loader mapping identity fix changed runtime source. |
| **05** | **Baseline restored before application work; complete local net −0.711592994 s** | **Final authoritative profitability result**, with unchanged queue, qualifier and timer boundary; actual executable mappings are bound to sealed descriptor identity. |

These repeats followed specific correctness, provenance or measurement-boundary
changes. No performance horizon, input, algorithm or selection threshold was
changed to obtain a favorable result. Registrations, supersession records,
all native observations and exact available bound source snapshots remain.

## Controls and identity

The final qualification passes actual lease/safe-point, allocation-refusal
cleanup, stable-owner switching, completed-queue replay refusal, active-call
refusal and real partial native cancellation controls. The performance runtime
ends with 24 allocations, 24 frees and zero live allocations. The short genuine
negative-gain control also retains its loss.

The tests additionally execute artifact path tampering with sealed loaded
bytes, restoration of a previously admitted version, a host exception only
after a real native item committed, producer mutation at the queue copy/hash
boundary, and the complete outer-wall negative-gain path. A controlled-clock
near-zero threshold regression is explicitly a policy unit test, not native
performance evidence. Logs and the independent guarded-proof review are in
`review/`.

The production loader now checks the actual native function address against the
kernel executable mapping and matches its device/inode to the still-open sealed
memfd. This covers the transition entry and all 14 owner-driver exports before
any invocation. A stale glibc cached mapping with the same `/proc/self/fd/N`
pathname is refused; hashing only the new fd would not establish loaded identity.
The separate real same-export/fd-reuse negative tests pass; final attempt05 also
retains actual mapping evidence for every admitted image and driver export.

Final runtime source SHA-256:
`8a3a0f6bd2068e6070b5f51f4be22cdf53090bb54abb8b84afaa80bdcc51b96e`.
Adaptive loader SHA-256:
`5dccab7880d75c6d37389a1d8261e56a948b75d7dca3591f8cfb12e73194f892`.
Mapping helper SHA-256:
`23ae4a968e0f72ff378d0fd7db43aa9a1b8fc7a61d045ad872d8d81ab611f80a`.
Final qualifier SHA-256:
`c24a059bde2b93547fac9a281e41f376a79bf23d7059f17ff8e6806b786bdc31`.
Source bindings are checked before and after final qualification.

The original `evidence.tar.xz` remains unchanged through attempt04. The separate
`evidence-attempt05.tar.xz` adds the final run, source snapshots, registration and
updated summaries. Both include original native binaries; duplicate loose ELF
copies are removed only after member-by-member SHA-256 verification.
Readable JSON, source snapshots, registrations, logs and this explanation remain
in the directory. See `RAW_MEMBERS.json` and `ARCHIVE.json` for archive identity.
