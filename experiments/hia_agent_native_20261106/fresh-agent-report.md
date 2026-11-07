# Fresh-context HIA acceptance — observed runtime r3

## Result

Completed the actual MCP discovery, authoring, diagnostic repair, whole-domain Core equivalence, direct emission, exact encoding verification, native evaluation, conditional adoption, stale-CAS rejection, and rollback loop. The selected final comparison has **unchanged whole shared-file size: 13,720 bytes versus 13,720 bytes; 0 bytes saved**.

A separate three-block program accepted an explicit Agent-selected block permutation. Both actual native variants matched all 256 independently calculated expected outputs. Their 406-byte ELF executable sections differ at **16 byte positions**, while both whole shared files are 13,712 bytes.

The last experiment endpoint session closed with exit code 0 at 2026-11-07T00:16:02.287309Z. The exact endpoint process is absent. All 121 observed HIA operations are terminal; no operation remains accepted or unknown. No further HIA endpoint calls are planned.

## Learning and provenance

The Agent began without HIA grammar or examples in its assigned task context, and learned the contracts through actual tools/list, hia_describe and hia_read artifacts. It did not read implementation, repository tests, other qualification traces, or external HIA material. Model pretraining exposure is **unknown**; this is not a claim of zero prior model exposure.

The observed cohort is **r3**. Parent supplied the pre-experiment executable SHA256 **bd896a3d57ff52a02036791bdf8cbcae6afac88c42ac20ee5260397a6f0c30f3**; that digest is parent-observed, not independently obtained by this Agent. Exact endpoint argv is in the JSON report. Tool-observed pins were:

| Identity | SHA256 |
| --- | --- |
| Catalog | 8b880cc02efc93e10d920bf812bccbb33197aa00f6b92282536a000238ba5e9e |
| Backend implementation | 2da6aaaaec1129a0129f0fdb7c3f91a4158103e0bcd0cb0f85baa77760a18c28 |
| Worker implementation | 15b1bde41801117626509595d2d7908f44340fe1a2bf88227f3626e42d29a937 |

The controller host was ai395. Inner operation receipts identify the configured alias hia-worker; its mapping to actual SSH host x230 is administrator/parent-provided. All profile references and hashes are in the JSON report and original discovery records.

## Authored arithmetic and frozen contract

The repaired candidate is:

```text
hia-asm.v1 hepta.hia.program.v8 fresh_xor5a_plus13
exports(transform)
fn transform(x:u8) -> (u8) effects() entry(entry)
block entry(x:u8)
  mask:u8 = const() {"value":90}
  mixed:u8 = bit.xor(x,mask)
  delta:u8 = const() {"value":13}
  answer:u8 = int.add.wrap(mixed,delta)
  ret(answer)
end
```

The final baseline performs the same computation, then eight explicit cancelling pairs of wrapping +17 and -17. It is a synthetic redundant baseline selected by the Agent. The final candidate has four typed instructions; the final baseline has 21. These instruction/source counts are not substituted for the whole-file byte metric.

The independently authored oracle uses ((x ^ 0x5A) + 13) & 255 for every x in 0..255. The frozen workload has all 256 cases, three measured repetitions, and zero warmup. The native reports record 768 measured calls per artifact. All baseline/candidate native and VM per-input outputs were independently matched against that oracle.

The context budget declares 20 minutes total wall time, 30 seconds native wall time, 512 MiB memory, 16 candidates, and a 1,000,000-token ceiling. Actual model tokens and model wall time remain unknown. The objective requires Core admission, behavior equivalence, and encoding checks; its artifact_bytes metric explicitly permits unchanged size and does not require a net-benefit claim. All five candidate-import attempts, including the invalid attempt and branch program, fit within the declared candidate count.

The successful equivalence evidence records checked=256, required=256, complete=true. Both actual emitted shared objects passed exact rederivation/linkage/ABI encoding checks. Emission was hia-direct with GNU ld linkage, no LLVM codegen, no external assembler, and no implicit profitability optimizer.

## Negative and nonwinning evidence retained

1. An explicit invalid u8 constant 256 was rejected with E_HIA_TYPE in core_verification. Repair changed that constant to 90.
2. The original synthetic baseline contained 128 cancelling pairs. Its exhaustive proof hit the deadline after 237 of 256 cases, so behavior_equivalence remained unknown. Its native file was 21,912 bytes versus the candidate's 13,720 bytes, a physical difference of 8,192 whole-file bytes. That pair did not pass the proof gate and was never evaluated or adopted; this is not a qualified optimization win.
3. Evaluation of that initial pair correctly rejected E_HIA_CLAIM_REQUIRED. The strict required claims were preserved when the Agent selected the smaller baseline and created a new frozen context with the same oracle/objective/budget references.
4. One local audit script assumed a nonexistent native_code_executed field and stopped with KeyError before any lifecycle MCP call. The actual native-observation.v1 report was inspected, the audit assertion repaired, and both scripts and original stderr retained.
5. One interrupted outer process_start was reconciled with exactly its original arguments and idempotency key. It returned reused=true for job 1a1b34d24dd-fc05-81dc and did not create another execution identity.

6. A packaging-only audit initially grouped observations by opaque response request_id. It was corrected to reconcile the exact original tool name and arguments; no HIA call was reopened. The original assertion failure is retained.

All original request keys, context identities, operation/job IDs, source bytes, partial-proof evidence, rejection envelopes, receipts, and measured-cost snapshots are retained.

## Adoption and rollback

The Agent explicitly adopted under the allow_unchanged objective to exercise the reversible lifecycle; no size, speed, or net benefit was claimed.

- Expected generation/epoch 0/0 adopted the candidate at 1/1 in fresh-agent-coldstart.
- A separate request deliberately reused stale expected state 0/0 and rejected E_HIA_GENERATION_STALE.
- Conditional rollback restored the retained eight-pair baseline at generation 0, epoch 2.
- Restored active native SHA256: 33dd8baa96ebc142c419c10c89820eb667233afe97d9af5c5561d196caf98e53.

## Explicit machine-plan experiment

The branch function choose(u8) returns wrapping x+3 when x<128, otherwise wrapping x-5. Its independent workload includes every u8 input, one measured call per artifact per input.

The source order is entry, low_side, high_side. The Agent explicitly submitted entry, high_side, low_side. The plan verifier proved exact block-permutation preservation of CFG, value slots and per-path operations, **conditional on canonical lowering/encoder correctness**. Both native encodings verified, and all 256 baseline/planned native outputs matched the independent oracle.

| Actual ELF artifact | Whole file bytes | Executable .text bytes | Actual .text SHA256 |
| --- | ---: | ---: | --- |
| Canonical | 13,712 | 406 | fba865e58fc0fbc4314c477d65f969701ef180345ee466a6e05937b813ea04d4 |
| Explicit plan | 13,712 | 406 | b9fdfb20099b53fecdf710ccd5ce61d01532a5728417359c10e48e0453c1a5e9 |

Actual binary files were retrieved through hia_read, decoded, checked against their issued artifact SHA256, and their ELF .text sections compared. The raw emitted-code digest in a build receipt is distinct from the linked ELF .text digest; both are preserved.

## Measurements, costs and limits

For the final arithmetic pair, aggregate measured ctypes-call time was 984,982 ns for the baseline and 1,282,871 ns for the candidate over 768 calls each. The candidate was slower in this observation. These baseline-then-candidate measurements include FFI overhead and use no warmup; they do not establish a robust speed comparison.

The main cost snapshot records 279,649,287 ns of native child wall time and 3,016,513,776 ns of evaluation wall time through reporting. Main and branch cost snapshots overlap and must not be summed. Model/discovery costs remain null/incomplete, and net_optimization_benefit_proved is false.

Recorded protocol: 289 wire records; 265 tools/call observations comprising 144 accepted observations, 118 completed responses and 3 rejected responses. There are 44 logical keyed calls (41 completed, 3 rejected), with no changed arguments under a reused key. Accepted operations were observed under the exact original tool/key/arguments.

**Trace limitation:** the supplied CLI's first tools/list session records initialize and tools/list RPCs but omits its one-way notifications/initialized record. All subsequent custom runner notifications and every actual HIA tool RPC request/response are captured. No missing notification has been fabricated.

This exercise establishes a bounded fresh-context authoring and qualification loop. It does not establish global optimality, broad Agent productivity, language superiority, universal backend refinement, whole-language soundness, or net economic benefit.

## Evidence package

The archive preserves all original working scripts and responses, initial and consolidated protocol traces, discovery artifacts, both baselines, repaired/invalid sources, independent workloads, actual canonical Core bytes, receipts, cost snapshots, controller metadata, and actual native artifacts. Large text/JSON traces are deterministically gzip-compressed. package-index.json records original and packaged SHA256/byte lengths; archive metadata uses sorted paths, zero timestamps and numeric owner/group zero.

The compact machine-readable report is fresh-agent-report.json. Source/file inventories and all complete identity references are there; the raw transcript is additionally retained at the originally requested private evidence path.
