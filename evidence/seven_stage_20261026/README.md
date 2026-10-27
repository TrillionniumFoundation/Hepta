# Seven-stage HIA delivery — executed evidence

The integrated compiler completed **2,023 tests with zero failures/skips** and
**14 of 15** integrated gates. The remaining performance gate is
`measurement_inconclusive`. The native JSON model study completed all **64
task cells plus four eligibility probes**, but neither model met either
prespecified benefit criterion. **The full seven-stage goal is not complete.**

## Source and review identity

- Compiler qualification: `6f5fc9fcf8e97f181dda3be53ecca65c64238f94`.
- Native JSON experiment: `9a20dd61ca1526cfe3f4fe7e68d77835ad79b982`; all compiler files have the
  same compiler-tree SHA-256 `f3f45a6df0e813e313d1e44575947158037dc57647c630326e21bc4e51b2a96f`.
- The experiment-only increment passed **44 related tests**. It changes the
  model adapter, experiment runner, their tests and preregistration; it does
  not change language or compiler sources.
- [PR #210](https://github.com/TrillionniumFoundation/Hepta/pull/210) is a draft
  integration against the guarded v6 baseline from #204.

## What was executed

| Area | Actual evidence | Boundary |
| --- | --- | --- |
| Unified language | Shared schema registry, distinct composite namespace, v6 normalization and explicit legacy import; complete regression pass | Finite admitted language; schemas and hashes do not replace verification |
| Resource composition | Generic aggregates, record-field/stored/reborrowed loans, enum/task/error/cancel paths with v2–v6 memory operations | No recursive heap ADTs, escaping loans or general asynchronous scheduler |
| Composite native/QEMU | 72 scalar calls, four binaries, 18 cases per binary; 31 allocations/31 frees/2 refusals per binary; peak live 2, final live 0 | Linux x86-64 and AArch64/QEMU, fixed finite allocator |
| Negative native controls | 2 wrong-result, 2 actually removed-free, 6 bounds-trap executions | Finite detection evidence, not exhaustive compiler refinement |
| C matrix | 2 configurations × 2 TUs; 408 VM results, 816 original/HIA native results, 5 rejected partition controls; 9 active declarations per configuration | Scalar module profile; original/HIA actual defined function symbols compared; no inferred resource contracts |
| C++ matrix | 2 configurations × 2 TUs; 408 VM results, 816 original/HIA native results, 5 rejected partition controls; 28 active declarations per configuration | Instantiated scalar templates; no arbitrary STL/object-layout/exception support |
| Selected formal proof | Actual four-instruction Core exported to independent Lean register semantics; all 2^64 pairs of u32 inputs; 2 real Core mutations rejected; 272 native/VM/spec cases | Exporter/verifier/LLVM/resource soundness remain unproved |
| Historical targets | Historical Core, hosted resource composition and Cortex-M4 Rust/BSP-QEMU gates pass | The historical BSP gate does not qualify standalone HIA for a 32-bit model or physical devices |

## Performance: retained uncertainty

Both complete runs used the same frozen v3 protocol, 63 observations each,
fixed backend rotation, no clipping and no threshold change. Both satisfied
the numerical paired-time limits. Both failed the fixed **5% relative-MAD**
quality bound:

- Run 2: `two_stage/rust` 8.39%, `two_stage/handwritten_rust` 5.12%.
- Run 3: `constructor_error/handwritten_rust` 5.44%.

Run 3 geometric paired HIA/Rust time ratios were **0.9210** versus the
same-source Rust path and **0.9092** versus independent safe handwritten Rust.
Those values are descriptive observations from an **unqualified timing run**,
not a stable speedup claim. All **126 samples** and measured binaries are
retained. No additional performance sampling followed the model-adapter change.

## Agent studies: failures are part of the result

The first strict protocol is preserved unchanged. Qwen Coder 0.5B completed 32
task cells; both HIA arms solved 0/8. Qwen Coder 1.5B added Markdown fences to
both eligibility responses, so its 32 task cells remained explicitly unstarted.
This run has **36 actual requests/responses**, not 68 completed generations.

The separate native JSON protocol uses only `json_schema={"type":"object"}`
for both languages, both models, all arms and preflights. Actual non-lazy
sampling grammar is checked in every response. It does not constrain answer
fields or enumerate correct answers. Tasks, prompts, model bytes, token
budget, seed, rotation and the minimum **7/8 successful HIA-query tasks** were
unchanged. This is a new frozen experiment; the old responses were not
extracted, repaired, retried or rescored.

Both models completed 34 requests in the native JSON experiment. Its 32 native
controls passed. Results below count input plus output **task** tokens;
eligibility costs remain separately recorded.

| Model | Arm | Successful repairs | Rejected responses | Accepted but wrong | Task tokens |
| --- | --- | ---: | ---: | ---: | ---: |
| qwen_coder_05b | HIA full | 0/8 | 0 | 8 | 3,485 |
| qwen_coder_05b | HIA query | 2/8 | 2 | 4 | 1,925 |
| qwen_coder_05b | Rust full | 1/8 | 0 | 7 | 1,694 |
| qwen_coder_05b | Rust query | 0/8 | 0 | 8 | 1,557 |
| qwen_coder_15b | HIA full | 1/8 | 6 | 1 | 3,638 |
| qwen_coder_15b | HIA query | 0/8 | 8 | 0 | 1,980 |
| qwen_coder_15b | Rust full | 1/8 | 1 | 6 | 1,692 |
| qwen_coder_15b | Rust query | 2/8 | 1 | 5 | 1,554 |

All primary and secondary criteria are false. The compact HIA views reduce
context size relative to full HIA, but the observed success rates do not meet
the minimum useful-quality gate, and HIA query tokens exceed Rust query
tokens. **General productivity and total development-cost improvement remain
unestablished.** There are **104 actual model requests** across the two
protocols. There were no missing responses.

The models are two small quantized sizes of one family. The tasks are eight
disclosed single-site arithmetic repairs. HIA has two functions in one module;
Rust has caller/kernel source files. This is not HIA cross-module maintenance,
independent-model-family coverage, representative production coding, or a
measurement of human labor. Full versus query changes encoding and context
together. The C/C++ module experiments are separate from these agent tasks.

## Failure and source history

`SOURCE_HISTORY.json` records the interrupted initial source, completed failed
run 2, corrected compiler run 3 and both model protocols. The initial C inline
ABI discrepancy was reproduced on real C99/C11/C17 objects before fixing it:
the old adapter incorrectly defined a symbol the original inline-only C
implementation did not define. The limited scalar profile now rejects
unsupported inline declaration chains and compares actual object symbols.

The completed run 2 failed two error-wording assertions in one test. A one-line
diagnostic change restored the existing contract; 36 related tests passed and
the complete 2,023-test suite subsequently passed on the corrected commit.
The upstream empty-owner native-drop fix is also carried with its original
tests: logical empty drops make no native `free(NULL)` call.

All completed qualification/model records are archived, including failed
outputs and measured artifacts. Some early sandbox/Lean diagnostics and
temporary development-test directories exist only in session output and were
not independently archived; they are not counted as complete acceptance runs.
The interrupted run has no invented terminal test count.

## Files and verification

`SUMMARY.json` contains machine-readable results and explicit unclosed claims.
Top-level copies of the detailed qualifications and both experiment plans/
reports support quick review. Each `.tar.xz` has a member-by-member SHA-256
manifest and preserves its historical input-path mapping. Extracting a file
does not turn a historical execution receipt into a new run.

Run `python verify_bundle.py` in this directory to verify every listed file
and archived member without extracting or executing archive contents. This
checks retained byte identity; it is not hostile-producer attestation or a
new compiler execution. Reproduction uses the commands and pinned tools in
the source documentation and the original plans.

## Independent record review and audit incident

`study-audit.json` records **811/811 consistency checks**, including 96
independently reconstructed task prompts, 36 paired actual requests, 624
retained-evidence byte hashes and 133 native/tool file hashes. These are
record checks, not 811 additional tests or executions. Total actual generation
cost, including eligibility probes, is **8,958 tokens** for the strict protocol
and **17,725 tokens** for the native JSON protocol.

The intended read-only audit contained a write-path variable-shadowing bug:
it temporarily overwrote one live strict-study request. The auditor recovered
that file from a previously matched paired request and rechecked all retained
evidence hashes. The root review then independently compared the recovered
file **byte for byte with its original member in the archive sealed before
the incident** and its pre-existing member manifest. The original archive
remained unchanged. The recovered file has SHA-256
`76cbbbe5725c2160111427f1ff0bc4373d1a0694331deaec7cf5a22fb6517678`.
Its modification time changed and was not fabricated.

`study-audit-initial.json`, the final audit's `audit_write_recovery` section
and `audit-recovery-check.json` retain the full incident and independent
verification. No compiler source, model or native artifact changed, and no
model request was rerun.
