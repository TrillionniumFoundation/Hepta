# Retained v5 Agent calibration: no eligible model

The formal v5 study ran the pinned 1.5B and 7B Qwen models on source
`9c9cfaccb4eff5fa5d62e3c9f33efdaf50b3c70e` (tree
`c5539be16e3248a389d15ae11458f2c3db08aceb`). Each passed one of three unchanged
baseline tasks within the preregistered three-submission budget. Neither model
qualified. The 16-cell main comparison did not start: zero cells and zero main
model requests. The actual selection function rejected the two formal receipts
with `E_FACTORIAL_BASELINE_CAPABILITY_UNQUALIFIED`; its retained refusal receipt
is in `controls_and_preflight`.

## Formal results and full recorded costs

| Model | Scalar reasoning | API upgrade | Owner flow | First submission passes | Requests | Input tokens | Output tokens | Total tokens | Experiment wall seconds |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1.5B | Compiler rejection, 3 submissions | Correct after 2 submissions | Interface rejection, 3 submissions | 0/3 | 8 | 6,607 | 905 | 7,512 | 178.501899374 |
| 7B | Interface rejection, 3 submissions | Correct on first submission | Observable wrong value, 3 submissions | 1/3 | 7 | 5,872 | 2,210 | 8,082 | 1,172.383919828 |
| Total | | | | 1/6 | 15 | 12,479 | 3,115 | 15,594 | 1,350.885819202 |

Every formal request has a complete validated response and retained input/output
token IDs. Unknown usage requests and human answer repairs are both zero. Source,
model and tool identities remained stable; all owned model processes exited.
One successful task from each model includes the unchanged functional, native,
resource and terminal hidden gates. These two calibration successes are not main
language-comparison successes.

The 1.5B scalar attempts retain both a width error and the wrong provider
arithmetic. Its ownership attempt moves the buffer and tries to use the old
owner; subsequent replies use the excluded `clone` allocation and also retain
the wrong byte update. The 7B ownership replies use the returned owner and meet
the resource contract, but preserve `buf[0] = x` instead of the requested
wrapping `x + 1`. Public observations remain 16/73 where 17/74 are required.
This is a real semantic omission, not a compiler-interface refusal.

### The 7B scalar refusal was an experimental interface restriction

The first 7B scalar reply uses a `u32` as the argument to a `u64` wrapping add.
The real compiler suggests a conversion. The second reply applies `.into()`;
the v5 finite source profile rejects that method before rustc runs. The third
reply retains it and is refused again.

The complete original second reply was then compiled without altering either
source file, under the same trusted Rust harness, using actual rustc 1.90.0
`--emit=metadata`. Compilation returned zero. This independent diagnostic is in
`independent_unchanged_rustc_typecheck`, including the original response identity,
exact generated files, command and compiler output. It performed no native
execution, changed no model answer, and does not rescore v5. The valid Rust
conversion was outside the old experimental profile; the result must not be
reported as proof that the model cannot write Rust.

## Earlier diagnostics remain separate

| Run | Original source | Classification | Requests | Tokens | Experiment wall seconds |
| --- | --- | --- | --- | --- | --- |
| `v5-qwen1_5b-01` | `ebb80bb8c1918d6e8df4fab09370bed8a65dc55b` | Incomplete: interpreter lacks Linux seal constants | 5 | 4,503 | 92.353548544 |
| `v5-qwen1_5b-02` | `6998c11` | Preflight fails because fcntl is built into the interpreter | 0 | 0 | No model run |
| `v5-qwen1_5b-03` | `9f555cbb9c0bc1f40381586f6149f64f0e9088c4` | Valid 1/3 calibration before transitive fixture JSON binding was added | 8 | 7,512 | 169.354537217 |

The initial incomplete run generated five complete replies before a native
execution attempted to use missing `fcntl.F_ADD_SEALS`. Its status remains
incomplete and `valid_observation` remains false. The preflight fix discovers
unsupported interpreters before model loading and actually checks the kernel's
seal/readback/write-refusal behavior. The next preflight exposed the separate
built-in-module metadata assumption, which was fixed by binding fcntl to the
interpreter image. Finally, the v4 fixture JSON was included in transitive source
bindings, and the 1.5B formal run was repeated on the corrected source. Its lower
earlier timing is not substituted for the corrected formal timing.

All four runs with model requests, including both diagnostic/development runs,
cost **28 requests, 27,609 tokens and 1,612.593904963 seconds of recorded model-run
experiment time**. Control executions, preflight checks and human/tool-development
labor are separate; human labor is unmeasured. Historical v4 output with unknown
timeout usage is not folded into this exact v5 token total.

## Controls and provenance

- Ten streaming, usage, preflight and binding tests passed after source `9c9cfac`
  was committed. The exact command, source tree and log hash are retained.
- Thirty-five actual native reference and partial-repair controls passed on
  source `6998c11`; the successful evaluator/fixture bytes are preserved in their
  original source history. This control execution is not relabelled as `9c9cfac`
  and is not model output. The failed first control attempt is also retained.
- The compact evidence keeps exact prompts, complete model replies, SSE byte
  streams, token usage, actual compiler diagnostics, generated sources and
  validation records. `RAW_MANIFEST.json` inventories all 1,024 original files
  and auxiliary receipts by byte length and SHA-256. Full implementation snapshots
  and native binaries remain in the named original raw directories for archival;
  their hashes are included even though they are not duplicated here.
- `SUMMARY.json` derives totals from the immutable raw result records and labels
  formal, diagnostic and prebinding executions separately.

## Claim boundary and prospective v6

This was the available shared development host, not a verified user's dot.
Timings are descriptive; no qualified language or general Agent-efficiency
comparison follows from the calibration timings. Both query/full interfaces
replace the same two complete function definitions; query provides a context
slice, not a node-level edit API. The small four-file tasks do not demonstrate
long-term production maintenance efficiency.

The independent legal-Rust diagnostic motivated a prospective v6 profile with
narrow unshadowed scalar-parameter `.into()` support. Root also authorized pairing
already public inputs, expected values and observed values in repair feedback.
Both changes must be preregistered before fresh inference, with unchanged task,
hidden, resource, model and per-cell budget gates. Only pinned 7B is selected for
the fresh follow-up; selection is adaptive and disclosed. No v5 answer, eligibility
or failed gate changes. A v6 versus v5 difference cannot independently identify
the effect of language, model competence, conversion support or feedback layout.
