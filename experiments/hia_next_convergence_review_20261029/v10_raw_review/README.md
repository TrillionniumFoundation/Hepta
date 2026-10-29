# V10 independent raw accounting and source review

The completed calibration belongs to frozen source
`11d6f78c6c01f66978af7fcf4d40eea7dae5d5f0`. Its RESULT SHA-256 is
`9d528ebfdfa5e6f0e748f625a6364cbbe8786ffd54f55ab8bb3f335d50905b94`.
No producer observation, model answer, scientific gate or frozen source was
changed by this review.

## Actual outcomes and complete request costs

All **9 requests have complete EOS responses**. Actual submitted integer prompt
IDs agree with preparation and cell records; concatenated SSE text and output
IDs agree with response, timing and usage records. All attempts remain in the
denominator, including the repeated failed answers.

| Qualification task | Requests | Input tokens | Output tokens | Correct tasks |
|---|---:|---:|---:|---:|
| Scalar reasoning | 3 | 5,045 | 173 | 0 |
| Two-file API migration | 3 | 6,218 | 327 | 0 |
| Owner flow repair | 3 | 8,106 | 973 | 0 |
| Total | **9** | **19,369** | **1,473** | **0/3** |

The total is **20,842 tokens**, with zero unknown usage or partial-output
residuals. There were **zero public native executions and zero terminal hidden
executions**. The main entry point was actually called and refused before
creating its output directory or engine: **zero main cells and model requests**.
No HIA model arm ran, so no between-language productivity result follows.

| Retained clock boundary | Seconds |
|---|---:|
| Sum of HTTP/SSE transport calls | 1177.763965362 |
| Sum of generation wrapper calls | 1177.948488506 |
| Complete qualification experiment | 1199.440217767 |
| Separate capacity/reference phase | 68.212309461 |
| Separate actual main-refusal invocation | 3.138174268 |
| Sum of the three separate recorded phases | **1270.790701496** |

The transport, wrapper and qualification durations are nested. Only capacity,
qualification and main refusal are added in the last row. These producer clocks
were independently reconciled, not independently recreated. They exclude human
labor, acquisition, tool development, outer process costs and other history.

One earlier execution-transport failure occurred before the capacity process was
created. Its retained receipt reports zero model/native execution and no output
directory/log. Its exact orchestration wall was **not measured**; this unknown
duration is preserved as unknown, not assigned zero or included in the three
measured phase total. `PRODUCER_PREPROCESS_TRANSPORT.json` preserves that receipt.

## Actual rejection boundaries

All nine submissions were rejected **before compiler invocation**. No Rust type,
native value, resource or later syntactic result is inferred from unexecuted
stages.

**Scalar:** the three retained BUILD records report
`E_FACTORIAL_RUST_PROVIDER_CALL_COUNT`, `native_built=false`, and no compiler
invocation record. The model edits `client.rs/entrypoint/n6`, whose original
fragment is the argument `a`, replacing it with a complete `api::span(...) + c`
expression. Its parent was already `api::span(a,b)`, so the recorded child-node
replacement introduces a nested second provider call. The supplement verifies
the original query spans and this textual splice without writing or executing
a candidate. The final two answers are byte-identical; output sizes are 57,
58 and 58 tokens. This is a source-profile rejection, not a rustc type failure.

**API:** all three answers are the same 251-byte / 109-token response, SHA-256
`18403383d311f97fc8e75eb142897b1d67e04b007fc49245bff64ef76fef4b1c`.
They insert complete function declarations into type nodes. The observed error
is `E_STRUCTURED_RUST: only disclosed scalar/Vec<u8> types`; no BUILD record is
reached.

**Owner:** the first answer is 894 bytes / 339 tokens; the last two are the same
836-byte / 317-token answer, SHA-256
`18512886872d7d2b44edebaad0cc51b413a64e067858becfa2aa4703ba4e0d6b`.
All are rejected by `E_STRUCTURED_RUST: trailing tokens outside selected
fragment`, before any build. The review does not regrade them or infer how a
human-corrected answer would behave. Each refusal leaves the original source
revision unchanged.

## Identity and feedback boundary

All **185 source snapshot files** were hashed against their declared bindings,
then checked directly against **185 immutable Git blobs at the original source**
with lazy network fetching disabled. Six canonical outer/nested query digests
were recomputed. The raw reader retains a 284-file read inventory; the source
and refusal supplement keeps its additional reads separately.

The model identity and all 39 retained runtime companion identity records agree
before/after. Each cell boundary records unchanged source/model/tools. This does
not represent a new multi-gigabyte model rehash or hardware attestation.

The engine records `exited=true`. Its additional producer absence receipt binds
the exact original identity file and PID 432026, with SHA-256
`03ef98d36469e25ba8b97ab8483ee56d4dd4159031b7737182c48d9c6a11ad2a`.
That historical process observation remains attributed to its producer.

Each repair retains the initial message and the full immediately previous
answer; every predecessor was a public rejection. No hidden evidence file
exists, and each new task resets messages. Every actual submitted prompt retains
the full registered output reserve. The official-template rendering and
generation-before/after ordering receive a separate safety review; this audit
does not rerun the template engine or tokenizer.

## Audit scope

The unchanged, parameterized completed-calibration reader passed on its first
V10 run. The separate source/exit/refusal supplement also passed on its first
run. Both invoke only standard-library data reads and read-only Git operations;
no model, tokenizer, native executable, compiler, solver, test or experiment
runner is invoked.

`REVIEW.json` SHA-256:
`9d431c627ce1c3f26fba6b128538a51f6b644ee3766d73fe756d35bec08a48a3`.

`SOURCE_EXIT_SUPPLEMENT.json` SHA-256:
`7c733512a0f270edaf03a8d2f9b7d103a7042ac4f52ff6a4b0be05cbaced2b3e`.

Reference capacity is not model qualification. This negative result does not
establish Agent efficiency, HIA/Rust superiority, general migration safety,
NDU profitability or a universal resource/performance advantage. The single
candidate stopping rule is unchanged.
