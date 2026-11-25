# Native NDU evaluator private memory map

The authoritative source is the checked-in HIA and readable fixed adapter.
All offsets below are byte offsets in the evaluator's private 24 MiB view.
They are not user input selectors.

| Offset/range | Purpose |
| --- | --- |
| 0..159 | Error, parser, formatter continuation and output control words |
| 160 | Plain error-message byte count for framed truncation |
| 256..359 | Parsed request and result-selection control words |
| 512..767 | Request/objective/profile/policy/evaluation digest state |
| 4096 + 192*i | Candidate i, with 128 admitted candidates and one parser scratch row |
| 40000..41023 | Candidate sorting indices |
| 43008 | Decimal reverse digits |
| 44032 | Literal scratch |
| 45056 | Fixed identity literal scratch, disjoint from all 128 sorting indices |
| 65536 onward | Decoded string arena |
| 1572864 | Number-role result record |
| 2097152 | Successful response serialization |
| 6291456 | SHA workspace |
| 7340032 | Number/debug workspace |
| 8388608 | Plain error message |
| 16777216 | Debug expansion, subsequently final error JSON |

The number role accepts the original number token as input, output capacity
at least 96 and workspace at least 16,384. Output header is four u64 words:
status (0 valid, 1 range, 2 invalid), relative error position, binary64 bits,
formatted text byte count. Text begins at 32.

The debug role consumes decoded UTF-8 and emits the exact Rust Debug string
contents including quotes and escapes. The helper is invoked only after
the main parser's original UTF-8/escape validation.

The standalone transport's 48 MiB view uses:
0..127 control, 512 session, 1024 sigaction, 1048576 argv/input,
9441208 output frame prefix, 9441280 output body, and 18874368 evaluator work.
Its output action descriptor holds syscall number at 0, six arguments at
8..48, and two-bit pointer selectors at 56. Selector 3 denotes a checked
offset into the same work view. Result 1 requests that syscall, 2 requests
the fixed evaluator role, and 4 continues the HIA state machine. A syscall
result is returned in work word 8. The HIA policy chooses every branch,
length, retry and exit; the mechanical adapter never parses a request.
