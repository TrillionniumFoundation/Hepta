# Complete worker report owner — development r1

The actual HIA image owns the ordinary worker's whole correlation, caught-error response, UUID formatting, report construction, and uncorrelated stderr decision. Its input objects are issued immutable Graph leases. Installation readings, service execution, exception observations, and entropy originate outside this component; no Graph header or hash is an authenticator for those facts. The complete ordinary worker and its eleven business methods remain open.

## Inputs and state

The retained native calling convention is RWW. The HIA entry borrows the second input read-only, so the semantic arguments are the immutable source Graph, an exact 192-byte command, and private mutable workspace. The workspace starts entirely zero, with at least 1,024 bytes. All offsets and lengths are unsigned 64-bit values. The Graph must remain the same private immutable lease through every continuation; its header is checked for correlation, not content authentication.

The command has 24 little-endian words:

| Word | Meaning |
| --- | --- |
| 0 | `HIAWRC01` |
| 1 | 1 initial, 2 growth continuation, 3 entropy response |
| 2–4 | nonzero invocation lease, nonzero request identity, last event sequence |
| 5 | disposition: 0 normal response, 1 error before service entry, 2 error after entry, 3 installation manifest |
| 6–9 | source Graph IDs for request, installation identities, response, and exception observation |
| 10–12 | entropy present flag, then the actual 16 entropy bytes as two words |
| 13–23 | zero |

Installation identities are the exact three-field dictionary of canonical worker, backend and catalog digests. An exception observation has string `message` and `type` fields; optional `code` and `retry_action` are preserved as values. Their absence selects the original defaults. In particular, a present null value is not treated as absence. The observation records the actual caught exception and does not authorize execution or retries.

Disposition 3 requires the other three roots to be zero. Disposition 0 has no exception root. Error dispositions have no response root. Request correlation requires only a dictionary containing the original four fields. This check deliberately does not admit their values, and it does not reject a correlated failure merely because a digest or tool value was invalid.

## Events

The entry returns 384 on a normal event. Its 128-byte event begins at workspace offset 256:

`[HIAWRE01, action, lease, request, sequence, neededWorkspace, outputOffset, outputBytes, refusalReason, rootID, outputKind, exitCode, disposition, 0, 0, 0]`

Actions are 0 complete, 1 grow, 2 request entropy, and 3 private protocol refusal. The actual BAD return `0xfffffffd` always takes precedence over event contents. An event sequence overflow can return BAD without a fresh event. A workspace shorter than 1,024 bytes cannot persist poison. The final fixed driver must discard the invocation lease on every BAD result. For complete workspaces a private framing or continuation error permanently poisons the state, and completion cannot be replayed.

Growth preserves the entire private workspace and resumes with command 2 and the last event sequence. All other command words remain exact. An entropy response uses command 3, sets the present flag, and supplies the actual bytes; all unrelated words remain exact. A correlated failure asks for entropy once when it was not already supplied. Normal responses, installation manifest output, and uncorrelated stderr do not request entropy. The HIA image applies UUID version 4 and variant bits itself and emits the original `worker-` plus 32 lowercase hexadecimal digits.

Output kind 1 is the complete immutable Graph view at `outputOffset/outputBytes`, with its final root ID in the header. Output kind 2 is the exact stderr byte span, including the newline, and exit code 2. Graph output is passed to the actual generic Graph wire owners with the original ordinary JSON profile: maximum 8 MiB, flags 2 (compact UTF-8, sorted keys), and the caller's unchanged integer conversion profile. The external worker adds the final newline. A late wire rejection is not changed into a successful report or a new caught-service rejection.

## Preserved decisions

Normal service responses are forwarded whole, including their original status and nested values. The report has all original nine fields. Error reports use the original four-field response and five-field error object. Before service entry the message is the first 4,096 Unicode code points, with the original exception class name used when the message is empty. Uncorrelated stderr uses the original empty string plus newline rather than the class-name fallback. After service entry every caught error becomes the original unknown-result message, `E_HIA_REQUEST_UNKNOWN`, and `observe_original`. Installation identities passed after a detected change are retained in that report.

No earlier response or Graph byte limit is introduced. Output allocation is measured and grown before the full value is copied. The existing final ordinary JSON wire budget retains its original position.

## Actual evidence

The production source is `agent_worker_report.hiaasm`, SHA-256 `12ffa47e29b679423299a0a410ef6e47aa0d36946073b8fd1c1665782be2c456`; the actual image is SHA-256 `1fdb7c72ae01d3364ebcd583e41102d2d83bd06a2ec989ae5fe56641b1ea16ed`. It was compiled by the exact historical f50 B3 under the original 10 CPU seconds, 20 wall seconds and 256 MiB development limits. This is not a fresh matching cold qualification.

The first semantic run completed all 47 byte comparisons, then exited 1 because its development teardown called a nonexistent image `close` method. Its exact script, harness, logs and raw states are retained. A new run with only mechanical mapping cleanup corrected passed all 47 cases: 119 actual report entries and 200 actual wire entries. The unchanged HIA image then passed 89 private protocol controls, 181 actual report entries and 10 actual wire entries. The raw cases explicitly demonstrate that an identical-header source substitution is not authenticated and that short workspace BAD requires driver lease discard.

The semantic oracle is the original complete `hia_agent_worker.main`, with controlled installation readings, service responses/errors and entropy. During native forwarding the retained worker, wire, decoder, service entry and `json.loads` are disabled. These are component observations, not claims that the eleven controlled service callbacks have been rewritten or executed natively.
