# Retained source integration failures and repairs

Both original failed CI attempts remain failures. Their complete decoded public job logs are retained unchanged beside this report. No cleanup budget, test inventory, failure status, or runtime catalog was weakened to make a retry pass.

## Discovery control

Source commit: `5f070218dfd7ec656147322cfb7da14bbb5894fd`.
Workflow [42507445694](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42507445694), job 128813030284 ran 524 tests in 408.602 seconds: one failed. The discovery test required obsolete optional prose (`result.artifact`), whereas the pinned runtime publishes the complete issued artifact reference through `outputSchema.properties.result.properties.artifact`. The old test also expected obsolete request-key wording and an optional hash description.

The repaired existing control checks equality of the issued reference schema across artifact output, read input and candidate import input; all three required reference fields; rejection of malformed and extra fields; the exact 64-hex catalog hash schema; and both false authority flags. It validates recovery without modifying the rejected request or refunding its attempt. Changed writer arguments require a new key only after confirmed rejection; accepted or unknown operations retain the original identity. Five local contract recovery tests pass. The canonical catalog and runtime pin are unchanged.

## Strict fake-child cleanup

Workflow [42507445856](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42507445856), job 128813031226 failed the existing eleven-stage fault-injection test. In the CertPart06 subcase, the intended failure stage was 7; the runner correctly stopped earlier at stage 2 with `cleanup_failed`, three invocations, two committed stage receipts, wall time 3964072357 ns and DENY_ALL authority. The original log does not include the failed process receipt, so it does not establish whether scheduling, filesystem latency or another cleanup condition caused that result.

The existing assertion now includes the available failed process receipt in its diagnostic before the temporary fixture is removed. All assertions, stage counts, process ownership rules and the two-second cleanup deadline remain unchanged. A later successful attempt cannot erase this observation or establish the unobserved root cause. The next exact-source CI run must still execute this control.

## Qualification report scope

The independently qualified v12 source at `4110a0f4739438ac9188ad66a7be8037feb4bdfa` performs successor compilation in HIA, while the host also assembles and generates independent native oracle programs after B0. Its original raw qualification reports are retained unchanged. This integrated source corrects the old broad `python_parser_or_codegen_after_B0` flag to true and publishes two explicit scopes: `python_parser_or_codegen_in_successor_compilation: false` and `host_reference_codegen_after_B0: true`. The compiler source bytes are unchanged by this reporting repair. A retained native test checks all three values on newly generated reports.

These are integration repairs and finite qualification observations. They do not establish general compiler refinement, general loader or ABI correctness, production adoption, or NDU economic value.

