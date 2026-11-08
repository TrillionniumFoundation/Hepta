# Retained source integration failures and repairs

The original failed CI attempts remain failures. Their complete decoded public job logs are retained unchanged beside this report. No cleanup budget, test inventory, failure status, or runtime catalog was weakened to make a retry pass.

## Discovery control

Source commit: `5f070218dfd7ec656147322cfb7da14bbb5894fd`.
Workflow [42507445694](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42507445694), job 128813030284 ran 524 tests in 408.602 seconds: one failed. The discovery test required obsolete optional prose (`result.artifact`), whereas the pinned runtime publishes the complete issued artifact reference through `outputSchema.properties.result.properties.artifact`. The old test also expected obsolete request-key wording and an optional hash description.

The repaired existing control checks equality of the issued reference schema across artifact output, read input and candidate import input; all three required reference fields; rejection of malformed and extra fields; the exact 64-hex catalog hash schema; and both false authority flags. It validates recovery without modifying the rejected request or refunding its attempt. Changed writer arguments require a new key only after confirmed rejection; accepted or unknown operations retain the original identity. Five local contract recovery tests pass. The canonical catalog and runtime pin are unchanged.

The already submitted pre-repair source `aee4ed1f6bd478764b1f6684a3d51f346ffb05c6` subsequently completed [workflow 42508532969](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42508532969), job 128816351126. Its 524 tests ran in 320.929 seconds and failed the same obsolete `result.artifact` assertion. That full decoded log is also retained unchanged: `unified-job-128816351126.log`, 283,655 bytes, SHA256 `36e6dcde765d67e8cfc0ff383168fa2f006803e3ff536c02dffe72f8b55e4410`. This remains a failed attempt; the repaired head must earn its own result.

## Strict fake-child cleanup

Workflow [42507445856](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42507445856), job 128813031226 failed the existing eleven-stage fault-injection test. In the CertPart06 subcase, the intended failure stage was 7; the runner correctly stopped earlier at stage 2 with `cleanup_failed`, three invocations, two committed stage receipts, wall time 3964072357 ns and DENY_ALL authority. The original log does not include the failed process receipt, so it does not establish whether scheduling, filesystem latency or another cleanup condition caused that result.

The existing assertion now includes the available failed process receipt in its diagnostic before the temporary fixture is removed. All assertions, stage counts, process ownership rules and the two-second cleanup deadline remain unchanged. A later successful attempt cannot erase this observation or establish the unobserved root cause. The next exact-source CI run must still execute this control.

## Loan qualification selection

Source `e05dbfffcfc1ccc0bb380e4b0d97ec43f251e03e` completed [workflow 42509874778](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42509874778), job 128820396438. Its 524 tests ran in 466.630 seconds with one failure. The native loan assertion selected every check name containing `-loan-`, so eight newly added owned-buffer checks were unintentionally counted with the original 142 loan checks; the observed count was 150.

The existing test now selects the exact `original-loan-` and `modified-loan-` namespaces. It still requires exactly 142 checks and every check to pass; the full native qualification still requires all other owned-buffer/chain checks as well. The count is the unchanged two-compiler inventory of 23 successful cases, 39 invalid-Core refusals, six valid-Core profile refusals and three ELF-object cases. The full original log is retained as `unified-job-128820396438.log`, 284,882 bytes, SHA256 `f8e6202b22040ec7ecec8eedf54306c26a179bd2f0afb8478eeed84426c14dc9`. This repair does not recategorize the failed run as a pass.

## Qualification report scope

The independently qualified v12 source at `4110a0f4739438ac9188ad66a7be8037feb4bdfa` performs successor compilation in HIA, while the host also assembles and generates independent native oracle programs after B0. Its original raw qualification reports are retained unchanged. This integrated source corrects the old broad `python_parser_or_codegen_after_B0` flag to true and publishes two explicit scopes: `python_parser_or_codegen_in_successor_compilation: false` and `host_reference_codegen_after_B0: true`. The compiler source bytes are unchanged by this reporting repair. A retained native test checks all three values on newly generated reports.

These are integration repairs and finite qualification observations. They do not establish general compiler refinement, general loader or ABI correctness, production adoption, or NDU economic value.

