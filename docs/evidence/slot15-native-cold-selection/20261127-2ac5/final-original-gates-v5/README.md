# Final Slot15 source-boundary and shallow-checkout validation

The actual original fifteen methods remain unchanged. The final successor b5814c3b28f57a4b87e9eeda72d250c6b3497f72 retains the strict native cold selector, all three physically checked compiler generations, original caller budgets, retained-owner poisoning and 202 actual native frames.

The source review found a narrow history-to-suite-loading binding window. Its successor freezes the initial source pins before history review, binds every captured relation and test source to that set, verifies the set before and after loading the original suite, and performs a final exact history comparison. The controls exercise physical mutations at both boundaries; no earlier full-gate false PASS is asserted.

Actual ROG runs:
- 7dac0b02e12dca9c8d77213e49e964433f26e137: all 9 source control groups passed; complete original Slot15 passed in 6.769258579995949 seconds with 202 actual frames.
- b5814c3b28f57a4b87e9eeda72d250c6b3497f72: all 9 source control groups passed (0.181 seconds inside unittest); complete original Slot15 passed in 7.30519057600759 seconds with 202 actual frames (11.086945713992463 seconds for the complete external invocation).
- Both runs preserve their complete stdout, stderr, commands, reports and generated products, with clean source and unchanged cold report, generation index and all three compiler images.

The QA-only b581 successor embeds independently captured original source bytes in the negative-control test. It does not change the product, qualifier, fixed source-history helper or immutable relation. Actual Mac controls passed in an ordinary checkout and in a real depth-one clone with exactly one commit and no f765 predecessor commit object. Thus CI's shallow checkout does not silently depend on unavailable history.

The Linux archive contains 66 independently read-back members; its SHA256 is 78908714820ad55e047df06d19936c0be9d368971d58211ae407bf9582b64022. The first original nested_report failure and intermediate exact error-context failure remain in the earlier evidence directory and were not rewritten. This is complete original Slot15 component qualification, not a claim of whole native delivery or old-stack retirement.
