# Native generic cold case assertions

cold_cases_gate.hepta is an independently constructed HIA assertion component.
It does not compile a target program, supply a historical VM answer, or execute
Python. Its image is produced by the admitted independent HIA assembly frontend,
reference projector, seed backend and native filter packer, before target B0.

The command takes no arguments and accepts HIAQCG01 followed by seven
little-endian u64 fields (mode, a, b, c, d, e, reserved_zero), then payload.

* Mode 0 checks a complete current HIASPR01 result. a is outcome class
  (0 returned, 1 trap, 2 budget); b is the semantic category (0 none,
  1 overflow, 2 division_by_zero, 3 bounds, 4 allocation, 5 user, 6 steps,
  7 calls, 8 heap); c is the original step budget, d the return count,
  and e the complete external-view snapshot size. It checks exact extent,
  the original status/detail category mapping and actual charged steps.
  Only a steps-budget result may charge the original budget plus one.
* Mode 1 checks the complete plain independent assembly diagnostic.
  a is the ASCII expected error-code length, b the report size and
  c/d/e are zero. Payload is the expected code followed by the complete
  diagnostic. It checks the entire fixed report envelope, a valid message
  string and its exact leading error category. It does not accept an error
  merely because a child returned nonzero.

Successful checks return exactly HIAQOK01; failures publish no output.
The current standalone filter retains the existing 8 MiB transport bound.
This is an assertion tool for the declared fixtures, not a claim to exhaust
the independent VM's entire larger input domain.

The v1 qualification contains 424 executed positive and negative checks:
251 distinct original generic-family Core rejections with exact error
categories, arithmetic/resource/explicit-trap and budget mappings, malformed
envelopes, exact report-prefix mutations and the step-budget plus-one boundary.
The original 13-family runs and final complete cold master remain separate.

Qualified image: 82872 bytes,
a59fb407f8faa80b2f9638c71f348519418d631fa2cd63a0b11a06aae1e0ec80.
Source SHA256:
149faf2ba1323c5ff33d14e3c8db39a02fa3327d50569f5e197d018ad58d2791.
The full report is retained at
native-release-closeout-20261124T0740Z/cold-generic-gate-v1/qualification.json.
