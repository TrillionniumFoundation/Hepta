# v65 source repair and retained preparation observations

These are original observations with their recorded source identities. They do
not qualify a later commit and do not turn desktop prerequisites into test passes.

* At merged source `c4add22574be3556434e912d5af4714cf5ad6d82`, all 46 actual
  workflow generators completed with exit zero in 31.689197635998426 seconds.
  The 3,042 indexed files had identical before/after SHA-256 maps. The observation
  and original log are retained in `v65-integration-regeneration-r1`.
* The same merged source ran all 18 selected workflow, constructor/outer source
  and frame controls in 3.3776812899996003 seconds. Loaded and executed IDs match;
  errors, failures, skips, expected failures and unexpected successes are zero.
  This source-only observation is under `v65-merged-source-controls-r1`.
* The later names-fixture repair removes construction of an unused compiler CFG.
  It preserves the exact HIA compiler source, independent-reference bytes,
  106 cases, 40 refusals and all 154 public assembly calls. Its original timing
  and 21-test observations are in the adjacent `hia_cold_throughput_20261111`
  directory. A local reduction of approximately 1.13 seconds does not establish
  compliance with the complete 180-second cold deadline.
* `desktop-preparation-originals` preserves verified tools, six external fixture
  builds and their process-owner receipts for exact source `6994512`. These are
  preparation records only. The source has not been relabelled v65. Earlier HOLD
  records and restoration of the original `93d66bc` CI archive custody are kept.

The prior `6994512` GitHub source and cold failures remain in
`hia_v64_ci_terminal_20261111`. Native qualification of the new frozen source is
still required. No deployed worker or release selector is changed here.
