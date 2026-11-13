# v68 complete-source qualification runner, revision 5

This revision preserves the complete v4 qualification sequence, original source
reproduction, full Git HEAD/tree/blob/mode custody, and unrestricted retained
test discovery. It adds the explicit slot-ledger group, the pinned-worker helper
and checker-identity groups, and matching-source cold selection for the Agent
identity fixture used by the helper bundle.

The 37 cold-report families include `SLOT_LEDGER` and `AGENT_IDENTITY`.
The ledger fixture composes its actual namespace, request, budget and publisher
dependencies. The Agent identity fixture admits the cold report before witness
or seed work and uses the existing cold builder. A development helper manifest
cannot override a requested cold report. Supplying a selector alone is not
qualification; the fixture must admit and consume that report.

The adjacent supervisor is byte-identical to v4, SHA256
`f3ebc453de2d2c9ecd3825547e301c122b6c7fa05af1aacd9103b8a67893ee80`.
The original v4 runner is retained unchanged, SHA256
`d4b4dcee0108cb4f9df77c16ddbd326e7435d5a94859e3ca71443e13a63d2573`.

| Boundary | Unchanged limit |
| --- | ---: |
| Product cold qualification | 180 seconds |
| Product cold cleanup | 3 seconds |
| External cold workflow step | 240 seconds |
| Ordinary steps and named suites | 1800 seconds |
| Unrestricted full retained discovery | 5400 seconds |
| Supervisor accepted step ceiling | 7200 seconds |

Run against a clean complete Git checkout, with a new output directory outside
the source tree:

```sh
python3 -B review-evidence/hia-native-rewrite-20261111/v68/qualification/run_hia_qualification_v5.py \
  --source /absolute/path/to/Hepta \
  --output /absolute/path/outside/Hepta/new-qualification \
  --full
```

All earlier component groups remain. Missing tests, failures, errors, skips,
expected failures and unexpected successes refuse qualification. Historical
logs are not relabelled. `whole_native_delivery_qualified` remains false even
if every retained test passes: the known direct slot-input domain gap and other
remaining foreign policy owners require their own completed implementation.
This file describes the harness; creating or checking it is not an execution.
