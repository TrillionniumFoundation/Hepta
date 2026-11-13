# Machine plan CONTROL family

## Candidate status

This document describes an authored integration candidate. The new family names, canonical resources, scope routing, builder inputs and source inventory have not yet been generated, compiled or qualified together. Historical component results from a733 and main do not qualify this new source.

The immutable inputs are main `51bc24b8b03e5adc3da1b2b3490ad5cc7357e8d8` and a733 `a733926a2786a3d4a37304bd2d18ebb2eac57ac9`. The original main document remains at `docs/HIA_MACHINE_PLAN_NATIVE.md`. The original a733 document is recoverable verbatim at that path in the fixed a733 commit; its old selector names must not be used as aliases for this family.

## Explicit selection

| Item | CONTROL value |
| --- | --- |
| Selector | `HEPTA_HIA_MACHINE_PLAN_CONTROL_MANIFEST` |
| Manifest schema | `hepta.hia.machine-plan-control-native.v1` |
| HIA source | `examples/hia_bootstrap/machine_plan_control.hepta` |
| Native module | `hepta.hia_machine_plan_control_native` |
| Selection module | `hepta.hia_machine_plan_control_selection` |
| Generator | `tools.generate_hia_machine_plan_control` |
| Builder | `tools.build_hia_machine_plan_control` |

The main v1 image remains at `machine_plan.hepta` and owns validation and the register witness. Its original code-options and preservation-check functions remain hosted. This independent CONTROL image owns all four original public APIs and their three helper bodies. Its `HIAPLN02` continuation protocol is not the main v1 protocol.

The existing main selector `HEPTA_HIA_MACHINE_PLAN_MANIFEST` keeps its original ABI. Selecting it together with the CONTROL selector is rejected before either manifest or image is admitted. A complete public operation captures the selected family, or explicit absence, once. Callback changes to environment selectors cannot silently switch the active implementation. A selected failure is returned as a failure; it does not enter the other family or the retained reference.

## Reproduction requirements

The canonical source must be regenerated in the actual combined source checkout. A build must use that exact source's current completed cold report and compiler. The existing compiler, cold, group and whole-suite limits are unchanged. An old image, old cold report or source-only result is not a substitute.

```sh
python -m tools.generate_hia_machine_plan_control
python -m tools.build_hia_machine_plan_control --output NEW_DIRECTORY --compiler CURRENT_B3 --cold-report CURRENT_COLD_REPORT
```

Source selector: `tests.test_hia_machine_plan_control_native.MachinePlanSourceTests`.
Native selector: `tests.test_hia_machine_plan_control_native.MachinePlanNativeTests`.
Caller entry: `tools.qualify_hia_machine_plan_control_callers`; retain its original arguments and complete caller groups.

The complete lifecycle module `tests.test_hia_machine_plan_control_lifecycle` remains separate. The caller qualifier retains all four original caller modules and all 44 original caller IDs.

New routing controls are in `tests.test_hia_backend_family_selection`. They check dispatch/capture only and never imply that any image executed. The main original suites, CONTROL full-frame/VM tests, installed-wheel controls, changed-source/image rejection, actual observer counts, exception identities and operand-retirement observations all remain required. Installed fixtures include all eleven original main resource groups.

## Remaining hosted boundaries

The selected HIA program owns its reviewed policy. Python remains the fixed object/FFI transport and supplies the original external providers. Keeping main scheduling, generic native continuation, Code, ELF, borrowed-byte and build owners available does not claim that selecting this one family activates all of them. Default activation and whole-source qualification remain open until the complete combined gates run.
