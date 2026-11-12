"""Public loader names for the complete HIA machine-plan control owner."""
from .hia_machine_plan_control_native import (
    SOURCE, SCHEMA, SELECTOR, NativeMachinePlanControl,
)
from .hia_json_preflight_native import _installed_json_image

NativeMachinePlan = NativeMachinePlanControl


def installed_machine_plan(manifest_path):
    return _installed_json_image(manifest_path, SOURCE, SCHEMA, NativeMachinePlan)
