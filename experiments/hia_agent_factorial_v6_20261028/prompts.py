"""No new examples or solution code: disclose the new profile and pair feedback."""
from experiments.hia_agent_factorial_v4_20261028 import evaluator, fixtures
from experiments.hia_agent_factorial_v5_20261028.prompts import prompt as previous_prompt


def prompt(task, arm):
    text = previous_prompt(task, arm)
    if arm == "calibration" or arm.startswith("rust_"):
        text = text.replace(",".join(fixtures.RUST_METHODS), ",".join((*fixtures.RUST_METHODS, "into")))
        text += ("\nThe into conversion method has a narrow additional rule: its receiver must be a bare identifier naming a declared scalar function parameter (u8/u16/u32/u64/usize/bool), with zero arguments. Macro definitions and dollar-sign metavariables are outside this profile in every file. In a file using into, do not shadow that receiver parameter, use closures or bar operators, or use complex let binding patterns. Container, field and expression receivers are outside this profile. Real rustc still decides whether the requested target conversion exists. Normal as casts remain available.")
    return text


def public_feedback(task, built, observed):
    result = evaluator.feedback(built, observed)
    actual = result.pop("public_observed")
    expected = result.pop("public_expected")
    result["public_argument_order"] = ["a", "b", "c"]
    result["public_cases"] = []
    if observed is not None:
        for index, (arguments, wanted) in enumerate(zip(task["public_cases"], expected)):
            seen = actual[index] if index < len(actual) else [None, None]
            result["public_cases"].append({
                "arguments": arguments,
                "entrypoint": {"expected": wanted[0], "observed": seen[0]},
                "provider_probe": {"expected": wanted[1], "observed": seen[1]},
            })
    return result
