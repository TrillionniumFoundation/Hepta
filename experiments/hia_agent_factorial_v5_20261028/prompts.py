"""Prospectively specified presentation change; no evaluator answers are added."""
from tools.provider_adapter.llama_cpp_engine import canonical
from hepta.hia_program_tools import decode_json
from experiments.hia_agent_factorial_v4_20261028 import calibration, fixtures


def prompt(task, arm):
    original = calibration.prompt(task) if arm == "calibration" else fixtures.prompt(task, arm)
    # Change only the response envelope and generic self-check instruction.
    # The task specification, public examples and source are reused verbatim.
    original = original.replace('Return ONLY JSON {"files":', 'Return ONLY JSON {"check":"short requirement self-check","files":')
    original = original.replace("no fences or explanation", "no fences or text outside the JSON object")
    return (original + "\nThe check field comes before files. Use it to check every requested change, integer widths, provider/caller agreement and owner lifetime. It must be brief (at most 1536 characters). Then supply both complete corrected files. Do not merely copy the current implementation. The check text is not scored; only compiled files and their behavior are scored.")


def strip_check(text):
    """The model's check text has no source-edit authority."""
    try:
        value = decode_json(text)
        if (type(value) is not dict or set(value) != {"check", "files"}
                or type(value["check"]) is not str or len(value["check"]) > 1536):
            return text  # Original evaluator will reject the wrong envelope.
        return canonical({"files": value["files"]}).decode()
    except (ValueError, TypeError):
        return text
