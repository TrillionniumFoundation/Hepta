"""Generic public edit-process guidance; no task-specific answer or node hints."""
from experiments.hia_agent_toolstudy_v11_20261030 import prompts as previous

REPAIR = previous.REPAIR
messages = previous.messages
plain_qwen_template = previous.plain_qwen_template
official_template_binding = previous.official_template_binding

PUBLIC_REVIEW = (
    "Before submitting, check every clause of the specification against the resulting complete program, "
    "including each callee, exact integer width and owner use. A repair replaces the entire rejected transaction "
    "against the original source; all still-needed changes must be present again. "
    "Public examples are checks, not the complete input domain. Return only the required JSON."
)
PUBLIC_NODE_GUIDE = (
    "For each edit, select the public node ID first, then write only that node's replacement. "
    "A type node takes a type, never a declaration. An expression node takes one expression, "
    "never a function or unwrapped sequence of statements. Select disjoint spans; "
    "do not repeat one replacement at overlapping ancestor and child nodes. "
    "The host does not extract fragments from complete functions or merge failed edits."
)


def prompt(task, arm, query=None):
    result = previous.prompt(task, arm, query) + "\n" + PUBLIC_REVIEW
    if arm == "calibration" or arm.endswith("_node"):
        result += "\n" + PUBLIC_NODE_GUIDE
    return result
