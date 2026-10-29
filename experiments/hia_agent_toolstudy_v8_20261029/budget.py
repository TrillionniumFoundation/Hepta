"""Shared prospective context limits: never truncate or repair model code."""
from __future__ import annotations

import copy
import hashlib

from experiments.hia_agent_toolstudy_v8_20261029 import prompts
from tools.provider_adapter.llama_cpp_engine import canonical


class BudgetFailure(ValueError):
    pass


def repair_messages(initial, previous, feedback, tokenize, limits):
    previous_ids = tokenize(previous)
    if len(previous_ids) > limits["previous_response_tokens"]:
        raise BudgetFailure("E_TOOLSTUDY_PREVIOUS_BUDGET: complete previous response exceeds registered cap; no truncation")
    # The complete diagnostic remains in the transaction/build evidence. Only
    # its displayed prefix may be halved; all public cases/resource flags stay.
    bounded = copy.deepcopy(feedback)
    diagnostic = bounded.get("diagnostic", "")
    diagnostic_text = diagnostic if type(diagnostic) is str else canonical(diagnostic).decode()
    bounded["diagnostic"] = diagnostic_text
    bounded["diagnostic_clipped"] = False
    bounded["diagnostic_original_sha256"] = hashlib.sha256(diagnostic_text.encode()).hexdigest()
    bounded["diagnostic_original_characters"] = len(diagnostic_text)
    calls = 1
    while True:
        feedback_ids = tokenize(canonical(bounded).decode()); calls += 1
        if len(feedback_ids) <= limits["feedback_tokens"]:
            break
        length = len(bounded["diagnostic"])
        if length == 0:
            raise BudgetFailure("E_TOOLSTUDY_FEEDBACK_BUDGET: public/resource observations do not fit; no case removal")
        bounded["diagnostic"] = bounded["diagnostic"][:length // 2]
        bounded["diagnostic_clipped"] = True
    result = prompts.messages(initial, previous, bounded)
    return result, {"previous_response_tokens": len(previous_ids), "feedback_tokens": len(feedback_ids),
                    "tokenizer_calls": calls, "feedback": bounded,
                    "previous_code_truncated": False, "public_cases_removed": False}

