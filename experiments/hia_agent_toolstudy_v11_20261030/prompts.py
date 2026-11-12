"""Unchanged V9 messages with the pinned Qwen3.5 non-thinking rendering.

The helper checks the official plain-role branch. It never tokenizes, provides
answers, or changes the model response passed to the source validator.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from experiments.hia_agent_toolstudy_v9_20261029.prompts import (
    REPAIR, render_nodes, prompt, messages,
)

HERE = Path(__file__).resolve().parent
TOKENIZER_CONFIG = HERE / "provenance/Qwen__Qwen3.5-4B__tokenizer_config.json"
TOKENIZER_BYTES = 16710
TOKENIZER_SHA256 = "316230d6a809701f4db5ea8f8fc862bc3a6f3229c937c174e674ff3ca0a64ac8"
OFFICIAL_TEMPLATE_SHA256 = "a4aee8afcf2e0711942cf848899be66016f8d14a889ff9ede07bca099c28f715"
GGUF_TEMPLATE = HERE / "provenance/GGUF_chat_template.jinja"
GGUF_TEMPLATE_SHA256 = "7f0e529032c25183bcd66c7f238da2d377f43be754a94e2725a58c4e16d2ed67"


def official_template_binding():
    data = TOKENIZER_CONFIG.read_bytes()
    if len(data) != TOKENIZER_BYTES or hashlib.sha256(data).hexdigest() != TOKENIZER_SHA256:
        raise ValueError("E_TOOLSTUDY_V11_OFFICIAL_TEMPLATE_BYTES")
    cfg = json.loads(data)
    official = hashlib.sha256(cfg["chat_template"].encode()).hexdigest()
    quantized = hashlib.sha256(GGUF_TEMPLATE.read_bytes()).hexdigest()
    if official != OFFICIAL_TEMPLATE_SHA256 or quantized != GGUF_TEMPLATE_SHA256:
        raise ValueError("E_TOOLSTUDY_V11_TEMPLATE_BYTES")
    return {
        "config_sha256": TOKENIZER_SHA256,
        "config_bytes": TOKENIZER_BYTES,
        "chat_template_sha256": official,
        "gguf_chat_template_sha256": quantized,
        "templates_identical": False,
        "chat_template_kwargs": {"enable_thinking": False},
        "scope": "plain user/assistant strings, final user, no tools/system; add_generation_prompt=true",
        "whole_template_or_tokenizer_equivalence_claimed": False,
    }


def plain_qwen_template(items):
    """Exact official branch for the unchanged one-turn or repair messages.

Qwen3.5's official template trims outer role-content whitespace and its
non-thinking generation suffix contains an empty think block. All raw task
messages and model responses remain retained independently of that rendering.
The study uses only [user] and [user, assistant, user]. A reasoning-tag-bearing
assistant response is refused: the official template would remove part of it,
which cannot satisfy the study's complete previous-response history rule.
"""
    official_template_binding()
    if (type(items) is not list or len(items) not in {1, 3}
            or any(type(item) is not dict or set(item) != {"role", "content"}
                   or type(item["content"]) is not str for item in items)
            or [item["role"] for item in items] != (
                ["user"] if len(items) == 1 else ["user", "assistant", "user"])):
        raise ValueError("E_TOOLSTUDY_V11_PLAIN_MESSAGE_SCOPE")
    for item in items:
        if item["role"] == "assistant" and "</think>" in item["content"]:
            raise ValueError("E_TOOLSTUDY_V11_REASONING_HISTORY_NOT_PLAIN")
    final = items[-1]["content"].strip()
    if final.startswith("<tool_response>") and final.endswith("</tool_response>"):
        raise ValueError("E_TOOLSTUDY_V11_TOOL_RESPONSE_SCOPE")
    return ("".join("<|im_start|>" + item["role"] + "\n" + item["content"].strip()
                    + "<|im_end|>\n" for item in items)
            + "<|im_start|>assistant\n<think>\n\n</think>\n\n")
