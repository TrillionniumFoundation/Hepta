"""Unchanged V9 task messages with separately pinned Qwen3 plain rendering."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
from experiments.hia_agent_toolstudy_v9_20261029.prompts import REPAIR, render_nodes, prompt, messages

HERE = Path(__file__).resolve().parent
TOKENIZER_CONFIG = HERE / "provenance/Qwen__Qwen3-4B-Instruct-2507__tokenizer_config.json"
TOKENIZER_BYTES = 9377
TOKENIZER_SHA256 = "a62ff0a2472a0fa1b8eaabcb57c59b58afa42a22831dc141400b6e0cf2b65ce3"


def official_template_binding():
    data = TOKENIZER_CONFIG.read_bytes()
    if len(data) != TOKENIZER_BYTES or hashlib.sha256(data).hexdigest() != TOKENIZER_SHA256:
        raise ValueError("E_TOOLSTUDY_V10_OFFICIAL_TEMPLATE_BYTES")
    cfg = json.loads(data)
    return {"config_sha256": TOKENIZER_SHA256, "config_bytes": TOKENIZER_BYTES,
            "chat_template_sha256": hashlib.sha256(cfg["chat_template"].encode()).hexdigest(),
            "scope": "plain user/assistant string messages, no tools or supplied system, add_generation_prompt=true"}


def plain_qwen_template(items):
    """Exact plain-role branch of the pinned official non-thinking template.

    Task messages are unchanged. Qwen3-2507 does not synthesize a default system
    message. Actual owned-server renderings are checked before generation;
    this helper neither tokenizes, supplies answers nor rewrites model text.
    """
    official_template_binding()
    if not items or any(set(item) != {"role", "content"} or item["role"] not in {"user", "assistant"}
                        or type(item["content"]) is not str for item in items):
        raise ValueError("plain user/assistant messages required")
    return ("".join("<|im_start|>" + item["role"] + "\n" + item["content"] + "<|im_end|>\n" for item in items)
            + "<|im_start|>assistant\n")
