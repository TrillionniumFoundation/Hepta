"""Original-byte Codex provider adapter for the macro mechanism campaign.

This adapter invokes the selected existing provider once per requested turn. It
never signs a receipt, retries a model, fills missing usage with zero, changes
an account, or calls a model-created tool. The caller supplies the original
remaining wall/token allowance; observed overruns remain charged.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.hia_agent_codex_transport import (CodexEvents, EventFailure,
    checked_usage, identity, run_owned, strict_json)

SCHEMA = "hepta.hia.agent.macro-provider-receipt.v1"
REQUEST_SCHEMA = "hepta.hia.agent.macro-provider-request.v1"
CHUNK_BYTES = 1024 * 1024
SOURCE_FILES = ("tools/hia_macro_codex_provider.py", "tools/hia_agent_codex_transport.py",
                "benchmarks/hia_agent_public_tools/PROTOCOL.json")
INSTRUCTION = ("Use only the public task and current cost state below. Propose a complete HIA Core JSON "
    "program preserving the task's behavior and scalar ABI, and choose whether its remaining "
    "search/verification/emission/evaluation/adoption/use/rollback sequence is worth performing "
    "under the original remaining budget. The alternative abstain uses the verified incumbent. "
    "The supplied forecasts have explicit uncertainty and are not observations of your proposal. "
    "No candidate has been checked yet. Return exactly one JSON object with keys candidate "
    "(the complete HIA Core program) and selected_id (candidate or abstain). Do not use tools, "
    "execute commands, read local files, browse, or add Markdown. Existing user rules remain effective.\n")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode()


def require(ok, reason):
    if not ok:
        raise ValueError("E_HIA_MACRO_PROVIDER: " + reason)


class MacroEvents(CodexEvents):
    """Accept typed reasoning, retaining the base strict no-tools transport."""
    def line(self, raw):
        event = strict_json(raw)
        if (type(event) is dict and event.get("type") in {"item.started", "item.updated", "item.completed"}
                and type(event.get("item")) is dict and event["item"].get("type") == "reasoning"):
            item = event["item"]
            require(set(event) == {"type", "item"} and {"id", "type"} <= set(item)
                and set(item) <= {"id", "type", "text"} and type(item["id"]) is str
                and ("text" not in item or type(item["text"]) is str)
                and self.turn_count == 1 and self.completed_count == 0, "invalid reasoning event")
            self.events.append(event)
            return
        super().line(raw)


def charged_tokens(usage):
    if usage is None:
        return None
    usage = checked_usage(usage)
    # Preserve all provider counters. The inherited transport does not attest
    # whether reasoning is included in output, so budget conservatively and
    # label the convention instead of asserting a billing-token identity.
    return usage["input_tokens"] + usage["output_tokens"] + usage["reasoning_output_tokens"]


def parse_stream(raw, warnings=()):
    require(type(raw) is bytes and len(raw) <= 16 * 1024 * 1024, "bounded raw stream required")
    events, failure, usage_rows, account_block = MacroEvents(list(warnings)), None, [], False
    lines = raw.splitlines()
    require(len(lines) <= 4096 and all(0 < len(line) <= CHUNK_BYTES for line in lines),
            "bounded nonempty JSONL lines required")
    for line in lines:
        try:
            event = strict_json(line)
            if type(event) is dict and event.get("type") == "turn.completed":
                try:
                    usage_rows.append(checked_usage(event.get("usage")))
                except ValueError:
                    usage_rows.append(None)
            message = (event.get("message") if type(event) is dict and event.get("type") == "error" else
                event.get("error", {}).get("message") if type(event) is dict and event.get("type") == "turn.failed"
                and type(event.get("error")) is dict else None)
            if type(message) is str and message.startswith("You've hit your usage limit."):
                account_block = True
            if failure is None:
                events.line(line)
        except (ValueError, UnicodeError, TypeError, RecursionError) as error:
            failure = failure or str(error)
    usage = usage_rows[0] if len(usage_rows) == 1 else None
    answer = None
    if failure is None:
        try:
            completed = events.complete()
            require(completed["usage"] == usage, "inconsistent original usage")
            answer = strict_json(completed["text"])
            require(type(answer) is dict and set(answer) == {"candidate", "selected_id"}
                and type(answer["candidate"]) is dict and answer["selected_id"] in {"candidate", "abstain"},
                "model must return one complete proposal and macro choice")
        except (ValueError, UnicodeError, TypeError, RecursionError) as error:
            failure = str(error)
    return {"usage": usage, "charged_model_tokens": charged_tokens(usage), "answer": answer,
        "stream_valid": failure is None, "error": failure, "account_block_observed": account_block}


def request_document(task, state):
    # The deterministic reference proposal and all later outcomes are excluded.
    public = {key: deepcopy(task[key]) for key in ("id", "specification", "baseline")}
    return {"schema": REQUEST_SCHEMA, "task_id": task["id"],
        "task_input_sha256": sha256(canonical(task)).hexdigest(), "task": public,
        "state": deepcopy(state), "instruction": INSTRUCTION,
        "information_boundary": "registered task, incumbent, prior receipts and supplied forecasts only"}


def prompt_bytes(request):
    require(type(request) is dict and request.get("schema") == REQUEST_SCHEMA
        and request.get("instruction") == INSTRUCTION, "unrecognized request")
    return INSTRUCTION.encode() + canonical({key: value for key, value in request.items()
        if key != "instruction"}) + b"\n"


def store_raw(evidence, raw):
    return {"sha256": sha256(raw).hexdigest(), "bytes": len(raw),
        "chunks": [evidence.put(raw[offset:offset + CHUNK_BYTES], binary=True)
                   for offset in range(0, len(raw), CHUNK_BYTES)]}


def read_raw(record, originals):
    require(type(record) is dict and set(record) == {"sha256", "bytes", "chunks"}
        and type(record["bytes"]) is int and 0 <= record["bytes"] <= 16 * 1024 * 1024
        and type(record["chunks"]) is list and len(record["chunks"]) <= 16,
        "invalid original stream inventory")
    raw = b"".join(originals[item] for item in record["chunks"])
    require(len(raw) == record["bytes"] and sha256(raw).hexdigest() == record["sha256"],
            "stream bytes do not match original digest")
    return raw


class CodexMacroProvider:
    def __init__(self, binary, model, *, warnings=(), reasoning_effort="low"):
        binary = Path(binary)
        require(binary.is_absolute() and os.access(binary, os.X_OK), "absolute executable Codex path required")
        require(type(model) is str and 1 <= len(model) <= 128 and not model.startswith("-"),
                "one explicit model selector required")
        require(reasoning_effort in {"low", "medium", "high"}, "bounded reasoning configuration required")
        require(type(warnings) in {list, tuple} and len(warnings) <= 16
            and all(type(x) is str and len(x) <= 4096 for x in warnings), "bounded registered warnings required")
        self.binary, self.model, self.warnings = binary, model, list(warnings)
        self.reasoning_effort, self.cli_identity = reasoning_effort, identity(binary)
        self.blocked_reason = None

    def description(self, evidence):
        return {"kind": "codex_cli", "cli_identity": self.cli_identity, "invocation_path": str(self.binary), "requested_model": self.model,
            "reasoning_effort": self.reasoning_effort, "registered_startup_warnings": self.warnings,
            "source_inventory": {name: evidence.put((ROOT / name).read_bytes(), binary=True) for name in SOURCE_FILES},
            "prompt_instruction_sha256": evidence.put(INSTRUCTION.encode(), binary=True),
            "turn_policy": "one fresh ephemeral no-tools request for both proposal and ordinary control advice",
            "token_budget_convention": "input + output + reasoning output; conservative overlap-unknown sum",
            "token_limit_enforcement": "observed after execution; overrun retained and terminates task",
            "requested_model_is_weight_attestation": False, "provider_tariff_or_invoice": None}

    def invoke(self, task, state, evidence, output, *, remaining_wall_ns, remaining_tokens):
        from tools.qualify_hia_macro_campaign import _read_regular
        request = request_document(task, state)
        request_sha = evidence.put(request)
        result = {"schema": SCHEMA, "request_sha256": request_sha, "provider": "codex_cli",
            "cli_identity": self.cli_identity, "requested_model": self.model,
            "reasoning_effort": self.reasoning_effort, "registered_startup_warnings": self.warnings,
            "remaining_wall_ns": remaining_wall_ns, "remaining_tokens": remaining_tokens,
            "status": "not_attempted", "process": None, "raw": None,
            "usage": None, "charged_model_tokens": 0, "answer": None,
            "monetary_cost": None, "original_receipts_authenticated": False,
            "account_block_observed": False, "strong_ordinary_advice_observed": False}
        if self.blocked_reason is not None:
            result["reason"] = self.blocked_reason
            return result
        if remaining_wall_ns <= 0 or remaining_tokens <= 0:
            result["reason"] = "original_remaining_budget_exhausted"
            return result
        require(identity(self.binary) == self.cli_identity, "CLI changed before request")
        output = Path(output)
        output.mkdir(mode=0o700, exist_ok=False)
        for name in ("cwd", "state", "logs"):
            (output / name).mkdir(mode=0o700)
        command = [str(self.binary), "exec", "--json", "--ephemeral", "--sandbox", "read-only",
            "--skip-git-repo-check", "-c", "sqlite_home=" + json.dumps(str(output / "state")),
            "-c", "log_dir=" + json.dumps(str(output / "logs")),
            "-c", "model_reasoning_effort=" + json.dumps(self.reasoning_effort), "-m", self.model, "-"]
        events = MacroEvents(self.warnings)
        process = run_owned(command, output / "cwd", output / "transport",
            input_bytes=prompt_bytes(request), wall_seconds=remaining_wall_ns / 1_000_000_000, on_line=events.line)
        raw = {name: _read_regular(output / "transport" / name,
            maximum=16 * 1024 * 1024 if name == "stdout.raw" else 4 * 1024 * 1024)
            for name in ("stdin.raw", "stdout.raw", "stderr.raw")}
        result.update(process=process, raw={name: store_raw(evidence, data) for name, data in raw.items()},
            cli_identity_after=identity(self.binary), status="failed", charged_model_tokens=None)
        parsed = parse_stream(raw["stdout.raw"], self.warnings)
        result.update(parsed)
        cleaned = all(process.get(name) is True for name in ("cleanup_confirmed", "leader_reaped", "streams_complete"))
        if not cleaned:
            self.blocked_reason = "not_attempted_after_uncertain_provider_cleanup"
            result["reason"] = self.blocked_reason
        elif parsed["account_block_observed"]:
            self.blocked_reason = "not_attempted_after_provider_account_quota"
            result["reason"] = self.blocked_reason
        elif result["cli_identity_after"] != self.cli_identity:
            self.blocked_reason = "not_attempted_after_cli_identity_change"
            result["reason"] = self.blocked_reason
        elif process.get("status") == "exited" and parsed["stream_valid"]:
            result["status"] = ("completed" if parsed["charged_model_tokens"] <= remaining_tokens
                and process["wall_ns"] <= remaining_wall_ns else "over_budget")
            result["strong_ordinary_advice_observed"] = result["status"] == "completed"
        return result


def verify_receipt(receipt, originals, provider):
    """Reconcile exact raw files with a local process record, never authenticate."""
    require(receipt.get("schema") == SCHEMA and receipt.get("provider") == "codex_cli",
            "unknown provider receipt")
    for key in ("cli_identity", "requested_model", "reasoning_effort", "registered_startup_warnings"):
        require(receipt[key] == provider[key], "provider identity/configuration drift")
    require(receipt["monetary_cost"] is None and receipt["original_receipts_authenticated"] is False,
            "unknown monetary costs or unauthenticated origins cannot be filled")
    request = strict_json(originals[receipt["request_sha256"]])
    if receipt["process"] is None:
        require(receipt["status"] == "not_attempted" and receipt["raw"] is None
            and receipt["usage"] is None and receipt["charged_model_tokens"] == 0
            and receipt["answer"] is None and receipt["strong_ordinary_advice_observed"] is False,
            "non-attempt cannot invent usage or a response")
        return request
    raw = {name: read_raw(receipt["raw"][name], originals) for name in ("stdin.raw", "stdout.raw", "stderr.raw")}
    require(raw["stdin.raw"] == prompt_bytes(request), "original request bytes differ")
    process = receipt["process"]
    invocation_root = Path(process["cwd"]).parent
    expected_argv = [provider["invocation_path"], "exec", "--json", "--ephemeral", "--sandbox", "read-only",
        "--skip-git-repo-check", "-c", "sqlite_home=" + json.dumps(str(invocation_root / "state")),
        "-c", "log_dir=" + json.dumps(str(invocation_root / "logs")),
        "-c", "model_reasoning_effort=" + json.dumps(provider["reasoning_effort"]),
        "-m", provider["requested_model"], "-"]
    require(process["argv"] == expected_argv, "actual provider executable/model/configuration differs")
    for name, data in raw.items():
        require(process["files"][name]["sha256"] == sha256(data).hexdigest()
            and process["files"][name]["bytes"] == len(data), "process output identity differs")
    parsed = parse_stream(raw["stdout.raw"], provider["registered_startup_warnings"])
    require(all(receipt[key] == value for key, value in parsed.items()), "usage or answer differs from original stream")
    require(type(process["wall_ns"]) is int and process["wall_ns"] >= 0,
            "unknown original provider duration")
    if receipt["status"] == "completed":
        require(process.get("status") == "exited" and process.get("returncode") == 0
            and all(process.get(key) is True for key in ("cleanup_confirmed", "leader_reaped", "streams_complete"))
            and parsed["stream_valid"] and receipt["cli_identity_after"] == provider["cli_identity"]
            and 0 < receipt["charged_model_tokens"] <= receipt["remaining_tokens"]
            and process["wall_ns"] <= receipt["remaining_wall_ns"]
            and receipt["strong_ordinary_advice_observed"] is True, "completed provider lacks complete bounded originals")
    else:
        require(receipt["strong_ordinary_advice_observed"] is False, "failed provider cannot supply admitted advice")
    return request


def main():
    """One transport smoke request. It is never a four-arm or P1 result."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--codex", type=Path, required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--task", type=Path, required=True)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--wall-seconds", type=int, default=90)
    parser.add_argument("--tokens", type=int, default=32768)
    args = parser.parse_args()
    from tools.qualify_hia_macro_campaign import Evidence, _read_regular
    require(1 <= args.wall_seconds <= 180 and 1 <= args.tokens <= 100000, "bounded diagnostic allowance required")
    task, state = (strict_json(_read_regular(path)) for path in (args.task, args.state))
    provider = CodexMacroProvider(args.codex, args.model)
    evidence = Evidence(args.output)
    configuration = provider.description(evidence)
    # A separate diagnostic allowance is preregistered. It does not overwrite
    # the original campaign or retrofit provider cost into earlier timings.
    evidence.named("registration.json", {"kind": "provider_transport_diagnostic", "provider": configuration,
        "task_sha256": evidence.put(task), "state_sha256": evidence.put(state),
        "wall_ns": args.wall_seconds * 1_000_000_000, "tokens": args.tokens})
    result = provider.invoke(task, state, evidence, args.output / "invocation",
        remaining_wall_ns=args.wall_seconds * 1_000_000_000, remaining_tokens=args.tokens)
    evidence.named("result.json", {"scope": "single provider mechanism diagnostic; no actual task qualification",
        "receipt": result, "objects": list(evidence.inventory.values()), "p1_acceptance": "HOLD"})
    print(json.dumps({key: result[key] for key in ("status", "usage", "charged_model_tokens", "account_block_observed")}))
    return 0 if result["status"] == "completed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
