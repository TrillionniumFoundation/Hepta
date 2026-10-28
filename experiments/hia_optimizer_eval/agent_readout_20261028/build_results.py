#!/usr/bin/env python3
"""Read-only aggregation of original and supplemental Agent evidence.

This never calls a model, compiler, native candidate, or solver. Missing output
usage remains null. Original qualification status is not changed by coverage.
"""
from __future__ import annotations

import argparse
import collections
from decimal import Decimal
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from tools.provider_adapter.llama_cpp_engine import canonical, file_identity, validate_completion

HERE = ROOT / "experiments/hia_optimizer_eval/next_20261028"
ARMS = ("hia_full_context", "hia_edit_query", "rust_full_context", "rust_edit_query")


def read(path):
    return json.loads(Path(path).read_bytes())


def outer_time(path):
    path = Path(path)
    if not path.is_file():
        return None
    text = path.read_text()
    result = {"artifact": file_identity(path), "reported_precision": "Bash rounded milliseconds"}
    for key in ("real", "user", "sys"):
        found = re.search(r"^" + key + r"\s+(\d+)m([0-9.]+)s\s*$", text, re.M)
        if found:
            result[key + "_ns"] = int((Decimal(found[1]) * 60 + Decimal(found[2])) * 1000000000)
    return result


def transports(model_root):
    rows, by_messages = [], {}
    for path in sorted(model_root.rglob("transport-*.request.json")):
        request = read(path)
        response_path = path.with_name(path.name.replace(".request.json", ".response.json"))
        item = {"request": file_identity(path), "known_input_tokens": len(request["payload"]["prompt"]),
                "max_new_tokens": request["payload"]["n_predict"], "validated_output_tokens": None,
                "usage_complete": False, "response": None}
        if response_path.is_file():
            item["response"] = file_identity(response_path)
            try:
                usage = validate_completion(read(response_path), request["payload"]["prompt"],
                                            request["payload"]["n_predict"], json_object=True)
                item.update(validated_output_tokens=usage["output_tokens"], usage_complete=True)
            except Exception as error:
                item["usage_validation_error"] = {"type": type(error).__name__, "message": str(error)}
        item["known_total_tokens"] = item["known_input_tokens"] + (item["validated_output_tokens"] or 0)
        item["total_tokens"] = item["known_total_tokens"] if item["usage_complete"] else None
        key = canonical(request["messages"]).decode()
        if key in by_messages:
            raise ValueError("ambiguous or repeated exact request messages within one family")
        by_messages[key] = item
        rows.append(item)
    return rows, by_messages


def cost_for(path, index):
    request = read(path)
    key = canonical(request["messages"]).decode()
    if key not in index:
        raise ValueError("a scored attempt has no retained actual transport request")
    return index[key]


def token_summary(costs):
    inputs = sum(item["known_input_tokens"] for item in costs)
    outputs = sum(item["validated_output_tokens"] or 0 for item in costs)
    unknown = sum(not item["usage_complete"] for item in costs)
    return {"known_input_tokens": inputs, "input_tokens": inputs, "known_output_tokens": outputs,
            "known_total_tokens": inputs + outputs, "output_tokens": outputs if not unknown else None,
            "total_tokens": inputs + outputs if not unknown else None,
            "unknown_output_requests": unknown, "usage_complete": not unknown}


def full_or_unknown(values):
    return sum(values) if all(value is not None for value in values) else None


def normalized_state(state, error):
    return "budget_timeout" if state == "budget_timeout" or (error or {}).get("type") == "TimeoutError" else state


def summarize_model(root, model):
    folder = root / model["id"]
    model_result = read(folder / "MODEL_RESULT.json")
    primary = read(folder / "primary/report.json")
    primary_plan = read(folder / "primary/plan.json")
    case_counts = {task["id"]: len(task["cases"]) for task in primary_plan["tasks"]}
    if len(case_counts) != 4 or any(count != 77 for count in case_counts.values()):
        raise ValueError("registered primary input inventory differs")
    upgrade = read(folder / "upgrade/RESULT.json")
    upgrade_plan = read(folder / "upgrade/PLAN.json")
    transport_rows, transport_index = transports(folder)
    primary_extra_path = folder / "primary-continuation/RESULT.json"
    upgrade_extra_path = folder / "upgrade-continuation/RESULT.json"
    primary_extra = read(primary_extra_path) if primary_extra_path.is_file() else None
    upgrade_extra = read(upgrade_extra_path) if upgrade_extra_path.is_file() else None
    for extra in (primary_extra, upgrade_extra):
        if extra is not None and not extra["execution_record_valid"]:
            raise ValueError("supplemental execution has invalid identity or incomplete coverage")
    primary_rows = []
    original_model = primary["model_report"]
    sources = [(row, "original", folder / "primary" / model["id"] / (row["id"] + ".request.json"))
               for row in original_model["rows"]]
    if primary_extra:
        sources += [(row, "supplemental", folder / "primary-continuation" / row["id"] / "request.json")
                    for row in primary_extra["cells"]]
    for row, origin, request_path in sources:
        cost = cost_for(request_path, transport_index)
        if row.get("generation", {}).get("usage"):
            recorded = row["generation"]["usage"]
            if (recorded["input_tokens"], recorded["output_tokens"]) != (cost["known_input_tokens"], cost["validated_output_tokens"]):
                raise ValueError("primary row usage differs from actual transport")
        native = row.get("native", {})
        primary_rows.append({"id": row["id"], "task": row["task"], "arm": row["arm"], "origin": origin,
            "attempts": 1, "success": bool(row["ok"]), "original_state": row["state"],
            "state": normalized_state(row["state"], row.get("error")), "rejection_or_error": row.get("error"),
            "parse_accepted": bool(row.get("accepted")), "native_candidate_evaluated": "native" in row,
            "native_executed": native.get("native_executed") is True, "registered_validation_cases": case_counts[row["task"]],
            "inference_ns": row.get("inference_ns"), "evaluation_ns": row.get("evaluation_ns"),
            "request_envelope_wall_ns": row.get("request_wall_ns"), "cost": cost})
    expected_primary = [row["id"] for row in primary_plan["scheduled_cells"]]
    if [row["id"] for row in primary_rows] != expected_primary or len(primary_rows) != 16:
        raise ValueError("all 16 registered primary cells must be attempted exactly once in their suffix order")
    arm_summary = {}
    for arm in ARMS:
        rows = [row for row in primary_rows if row["arm"] == arm]
        if len(rows) != 4:
            raise ValueError("primary arm denominator changed")
        arm_summary[arm] = {"planned_cells": 4, "attempted_cells": 4, "attempts": 4,
            "successes": sum(row["success"] for row in rows), "unsuccessful_cells": sum(not row["success"] for row in rows),
            "timeouts": sum(row["state"] == "budget_timeout" for row in rows),
            "states": dict(collections.Counter(row["state"] for row in rows)),
            "native_candidate_evaluations": sum(row["native_candidate_evaluated"] for row in rows),
            "native_executions": sum(row["native_executed"] for row in rows),
            "known_inference_ns": sum(row["inference_ns"] or 0 for row in rows),
            "inference_ns": full_or_unknown([row["inference_ns"] for row in rows]),
            "known_evaluation_ns": sum(row["evaluation_ns"] or 0 for row in rows),
            "evaluation_ns": full_or_unknown([row["evaluation_ns"] for row in rows]),
            **token_summary([row["cost"] for row in rows])}
    upgrade_rows = []
    sources = [(row, "original", folder / "upgrade" / row["id"]) for row in upgrade["cells"]]
    if upgrade_extra:
        sources += [(row, "supplemental", folder / "upgrade-continuation" / row["id"]) for row in upgrade_extra["cells"]]
    for row, origin, where in sources:
        attempts = []
        for attempt in row["attempts"]:
            cost = cost_for(where / f"attempt-{attempt['index']}.request.json", transport_index)
            error = attempt.get("diagnostic") or attempt.get("build", {}).get("error")
            if not cost["usage_complete"] and error is None and origin == "original":
                error = upgrade.get("diagnostic")
            attempts.append({"index": attempt["index"], "original_status": attempt["status"],
                "state": normalized_state(attempt["status"], error), "rejection_or_error": error,
                "native_built": attempt.get("build", {}).get("native_built") is True,
                "public_validation_performed": attempt.get("public_validation") is not None,
                "public_validation_passed": (attempt.get("public_validation") or {}).get("status") == "correct",
                "inference_ns": attempt.get("inference_ns"), "evaluation_ns": attempt.get("evaluation_ns"),
                "request_envelope_wall_ns": attempt.get("request_wall_ns"), "cost": cost})
        state = row["status"]
        if any(attempt["state"] == "budget_timeout" for attempt in attempts):
            state = "budget_timeout"
        elif attempts and all(attempt["state"] == "response_rejected" for attempt in attempts):
            # The original public-validation stage also includes JSON admission.
            # Do not imply that a compiler or public native cases were reached.
            state = "response_rejected"
        upgrade_rows.append({"id": row["id"], "task": row["task"], "language": row["language"], "origin": origin,
            "success": bool(row["correct"]), "state": state, "original_state": row["status"], "attempts": attempts,
            "automatic_repair_rounds": max(0, len(attempts) - 1), "human_response_repair_rounds": 0,
            "manual_time_ns": None, "hidden_validation_performed": bool(row["hidden_tests_evaluated"]),
            "hidden_validation_ns": row.get("hidden_validation_ns"),
            **token_summary([attempt["cost"] for attempt in attempts])})
    if [row["id"] for row in upgrade_rows] != [row["id"] for row in upgrade_plan["scheduled_cells"]] or len(upgrade_rows) != 4:
        raise ValueError("all four registered upgrade cells must remain in the denominator")
    upgrade_summary = {}
    for language in ("hia", "rust"):
        rows = [row for row in upgrade_rows if row["language"] == language]
        attempts = [attempt for row in rows for attempt in row["attempts"]]
        upgrade_summary[language] = {"planned_cells": 2, "attempted_cells": len(rows),
            "successes": sum(row["success"] for row in rows), "attempts": len(attempts),
            "timeouts": sum(attempt["state"] == "budget_timeout" for attempt in attempts),
            "automatic_repair_rounds": sum(row["automatic_repair_rounds"] for row in rows),
            "native_builds": sum(attempt["native_built"] for attempt in attempts),
            "public_validations": sum(attempt["public_validation_performed"] for attempt in attempts),
            "hidden_validations": sum(row["hidden_validation_performed"] for row in rows),
            "known_inference_ns": sum(attempt["inference_ns"] or 0 for attempt in attempts),
            "inference_ns": full_or_unknown([attempt["inference_ns"] for attempt in attempts]),
            "known_evaluation_ns": sum(attempt["evaluation_ns"] or 0 for attempt in attempts),
            "evaluation_ns": full_or_unknown([attempt["evaluation_ns"] for attempt in attempts]),
            **token_summary([attempt["cost"] for attempt in attempts])}
    expected_requests = original_model["requests_started"] + upgrade["new_model_requests"]
    expected_responses = original_model["responses_received"] + upgrade["responses_received"]
    for extra in (primary_extra, upgrade_extra):
        if extra:
            expected_requests += sum(engine["requests_started"] for engine in extra["engines"])
            expected_responses += sum(engine["responses_received"] for engine in extra["engines"])
    if expected_requests != len(transport_rows) or expected_responses != sum(row["response"] is not None for row in transport_rows):
        raise ValueError("all-request cost inventory differs from runtime counters")
    costs = {"original_primary_phase_ns": primary["experiment_wall_ns"],
        "original_primary_native_controls_ns": primary["native_controls_wall_ns"],
        "original_primary_model_execution_ns": primary["model_execution_wall_ns"],
        "original_upgrade_phase_ns": upgrade["experiment_wall_ns"],
        "original_upgrade_native_controls_ns": upgrade.get("controls_wall_ns"),
        "original_whole_model_run_ns": model_result["experiment_wall_ns"],
        "original_whole_process_outer": outer_time(folder / "OUTER_EXECUTION.txt"),
        "supplemental_primary_run_ns": primary_extra["experiment_wall_ns"] if primary_extra else None,
        "supplemental_primary_outer": outer_time(folder / "primary-continuation/OUTER_EXECUTION.txt") if primary_extra else None,
        "supplemental_upgrade_run_ns": upgrade_extra["experiment_wall_ns"] if upgrade_extra else None,
        "supplemental_upgrade_outer": outer_time(folder / "upgrade-continuation/OUTER_EXECUTION.txt") if upgrade_extra else None,
        "cost_scope": "Original phase timers and supplemental run() timers end before final result writes; outer Bash real includes process startup/imports and final writes. These intervals overlap within each original whole run; do not sum parent and child intervals.",
        "manual_time_ns": None, "tool_construction_time_ns": None, "total_economic_cost": None}
    refs = [folder / "MODEL_RESULT.json", folder / "primary/plan.json", folder / "primary/report.json",
            folder / "upgrade/PLAN.json", folder / "upgrade/RESULT.json"]
    refs += [path for path in (primary_extra_path, upgrade_extra_path) if path.is_file()]
    return {"model": model, "original_model_status": model_result["status"],
        "original_primary_status": primary["status"], "original_upgrade_status": upgrade["status"],
        "original_primary_gate": primary["single_model_descriptive_criteria"],
        "original_primary_completed": primary["status"] == "completed", "original_upgrade_completed": upgrade["complete"],
        "supplemental_primary_used": primary_extra is not None, "supplemental_upgrade_used": upgrade_extra is not None,
        "primary_coverage_complete": True, "upgrade_coverage_complete": True,
        "reference_controls": {"primary_executed": primary["native_controls"],
            "primary_passed": primary["native_controls_passed"],
            "upgrade_executed": upgrade["controls"]["count"], "upgrade_passed": upgrade["controls"]["passed"],
            "counted_as_model_success": False},
        "primary": {"planned_cells": 16, "attempted_cells": 16, "successes": sum(row["success"] for row in primary_rows),
                    "arms": arm_summary, "cells": primary_rows},
        "upgrade": {"planned_cells": 4, "attempted_cells": 4, "successes": sum(row["success"] for row in upgrade_rows),
                    "languages": upgrade_summary, "cells": upgrade_rows},
        "all_actual_completion_requests": expected_requests, "all_actual_responses_received": expected_responses,
        "all_request_token_costs_including_probes": token_summary(transport_rows), "transports": transport_rows,
        "phase_costs": costs, "raw_report_bindings": [file_identity(path) for path in refs]}


def ns(value):
    return "null（未计量/未知）" if value is None else f"{value / 1e9:.3f}"


def tokens(row):
    return str(row["total_tokens"]) if row["total_tokens"] is not None else f"null；已知下界 {row['known_total_tokens']}"


def label(state):
    return {"correct": "通过", "observable_wrong": "原生结果错误", "response_rejected": "响应拒绝",
            "budget_timeout": "预算超时", "public_validation_failed": "公开验证未通过",
            "expected_overflow_trap": "溢出陷阱（未成功）"}.get(state, state)


def markdown(result):
    models = result["models"]
    lines = ["# Agent 实验最终结果：原记录与故障续行分别保留", "",
        f"本轮实际覆盖 **32 个主实验计划格**与**8 个独立升级计划格**。主实验通过 {result['primary_successes']}/32，升级通过 {result['upgrade_successes']}/8。两模型的原科学门槛均未通过，不能据此宣称 HIA 的开发效率或维护成本全面优于 Rust。", "",
        "完整覆盖包含原登记之后增加的故障续行；它没有把原始未完成状态改写为完成，也没有重试任何已经 attempted 的格。模型真实答案、预算超时、拒绝、错误及所有原始成本全部保留。参考答案仅用于 native controls，不计为 Agent 成功。", "",
        "最终两家系分别完成 32 项主任务 native controls 与 16 项升级 native controls，合计 96 项参考对照通过；这些对照的执行成本包含在各阶段墙钟中，但没有加入 32/8 的模型成功分母。首次加载失败及开发阶段的额外对照另外保留。", "",
        "## 主实验：四个任务 × 四种接口 × 两模型", "",
        "每格一次提交、512 输出 token 上限、180 秒 completion timeout；每个任务沿用 77 个冻结原生测试输入。`full_context` 与 `edit_query` 使用同一语义任务。成功仅表示通过本次有限输入验证。", "",
        "| 模型 | arm | 成功/计划 | 实际 attempts | timeout | 已知输入 | 已知输出 | 总 tokens |",
        "|---|---|---:|---:|---:|---:|---:|---|"]
    for model in models:
        for arm in ARMS:
            row = model["primary"]["arms"][arm]
            lines.append(f"| {model['model']['id']} | {arm} | {row['successes']}/4 | {row['attempts']} | {row['timeouts']} | {row['known_input_tokens']} | {row['known_output_tokens']} | {tokens(row)} |")
    lines += ["", "输出未知时，已知输出仅累加收到并验证的 response 计数。总数保持 `null`；已知下界不能用于声称成本更低。输入 token 则从每次真实 transport 中的 token ID 恢复。", "",
        "### 任务级足迹", "", "| 模型 | 任务 | HIA full | HIA query | Rust full | Rust query |", "|---|---|---|---|---|---|"]
    for model in models:
        for task in result["protocol"]["agent"]["task_ids"]:
            values = {row["arm"]: label(row["state"]) for row in model["primary"]["cells"] if row["task"] == task}
            lines.append("| " + " | ".join([model["model"]["id"], task] + [values[arm] for arm in ARMS]) + " |")
    lines += ["", "## 升级实验：单独的 8 格分母", "",
        "两个任务分别是长度接口扩宽并更新位布局，以及带容量约束的双返回值窗口接口升级；每个候选必须同时替换 provider 与 consumer。每格至多两次提交、每次 1536 输出 token、180 秒 timeout。只允许编译/公开三例反馈；110 或 160 个隐藏输入只在公开验证通过后运行一次。", "",
        "| 模型 | 任务/语言 | 结果 | attempts | 自动第二次提交 | hidden 验证 | 总 tokens |", "|---|---|---|---:|---:|---|---|"]
    for model in models:
        for row in model["upgrade"]["cells"]:
            lines.append(f"| {model['model']['id']} | {row['id']} | {label(row['state'])} | {len(row['attempts'])} | {row['automatic_repair_rounds']} | {'执行' if row['hidden_validation_performed'] else '未进入'} | {tokens(row)} |")
    lines += ["", "响应封装或字段拒绝不能解读成程序已经被证明语义错误；预算超时也不等于语义错误。所有这些格仍是原计划分母中的未成功格。没有人工修改任何模型答案；人工及工具开发时间未计量，不写成零。", "",
        "### 失败原因与验证次数", ""]
    for model in models:
        reasons = collections.Counter()
        for row in model["primary"]["cells"]:
            if row.get("rejection_or_error"):
                reasons[row["rejection_or_error"]["message"]] += 1
        for row in model["upgrade"]["cells"]:
            for attempt in row["attempts"]:
                if attempt.get("rejection_or_error"):
                    reasons[attempt["rejection_or_error"]["message"]] += 1
        lines.append(f"**{model['model']['id']}**：主任务 native 候选验证 {sum(row['native_candidate_evaluations'] for row in model['primary']['arms'].values())} 次；升级 native build {sum(row['native_builds'] for row in model['upgrade']['languages'].values())} 次、公开 native 验证 {sum(row['public_validations'] for row in model['upgrade']['languages'].values())} 次、hidden 验证 {sum(row['hidden_validations'] for row in model['upgrade']['languages'].values())} 次。")
        lines.append("")
        for reason, count in sorted(reasons.items()):
            lines.append(f"- `{reason.replace('`', '')}`：{count} 次。")
        lines.append("")
    lines += ["## 原协议状态与补充覆盖", "", "| 模型 | 原 primary | 原 upgrade | 主任务续行 | 升级续行 | 主格覆盖 | 升级覆盖 | 原 gate |", "|---|---|---|---|---|---:|---:|---|"]
    for model in models:
        lines.append(f"| {model['model']['id']} | {model['original_primary_status']} | {model['original_upgrade_status']} | {'有' if model['supplemental_primary_used'] else '无'} | {'有' if model['supplemental_upgrade_used'] else '无'} | 16/16 | 4/4 | failed |")
    lines += ["", "Qwen 的原升级首格 timeout 后，独立工具只补原顺序中未启动的三格；Granite 的原 primary 第四格 timeout 后，另一个独立工具只补剩余十二格。已开始的格一律跳过，绝不以‘没有完整 response’作为重试理由。两个续行工具均有独立源码/计划/身份绑定、单一输出目录与失败控件；它们明确属于登记之后增加的故障处理。", "",
        "## 实际成本：阶段计时与外层进程计时分别列示", "",
        "下表单位为秒。原 primary 与 upgrade 的阶段计时包含在原两阶段总进程内，不能把父区间与子区间重复相加。续行 run() 区间从入口到末端身份检查，尚未包含最终 JSON 写入；Bash outer real 另含 Python 启动/import 与最终写入。", "",
        "| 模型 | 原 primary 阶段 | 原 upgrade 阶段 | 原两阶段 run | 原进程 outer real | primary 续行 run / outer | upgrade 续行 run / outer |", "|---|---:|---:|---:|---:|---|---|"]
    for model in models:
        c = model["phase_costs"]
        outer = lambda key: ns((c.get(key) or {}).get("real_ns"))
        primary_extra = f"{ns(c['supplemental_primary_run_ns'])} / {outer('supplemental_primary_outer')}" if model["supplemental_primary_used"] else "未执行（不适用）"
        upgrade_extra = f"{ns(c['supplemental_upgrade_run_ns'])} / {outer('supplemental_upgrade_outer')}" if model["supplemental_upgrade_used"] else "未执行（不适用）"
        lines.append(f"| {model['model']['id']} | {ns(c['original_primary_phase_ns'])} | {ns(c['original_upgrade_phase_ns'])} | {ns(c['original_whole_model_run_ns'])} | {outer('original_whole_process_outer')} | {primary_extra} | {upgrade_extra} |")
    lines += ["", f"实际 completion 请求共 **{result['all_actual_completion_requests']}** 次，收到完整 response **{result['all_actual_responses_received']}** 次，包含四次格式 probe。已知输入 **{result['all_request_token_costs']['known_input_tokens']}** tokens，已验证的已知输出 **{result['all_request_token_costs']['known_output_tokens']}** tokens；**{result['all_request_token_costs']['unknown_output_requests']}** 次输出 usage 不完整，所以整体 output/total tokens 保持 `null`。每次请求、失败原因、token ID 与成本源文件 SHA 均可在配套 JSON 中追溯。", "",
        "另有首次运行的两次加载 OOM（发生在任何 completion 之前，不能写成模型 0/20）、零 generation 的 no-repack readiness、两模型下载与存储切换、各次归档/成员核验开销。它们在配套 JSON 的 runtime/dependency/archive 记录中独立保留，没有从本轮工程成本中删去。`LLAMA_ARG_REPACK=0` 的变更发生在任何模型答案前，所有实际 server PID 均保留白名单环境证据。", "",
        "## 结论范围", "",
        "Qwen 的 HIA query 确有通过隐藏输入的真实维护响应，但四题门槛及 token 非劣条件仍未通过；补充覆盖不能把失败门槛改成通过。本轮只有四个既有两 helper 任务、两个有限双文件接口升级和两个固定量化模型，运行在共享 CPU 环境中。它不是一般工程项目、所有模型或人工维护成本的证明。", "",
        "原始证据保持字节不变；超过发布接口限制的 archive 只能以可重组、SHA 可核对的无损分片发布，不能重打包后冒充原档。配套 `AGENT_FINAL_RESULTS.json` 保留全部原始报告、transport、源码和归档 manifest 的精确身份。", ""]
    return "\n".join(lines)


def build(suite, output):
    root, output = Path(suite).resolve(strict=True), Path(output)
    suite_plan = read(root / "SUITE_PLAN.json")
    models = [summarize_model(root, model) for model in suite_plan["models"]]
    all_transports = [item for model in models for item in model["transports"]]
    dependencies = {}
    for name in ("RUNTIME_AMENDMENT.json", "RUNTIME_AMENDMENT_APPLIED.json", "MODEL_STORAGE_SWAP.json", "norepack-readiness.json", "dependency-downloads-initial.json", "ORIGINAL_SUITE_RESULT.json"):
        path = HERE / name
        if path.is_file():
            dependencies[name] = {"artifact": file_identity(path), "record": read(path)}
    archives = []
    for path in sorted(HERE.glob("*.tar.manifest.json")):
        if any(path.name.startswith(prefix) for prefix in ("agent-startup-oom", "qwen-final-02", "granite-final-02")):
            manifest = read(path)
            archives.append({"manifest": file_identity(path), **{key: manifest[key] for key in ("archive", "archive_sha256", "archive_bytes", "member_count", "all_member_hashes_verified", "pack_and_verify_ns", "reclaimed_bytes")}})
    result = {"schema": "hepta.hia.agent-final-results.next-20261028.v1", "aggregation_source": file_identity(__file__),
        "suite_plan": file_identity(root / "SUITE_PLAN.json"), "protocol": suite_plan["protocol"],
        "registration": file_identity(HERE / "REGISTRATION.json"), "models": models,
        "primary_planned_cells": 32, "primary_attempted_cells": 32, "primary_successes": sum(model["primary"]["successes"] for model in models),
        "upgrade_planned_cells": 8, "upgrade_attempted_cells": 8, "upgrade_successes": sum(model["upgrade"]["successes"] for model in models),
        "all_actual_completion_requests": sum(model["all_actual_completion_requests"] for model in models),
        "all_actual_responses_received": sum(model["all_actual_responses_received"] for model in models),
        "all_request_token_costs": token_summary(all_transports),
        "original_registered_complete": all(model["original_model_status"] == "completed" for model in models),
        "original_scientific_gate_passed": bool(all(model["original_model_status"] == "completed"
            and model["original_primary_gate"]["primary"] for model in models)),
        "supplemental_task_coverage_complete": True,
        "supplemental_after_registration": True, "manual_time_ns": None, "total_economic_cost": None,
        "claims": {"general_productivity_superiority": False, "human_labor_measured": False,
                   "reference_controls_counted_as_model_success": False, "unknown_usage_counted_as_zero": False},
        "runtime_dependency_and_failure_records": dependencies, "archives": archives}
    output.mkdir(parents=True, exist_ok=True)
    for name, data in (("AGENT_FINAL_RESULTS.json", canonical(result) + b"\n"),
                       ("AGENT_FINAL_RESULTS.md", markdown(result).encode())):
        with (output / name).open("xb") as stream:
            stream.write(data)
    print(json.dumps({key: result[key] for key in ("primary_successes", "upgrade_successes", "all_actual_completion_requests", "all_actual_responses_received", "original_registered_complete", "supplemental_task_coverage_complete")}), flush=True)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", required=True); parser.add_argument("--output", required=True)
    build(**vars(parser.parse_args()))
