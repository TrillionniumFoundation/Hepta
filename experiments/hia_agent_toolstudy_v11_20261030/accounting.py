"""Retain measured costs even when final identity or shutdown checks fail.

This module grants no source, model or main-stage authority. Failed cleanup or
identity checks remain failed; independent finalization steps cannot erase
earlier request counters, raw service records or token usage.
"""
from __future__ import annotations

import copy
import subprocess
import time


def measure(record, key, operation, default=None):
    started = time.monotonic_ns()
    ok = False
    try:
        value = operation()
        ok = True
    except Exception as exc:
        record.setdefault("finalization_errors", []).append({
            "operation": key, "type": type(exc).__name__, "message": str(exc),
        })
        value = default
    record[key] = value
    record.setdefault("finalization_steps", []).append({
        "operation": key, "wall_ns": time.monotonic_ns()-started, "completed": ok,
    })
    return value


def _counter(engine, name):
    value = getattr(engine, name)
    if type(value) is not int or value < 0:
        raise ValueError("E_TOOLSTUDY_COUNTER: " + name)
    return value


def _stop_owned(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)
    return process.poll() is not None


def finish_engine(engine, record, save, service_path):
    """Caller registers ``record`` before any of these fallible actions."""
    record["folder"] = str(engine.output)
    # Snapshot costs first. Missing counters remain unknown, never zero.
    for key, attribute in (("requests", "generation_count"), ("responses", "response_count"),
                           ("preparations", "preparation_count")):
        measure(record, key, lambda attribute=attribute: _counter(engine, attribute))
    measure(record, "service_calls", lambda: copy.deepcopy(engine.service_calls))
    measure(record, "pid", lambda: engine.process.pid)
    measure(record, "identity", lambda: engine.verify_final_identity())
    before = time.monotonic_ns()
    measure(record, "close_returned", lambda: (engine.close(), True)[1], False)
    measure(record, "exited", lambda: engine.process.poll() is not None, False)
    if record["exited"] is not True:
        # This is only the already-owned Popen child. A cleanup failure never
        # authorizes a PID lookup or killing another process.
        measure(record, "emergency_owned_shutdown", lambda: _stop_owned(engine.process), False)
        measure(record, "exited", lambda: engine.process.poll() is not None, False)
    record["shutdown_ns"] = time.monotonic_ns()-before
    if record["service_calls"] is not None:
        measure(record, "service_calls_saved", lambda: (save(service_path, record["service_calls"]), True)[1], False)
    identity = record.get("identity")
    record["failure_reasons"] = []
    if type(identity) is not dict or identity.get("model_unchanged") is not True:
        record["failure_reasons"].append("model_identity_unconfirmed")
    if type(identity) is not dict or identity.get("runtime_unchanged") is not True:
        record["failure_reasons"].append("runtime_identity_unconfirmed")
    if record["exited"] is not True:
        record["failure_reasons"].append("owned_process_exit_unconfirmed")
    if record.get("finalization_errors"):
        record["failure_reasons"].append("finalization_operation_failed")
    record["complete"] = bool(not record.get("finalization_errors") and record["exited"] is True
                              and record.get("service_calls_saved") is True and type(identity) is dict
                              and identity.get("model_unchanged") is True and identity.get("runtime_unchanged") is True)
    return record


def final_identities(record, *, source_check, tools_check, model_check):
    for key, operation in (("source_unchanged", source_check), ("tools_unchanged", tools_check),
                           ("model_unchanged", model_check)):
        measure(record, key, operation, False)


def counter_sum(engines, key):
    values = [item.get(key) for item in engines]
    return sum(values) if all(type(value) is int and value >= 0 for value in values) else None


def _complete_usage(value):
    return (type(value) is dict
            and all(type(value.get(key)) is int and value[key] > 0
                    for key in ("input_tokens", "output_tokens", "total_tokens"))
            and value["total_tokens"] == value["input_tokens"] + value["output_tokens"])


def usage_summary(attempts, requests):
    known_inputs = known_outputs = partial_outputs = completed = recovered = 0
    declared_requests = sum(attempt.get("actual_generation_requested") is True for attempt in attempts)
    consistent = type(requests) is int and requests >= 0 and declared_requests == requests
    for attempt in attempts:
        usage = attempt.get("usage")
        receipt = attempt.get("partial_usage")
        if not _complete_usage(usage):
            # A validated terminal SSE receipt may survive an answer-file
            # persistence exception. Retain its exact cost, but do not turn
            # this failed attempt into a successful submission or qualification.
            if type(receipt) is dict and receipt.get("complete") is True and _complete_usage(receipt):
                usage = receipt
                recovered += 1
            else:
                usage = None
        if usage is not None:
            completed += 1
            known_inputs += usage["input_tokens"]
            known_outputs += usage["output_tokens"]
            consistent &= attempt.get("actual_generation_requested") is True
            continue  # Never count the same usage again through partial_usage.
        if type(receipt) is dict:
            value = receipt.get("input_tokens")
            if type(value) is int and value >= 0:
                known_inputs += value
            value = receipt.get("observed_output_token_lower_bound")
            if type(value) is int and value >= 0:
                partial_outputs += value
    unknown = requests-completed if type(requests) is int and requests >= completed else None
    complete = bool(consistent and unknown == 0)
    return {
        "requests": requests, "observed_requested_attempts": declared_requests,
        "complete_usage_requests": completed, "recovered_terminal_usage_receipts": recovered,
        "unknown_usage_requests": unknown, "usage_accounting_consistent": consistent,
        "complete_usage": complete, "known_input_tokens": known_inputs,
        "known_output_tokens": known_outputs, "partial_output_token_lower_bound": partial_outputs,
        "total_tokens": known_inputs+known_outputs if complete else None,
    }
