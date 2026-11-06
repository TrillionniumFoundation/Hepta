"""Actual cache actions for the feedback study, using the existing native worker.

This is a controlled matrix workload, not an HIA compiler qualification. The
controller receives observations only. Seeds and the not-yet-revealed request
stream belong to the experiment driver and never enter its planning interface.
"""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import time

from hepta.hia_ndu_dynamic import JsonProcess, DynamicError


def digest(value):
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                             allow_nan=False).encode()).hexdigest()


class NativeCache:
    """A two-artifact, one-slot worker; every decision is checked against state."""

    def __init__(self, binary, manifest, log, *, n, seed):
        self.started_ns = time.monotonic_ns()
        self.process = JsonProcess(binary, manifest, role="--workload-stream", log=log)
        self.state = None
        self.generation = 0
        self.closed = False
        self.close_receipt = None
        self.rows = []
        self.n = n
        try:
            self._ask({"command": "init", "count": 2, "n": n, "seed": seed,
                       "quota_bytes": n * n * 4})
            self.startup_ns = time.monotonic_ns() - self.started_ns
        except BaseException:
            self.process.close()
            raise

    def _ask(self, command):
        response, receipt = self.process.ask(command)
        if response.get("schema") != "hepta.hia.ndu.dynamic-cache.workload.response.v1":
            raise DynamicError("feedback workload rejected command: " + str(response.get("reason")))
        state = response["state"]
        if (type(state) is not dict or state.get("n") != self.n
                or any(type(state.get(key)) is not int or state[key] < 0 for key in
                       ("quota_bytes", "resident_bytes", "baseline_bytes", "executions", "allocations", "retirements"))
                or type(state.get("ready")) is not list
                or any(type(v) is not int or v not in (0, 1) for v in state["ready"])
                or type(state.get("epochs")) is not list or len(state["epochs"]) != 2
                or any(type(v) is not int or v < 1 for v in state["epochs"])
                or state["quota_bytes"] != self.n * self.n * 4
                or state["resident_bytes"] > state["quota_bytes"]
                or len(state["ready"]) > 1
                or bool(state["ready"]) != bool(state["resident_bytes"])):
            raise DynamicError("feedback workload state violates one-slot quota")
        body, kind = response.get("result"), command["command"]
        if type(body) is not dict:
            raise DynamicError("feedback workload result shape")
        if kind == "prepare" and (body.get("prepared") != command["id"]
                                  or command["id"] not in state["ready"]
                                  or state["epochs"][command["id"]] != command["epoch"]):
            raise DynamicError("feedback workload prepare receipt mismatch")
        if kind == "retire" and (body.get("retired") != command["id"]
                                 or command["id"] in state["ready"]):
            raise DynamicError("feedback workload retire receipt mismatch")
        self.state = state
        return response, receipt

    @property
    def resident(self):
        return self.state["ready"][0] if self.state["ready"] else -1

    @property
    def state_digest(self):
        return digest({"generation": self.generation, "state": self.state})

    def execute(self, desired, target, *, repeats, vector_seed, expected_state_digest):
        """Apply the selected cache action and execute the current request.

        The native worker enforces allocation quota and epochs independently.
        Rejected stale advice causes no workload command. Measured latency,
        including dispatch/validation, is returned only after the action.
        """
        started = time.monotonic_ns()
        if self.closed or expected_state_digest != self.state_digest:
            raise DynamicError("feedback workload stale or closed state")
        if type(desired) is not int or desired not in (-1, 0, 1):
            raise DynamicError("feedback workload invalid resident action")
        if type(target) is not int or target not in (0, 1):
            raise DynamicError("feedback workload invalid target")
        if type(repeats) is not int or not 1 <= repeats <= 64:
            raise DynamicError("feedback workload invalid repeat count")
        if type(vector_seed) is not int or not 0 <= vector_seed <= 0xffffffff:
            raise DynamicError("feedback workload invalid vector seed")
        before, before_digest = dict(self.state), self.state_digest
        commands, service_ns, kernel_ns, validation_ns = [], 0, 0, 0
        dispatch = "packed" if desired == target else "direct"
        error, result, pending = None, None, None
        def issue(command):
            nonlocal pending, service_ns
            pending = command
            response, receipt = self._ask(command)
            commands.append({"command": command, "result": response, "wire_ns": receipt["wire_roundtrip_ns"]})
            service_ns += response["service_ns"]
            pending = None
            return response
        try:
            old = self.resident
            if old != desired and old >= 0:
                issue({"command": "retire", "id": old})
            if desired >= 0 and desired != old:
                issue({"command": "prepare", "id": desired, "epoch": self.state["epochs"][desired]})
            result = issue({"command": "run", "id": target, "vector_seed": vector_seed,
                            "repeats": repeats, "dispatch": dispatch})
            body = result["result"]
            if (body["all_outputs_checked"] != self.n or self.resident != desired
                    or body["matrix"] != target or body["epoch"] != before["epochs"][target]
                    or body["dispatch"] != dispatch or body["repeats"] != repeats
                    or self.state["executions"] != before["executions"] + 1):
                raise DynamicError("feedback workload selected/executed action mismatch")
            kernel_ns += body["kernel_ns"]
            validation_ns += body["oracle_ns"]
        except BaseException as exc:
            error = exc
            raise
        finally:
            # Even a partial failed load/retire/run invalidates old advice and
            # keeps its actual elapsed work. Raw failed frames are in the log.
            self.generation += 1
            returned_body = result.get("result") if type(result) is dict else None
            row = {"generation": self.generation, "before": before, "after": dict(self.state),
                   "before_digest": before_digest, "after_digest": self.state_digest,
                   "selected_resident": desired, "executed_resident": self.resident,
                   "target": target, "dispatch": dispatch, "commands": commands,
                   "pending_command": pending, "status": "success" if error is None else "failed",
                   "error": None if error is None else f"{type(error).__name__}: {error}",
                   "kernel_ns": kernel_ns, "output_validation_ns": validation_ns,
                   "native_service_ns": service_ns, "workload_wall_ns": time.monotonic_ns() - started,
                   "checksum": returned_body.get("checksum") if type(returned_body) is dict else None,
                   "output_elements_checked": self.n if error is None else 0}
            self.rows.append(row)
        return row

    def close(self):
        if self.closed:
            if self.close_receipt is None or self.close_receipt.get("error"):
                raise DynamicError("feedback workload previous close failed")
            return self.close_receipt
        started = time.monotonic_ns()
        self.closed = True
        error = None
        try:
            result, _ = self._ask({"command": "close"})
            state = result["state"]
            if (state["resident_bytes"] != 0 or state["baseline_bytes"] != 0
                    or state["allocations"] != state["retirements"]):
                raise DynamicError("feedback workload cache lifecycle imbalance")
        except BaseException as exc:
            error = exc
        finally:
            try:
                self.process.close()
            except BaseException as exc:
                error = error or exc
        returncode = getattr(self.process, "returncode", None)
        if error is None and returncode != 0:
            error = DynamicError("feedback workload worker exited unsuccessfully")
        self.close_receipt = {"close_ns": time.monotonic_ns() - started,
                              "returncode": returncode,
                              "final_state": self.state,
                              "error": None if error is None else str(error)}
        if error is not None:
            raise error
        return self.close_receipt


def calibrate(binary, manifest, output, *, dimensions, seeds, samples=5, repeats=4):
    """Only training inputs are measured; retain every warmup and observation."""
    import statistics
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    began = time.monotonic_ns()
    rows, models = [], {}
    for n in dimensions:
        buckets = {key: [] for key in ("direct", "packed", "prepare", "retire")}
        for seed in seeds:
            worker = NativeCache(binary, manifest, output / f"train-n{n}-s{seed}.jsonl", n=n, seed=seed)
            try:
                for sample in range(samples):
                    # Alternate order; every load and retirement is paid and retained.
                    for desired in ((0, -1) if sample % 2 else (-1, 0)):
                        row = worker.execute(desired, 0, repeats=repeats,
                                             vector_seed=(seed + sample * 17) & 0xffffffff,
                                             expected_state_digest=worker.state_digest)
                        rows.append({"n": n, "seed": seed, "sample": sample, "row": row})
                        for part in row["commands"]:
                            command = part["command"]["command"]
                            key = part["command"]["dispatch"] if command == "run" else command
                            buckets[key].append(part["wire_ns"])
            finally:
                worker.close()
        # Costs are forecasts of command roundtrip latency, never future measurements.
        models[str(n)] = {key + "_ns": round(statistics.median(values))
                          for key, values in buckets.items()}
        models[str(n)]["samples"] = {key: values for key, values in buckets.items()}
    return {"models": models, "rows": rows, "wall_ns": time.monotonic_ns() - began,
            "training_dimensions": dimensions, "training_seeds": seeds,
            "repeats": repeats, "future_measurement_access": False,
            "forecast_scope": "wire roundtrip includes native work and parsing; excludes raw-log flush and outer validation; final cost uses outer wall",
            "cost_unit": "measured host nanoseconds; training forecast only"}
