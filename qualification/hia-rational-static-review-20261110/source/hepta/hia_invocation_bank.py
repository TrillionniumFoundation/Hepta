"""Prepare the existing invocation gate's optimistic bound once per cost bank.

Only supplied finite-model arithmetic is reused. This owner cannot import a
proof receipt, cache a native response or authorize an artifact. Each lookup
uses its current budget, generation and invocation cost. Changing bank facts
requires a new epoch/owner; the old full-model gate remains the slow path.
"""
from __future__ import annotations

from hashlib import sha256
from pathlib import Path
from threading import RLock
import time
from types import MappingProxyType
from weakref import WeakKeyDictionary

from . import hia_ndu_stateful as stateful
from .hia_program_tools import bounded_json_wire, decode_json

SCHEMA = "hepta.hia.ndu.invocation-bound-bank.v1"
MAX_SIZES = 16
MAX_BANK_BYTES = 500_000
_CONSTRUCTION = object()
_BANKS = WeakKeyDictionary()
_LOCK = RLock()


def _require(ok, message):
    stateful._require(ok, "invocation bank: " + message)


def _facts(model):
    result = {key: model[key] for key in
              ("schema", "objective_digest", "memory_budget_bytes", "completion_value_ns", "cost_basis")}
    result["baseline"] = {key: value for key, value in model["baseline"].items() if key != "latency_ns"}
    result["variants"] = [{key: value for key, value in row.items()
                           if key not in {"latency_ns", "holding_ns"}} for row in model["variants"]]
    return result


def prepare_invocation_bank(models, *, epoch):
    """Freeze 1..16 size-indexed templates using the existing bounded intake.

    A lookup of horizon h uses the first h predicted batches in its template.
    The native current-size-persistence profile has constant cost arrays.
    Templates share the same source/proof/support/status/quota facts; per-size
    execution and holding forecasts may differ. They remain external model
    assertions, not machine-code verification or physical timing guarantees.
    """
    started = time.monotonic_ns()
    stateful._int(epoch, "bank epoch", (1 << 32) - 1)
    _require(epoch > 0, "epoch must be nonzero")
    _require(type(models) is dict and 1 <= len(models) <= MAX_SIZES,
             "one to sixteen ordinary size templates required")
    _require(all(type(size) is int and 0 <= size <= 65536 for size in models), "invalid size key")
    # Snapshot the whole caller-owned collection before considering any model.
    try:
        encoded = bounded_json_wire({"models": [{"size": size, "model": model}
                                    for size, model in sorted(models.items())]}, MAX_BANK_BYTES)
        snapshot = decode_json(encoded)["models"]
    except (ValueError, TypeError, RuntimeError, RecursionError, OverflowError, UnicodeError) as error:
        raise stateful.StatefulPlanningError("E_HIA_NDU_STATEFUL: invocation bank snapshot rejected") from error
    checked = [(row["size"], stateful.validate_model(row["model"])) for row in snapshot]
    common = _facts(checked[0][1])
    _require(all(_facts(model) == common for _, model in checked), "templates use different source/cost-bank facts")
    variants = checked[0][1]["variants"]
    names = tuple(row["id"] for row in variants)
    bounds, rows = {}, 0
    for size, model in checked:
        data = {}
        horizon = len(model["baseline"]["latency_ns"])
        reversible = model["schema"] == stateful.SCHEMA_V3
        for mask in range(1 << len(variants)):
            ready = tuple(row for index, row in enumerate(model["variants"]) if mask & (1 << index))
            resident = sum(row["resident_bytes"] for row in ready)
            if resident > model["memory_budget_bytes"] or any(row["status"] != "verified" for row in ready):
                continue
            available = [row for index, row in enumerate(model["variants"])
                         if row["status"] == "verified" and
                         (row["resident_bytes"] if reversible else
                          resident + (0 if mask & (1 << index) else row["resident_bytes"]))
                         <= model["memory_budget_bytes"]]
            incumbent, lower, base, holding_all = 0, 0, 0, 0
            for batch in range(horizon):
                baseline = model["baseline"]["latency_ns"][batch]
                holding = sum(row["holding_ns"][batch] for row in ready)
                incumbent += min([baseline, *(row["latency_ns"][batch] for row in ready)]) + holding
                lower += min([baseline, *(row["latency_ns"][batch] for row in available)]) + (0 if reversible else holding)
                base += baseline
                holding_all += sum(row["holding_ns"][batch] for row in model["variants"])
                h = batch + 1
                transition = (h * sum(row["preparation_ns"] + row["eviction_ns"] for row in model["variants"])
                              if reversible else sum(row["preparation_ns"] for row in model["variants"]))
                data[(mask, h)] = (incumbent, lower, transition + base + holding_all,
                                   tuple(row["id"] for row in ready), resident)
                rows += 1
        bounds[size] = MappingProxyType(data)
    source_names = (Path(__file__).name, Path(stateful.__file__).name,
                    "hia_program_tools.py", "hia_json_preflight.py",
                    "hia_bounded_memory.py", "hia_bounded_wire.py")
    source_hashes = tuple((name, sha256(Path(__file__).with_name(name).read_bytes()).hexdigest())
                          for name in source_names)
    implementation = stateful.digest(dict(source_hashes))
    owner = InvocationBoundBank(_CONSTRUCTION)
    with _LOCK:
        _BANKS[owner] = {"epoch": epoch, "names": names, "bounds": MappingProxyType(bounds),
            "model_schema": common["schema"], "cost_basis": common["cost_basis"],
            "binding_sha256": stateful.digest({"schema": SCHEMA, "epoch": epoch,
                "models": [{"size": size, "model": model} for size, model in checked],
                "implementation_sha256": implementation}),
            "implementation_sha256": implementation, "implementation_sources": source_hashes,
            "retained_input_bytes": len(encoded),
            "bound_rows": rows, "lookups": 0, "rejections": 0,
            "preparation_ns": time.monotonic_ns() - started}
    return owner


class InvocationBoundBank:
    """Private local arithmetic evidence; no deserialization or execution API."""
    __slots__ = ("__weakref__",)

    def __new__(cls, token=None):
        _require(token is _CONSTRUCTION, "construct with prepare_invocation_bank")
        return super().__new__(cls)

    def _record(self):
        record = _BANKS.get(self)
        _require(record is not None, "owner is closed or was not prepared here")
        return record

    def mask_for(self, ready):
        with _LOCK:
            record = self._record()
            try:
                _require(type(ready) in (tuple, frozenset) and len(ready) <= len(record["names"]),
                         "ready identities require a bounded immutable tuple or frozenset")
                _require(all(type(name) is str and name in record["names"] for name in ready)
                         and len(set(ready)) == len(ready), "invalid ready identity")
                return sum(1 << record["names"].index(name) for name in ready)
            except (ValueError, TypeError):
                record["rejections"] += 1
                raise

    def lookup(self, *, size, horizon, ready_mask, budget_ns, invocation_cost_ns,
               epoch, generation, sunk_cost_ns=0, future_decision_cost_ns=0):
        """Recompute the original sufficient bound on current scalar inputs.

        No JSON normalization, model hashing, DP search or native call occurs
        here. Inapplicable queries refuse; the caller may explicitly pay for a
        new bank or the original full-model path. A skip is advisory only.
        """
        with _LOCK:
            record = self._record()
            try:
                for value, label in ((budget_ns, "budget"), (invocation_cost_ns, "invocation cost"),
                                     (sunk_cost_ns, "sunk cost"), (future_decision_cost_ns, "future decision cost")):
                    stateful._int(value, label)
                for value, label in ((epoch, "bank epoch"), (generation, "generation")):
                    stateful._int(value, label, (1 << 32) - 1)
                    _require(value > 0, label + " must be nonzero")
                _require(epoch == record["epoch"], "bank epoch changed")
                _require(type(size) is int and size in record["bounds"], "unknown workload size")
                _require(type(ready_mask) is int and type(horizon) is int,
                         "mask and horizon must be exact integers")
                row = record["bounds"][size].get((ready_mask, horizon))
                _require(row is not None, "unavailable resident mask or horizon")
                incumbent, lower, envelope, ready, resident = row
                _require(record["model_schema"] != stateful.SCHEMA or future_decision_cost_ns == 0,
                         "v1 has no future-decision field")
                _require(envelope + (horizon - 1) * future_decision_cost_ns <= stateful._MAX_NS,
                         "complete cost envelope exceeds the finite profile")
                upper = incumbent - lower
                affordable = invocation_cost_ns + lower <= budget_ns
                invoke = affordable and upper > invocation_cost_ns
                reason = ("optimistic_savings_exceed_invocation_estimate" if invoke else
                          "invocation_and_optimistic_delivery_exceed_budget" if not affordable else
                          "optimistic_savings_cannot_repay_invocation")
                record["lookups"] += 1
                return {"schema": "hepta.hia.ndu.invocation-bound.lookup.v1",
                    "binding_sha256": record["binding_sha256"], "epoch": epoch, "generation": generation,
                    "size": size, "horizon": horizon, "ready_mask": ready_mask,
                    "budget_ns": budget_ns, "sunk_cost_ns": sunk_cost_ns, "invocation_cost_ns": invocation_cost_ns,
                    "future_decision_cost_ns": future_decision_cost_ns, "invoke": invoke, "reason": reason,
                    "incumbent_delivery_ns": incumbent, "optimistic_delivery_lower_bound_ns": lower,
                    "gross_savings_upper_bound_ns": upper, "incumbent_ready": list(ready),
                    "resident_bytes": resident, "cost_basis": record["cost_basis"],
                    "scope": "same supplied deterministic-model optimistic bound; no physical timing guarantee",
                    "authority": "DENY_ALL", "safety_certificate": False, "execution_authorized": False}
            except (ValueError, TypeError, KeyError):
                record["rejections"] += 1
                raise

    def snapshot(self):
        with _LOCK:
            record = self._record()
            return {"schema": SCHEMA, "closed": False, "authority": "DENY_ALL",
                    "safety_certificate": False, "execution_authorized": False,
                    **{key: value for key, value in record.items() if key not in {"bounds", "names"}}}

    def close(self):
        with _LOCK:
            result = self.snapshot()
            del _BANKS[self]
            return {**result, "closed": True}

    def __copy__(self):
        raise stateful.StatefulPlanningError("invocation bank has one lifetime owner")

    def __deepcopy__(self, memo):
        return self.__copy__()
