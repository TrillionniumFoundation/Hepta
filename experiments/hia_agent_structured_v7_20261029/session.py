"""A real validated edit transaction for the finite multi-file study profile.

Only the complete accepted candidate advances the in-memory source revision.
Candidate diagnostics and public observations are retained; hidden inputs are
never part of a query or returned to a model. No candidate is published to disk
as a working project or installed into the repository.
"""
from __future__ import annotations

import copy
from pathlib import Path
import threading
import time

from experiments.hia_agent_factorial_v4_20261028 import evaluator, fixtures
from experiments.hia_agent_factorial_v6_20261028.prompts import public_feedback
from experiments.hia_agent_structured_v7_20261029 import editing
from hepta.hia_program import verify_program
from hepta.hia_program_tools import decode_json
from tools.provider_adapter.llama_cpp_engine import canonical

QUERY_SCHEMA = "hepta.agent.structured-task-query.v1"
RESPONSE_SCHEMA = "hepta.agent.structured-task-response.v1"


class ValidatedTaskSession:
    def __init__(self, task, language, *, clang, rustc, interface_policy="preserve"):
        if language not in {"hia", "rust"} or interface_policy not in {"preserve", "migrate"}:
            editing.reject("registered language and interface policy required")
        self._lock = threading.RLock()
        self._task = copy.deepcopy(task)
        self.language = language
        self.clang, self.rustc = clang, rustc
        self.interface_policy = interface_policy
        self._files = {**copy.deepcopy(task["unchanged_" + language]), **copy.deepcopy(task["original_" + language])}
        self._symbols = ({"api.rs": task["provider"], "client.rs": "entrypoint"} if language == "rust"
                         else {"api.hia.json": task["provider"], "client.hia.json": "entrypoint"})
        self._attempts = 0

    @property
    def files(self):
        with self._lock:
            return copy.deepcopy(self._files)

    @property
    def revision(self):
        with self._lock:
            return editing.digest(self._files)

    def _core(self):
        return verify_program({"schema": "hepta.hia.program.v6", "module": self._task["id"],
                               "exports": ["entrypoint"],
                               "functions": [self._files[name] for name in ("api.hia.json", "client.hia.json", "audit.hia.json", "utility.hia.json")]})

    def query(self):
        with self._lock:
            return self._query_locked()

    def _query_locked(self):
        inner = (editing.prepare_rust(self._files, self._symbols, interface_policy=self.interface_policy) if self.language == "rust"
                 else editing.prepare_hia(self._core(), list(self._symbols.values()), interface_policy=self.interface_policy))
        value = {"schema": QUERY_SCHEMA, "language": self.language, "profile": editing.PROFILE,
                 "interface_policy": self.interface_policy,
                 "source_revision": self.revision, "edit_query": inner,
                 "budget": {"max_edits": editing.MAX_EDITS, "max_response_bytes": editing.MAX_RESPONSE_BYTES},
                 "admission": "same finite source profile, real compiler, bounded native public cases and ownership/resource observations",
                 "source_publication": "unpublished; whole validated transaction advances only the in-memory project revision"}
        value["query_sha256"] = editing.digest(value)
        return copy.deepcopy(value)

    @staticmethod
    def response(query, edits):
        return {"schema": RESPONSE_SCHEMA, "source_revision": query["source_revision"],
                "query_sha256": query["query_sha256"], "edits": copy.deepcopy(edits)}

    def apply(self, response, output):
        # Serialize the entire project transaction, including validation and
        # receipt retention. A second request with the same old revision must
        # observe the first commit and fail its stale check before compilation.
        with self._lock:
            return self._apply_locked(response, output)

    def _apply_locked(self, response, output):
        before = self.revision
        started = time.monotonic_ns()
        folder = Path(output); folder.mkdir(parents=True, exist_ok=False)
        self._attempts += 1
        record = {"schema": "hepta.agent.structured-task-transaction.v1", "language": self.language,
                  "before_revision": before, "after_revision": before, "attempt": self._attempts,
                  "accepted": False, "source_published": False, "hidden_evaluated": False,
                  "status": "response_rejected", "model_answer": None}
        admitted_files = None
        try:
            query = self.query()
            evaluator.save(folder / "QUERY.json", query)
            if type(response) in (str, bytes):
                raw = response.encode() if type(response) is str else response
                if len(raw) > editing.MAX_RESPONSE_BYTES:
                    editing.reject("response byte budget")
                value = decode_json(raw)
            else:
                value = decode_json(editing.wire(response, editing.MAX_RESPONSE_BYTES))
            evaluator.save(folder / "RESPONSE.json", value)
            if type(value) is not dict or set(value) != {"schema", "source_revision", "query_sha256", "edits"}:
                editing.reject("exact task transaction envelope required")
            if (value["schema"] != RESPONSE_SCHEMA or value["source_revision"] != before
                    or value["query_sha256"] != query["query_sha256"]):
                editing.reject("stale project revision or complete query digest")
            inner_response = editing.response_for(query["edit_query"], value["edits"])
            if self.language == "rust":
                proposed, structural = editing.propose_rust(self._files, query["edit_query"], inner_response, editable_symbols=self._symbols, interface_policy=self.interface_policy)
            else:
                checked, structural = editing.apply_hia(self._core(), query["edit_query"], inner_response,
                                                       editable_functions=list(self._symbols.values()), interface_policy=self.interface_policy)
                by_name = {function["name"]: function for function in checked.as_dict()["functions"]}
                proposed = copy.deepcopy(self._files)
                for file, symbol in self._symbols.items():
                    proposed[file] = by_name[symbol]
            if any(proposed[name] != self._files[name] for name in self._files if name not in self._symbols):
                editing.reject("unchanged source file drift")
            record["structural_edit"] = structural
            candidate = {name: proposed[name] for name in fixtures.EDITABLE[self.language]}
            built = evaluator.build(self._task, self.language, canonical({"files": candidate}).decode(),
                                    folder / "candidate", self.clang, self.rustc, primitive_parameter_into=True)
            observed = (evaluator.execute(built, self._task, self._task["public_cases"], self._task["public_expected"])
                        if built["status"] == "compiled" and built["native_built"] else None)
            record.update(build=built, public=observed, feedback=public_feedback(self._task, built, observed),
                          status=observed["status"] if observed else built["status"])
            if built["status"] == "infrastructure_failure" or observed is not None and not observed["artifact_unchanged"]:
                record["status"] = "infrastructure_failure"
            elif observed and observed["status"] == "correct":
                candidate_revision = editing.digest(proposed)
                record.update(accepted=True, after_revision=candidate_revision)
                admitted_files = proposed
        except Exception as exc:
            admitted_files = None
            record.update(accepted=False, after_revision=before,
                          status="response_rejected" if isinstance(exc, ValueError) else "infrastructure_failure")
            record["error"] = {"type": type(exc).__name__, "message": str(exc)}
        record["wall_ns"] = time.monotonic_ns() - started
        record["failed_transaction_left_source_unchanged"] = self.revision == before
        evaluator.save(folder / "TRANSACTION.json", record)
        if record["accepted"] is True and admitted_files is not None:
            self._files = admitted_files
        return record
