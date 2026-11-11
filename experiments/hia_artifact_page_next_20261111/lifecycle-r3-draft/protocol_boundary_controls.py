"""Low-level page continuation controls using real page and wire images.

This is a development probe of private step/observe lifecycle semantics. It
does not select a product hook, qualify source, or establish disk durability.
Each SQLite database is independent and in memory; execute calls are counted
as well as rows, because INSERT OR IGNORE can conceal a repeated effect.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import struct
import sys
import time
import traceback
from types import SimpleNamespace
from unittest.mock import patch


def file_record(path):
    path = Path(path).resolve(strict=True)
    raw = path.read_bytes()
    return {"path": str(path), "bytes": len(raw), "sha256": sha256(raw).hexdigest()}


def trace_frames(value):
    rows = []
    at = value.__traceback__
    while at is not None:
        rows.append({"function": at.tb_frame.f_code.co_name,
                     "file": at.tb_frame.f_code.co_filename, "line": at.tb_lineno})
        at = at.tb_next
    return rows


class ForeignStop(BaseException):
    pass


def foreign_origin():
    raise ForeignStop("page foreign effect sentinel")


class CountingDatabase:
    def __init__(self):
        self.connection = sqlite3.connect(":memory:")
        self.connection.row_factory = sqlite3.Row
        self.connection.execute(
            "CREATE TABLE cursors(id TEXT PRIMARY KEY,artifact_id TEXT,sha256 TEXT,offset INTEGER)")
        self.inserts = 0
        self.failure = None
        self.handled_at_insert = []

    def execute(self, sql, args=()):
        if sql.startswith("INSERT OR IGNORE INTO cursors"):
            self.inserts += 1
            self.handled_at_insert.append(sys.exception())
            if self.failure is not None:
                raise self.failure
        return self.connection.execute(sql, args)

    def rows(self):
        return [tuple(row) for row in self.connection.execute("SELECT * FROM cursors ORDER BY id")]


def main():
    cli = argparse.ArgumentParser()
    cli.add_argument("--source-root", required=True)
    cli.add_argument("--wire-manifest", required=True)
    cli.add_argument("--adapter")
    cli.add_argument("--draft-root")
    cli.add_argument("--output", required=True)
    cli.add_argument("--expect", choices=("observe", "fixed"), default="observe")
    config = cli.parse_args()
    root = Path(config.source_root).resolve(strict=True)
    folder = Path(config.draft_root).resolve(strict=True) if config.draft_root else Path(__file__).resolve().parent
    destination = Path(config.output)
    if destination.exists():
        raise FileExistsError(destination)
    sys.path.insert(0, str(root))
    from hepta import hia_agent_service as service_module
    from hepta.hia_json_preflight_native import NativeHiaJsonImage
    from hepta.hia_json_wire_native import SOURCE as wire_source, installed_json_wire

    adapter_path = Path(config.adapter).resolve(strict=True) if config.adapter else folder / "hia_artifact_page_native.py"
    spec = importlib.util.spec_from_file_location("hepta.hia_artifact_page_native", adapter_path)
    page = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(page)
    policy_manifest_path = folder / "development-r1/manifest.json"
    policy_manifest = json.loads(policy_manifest_path.read_bytes())
    if sha256((folder / "artifact_page.hiaasm").read_bytes()).hexdigest() != policy_manifest["source_sha256"]:
        raise ValueError("artifact-page source differs from its development image manifest")
    policy_path = policy_manifest_path.parent / policy_manifest["image_path"]
    policy = NativeHiaJsonImage(policy_path.read_bytes(), policy_manifest["image_sha256"])
    wire = installed_json_wire(config.wire_manifest)
    owner = page.NativeArtifactPage(policy, wire)
    paths = [Path(__file__), adapter_path,
             folder / "artifact_page.hiaasm", policy_manifest_path, policy_path,
             Path(config.wire_manifest), wire_source,
             root / "hepta/hia_json_wire_native.py", root / "hepta/hia_agent_service.py"]
    before = [file_record(path) for path in paths]
    observations = []
    opened = []
    started = time.monotonic_ns()
    report = {"schema": "hia.artifact-page-private-lifecycle-controls.v1",
              "scope": "DEVELOPMENT_REAL_PAGE_AND_WIRE_IMAGES_PRIVATE_CONTINUATION_ONLY",
              "whole_native_delivery_qualified": False, "expect": config.expect,
              "policy_image_sha256": policy.image_sha256,
              "wire_image_sha256": wire.image_sha256,
              "source_before": before, "observations": observations,
              "sqlite_scope": "independent in-memory databases; no disk durability claim"}

    def new():
        data = b"abcdef"
        ref = {"id": "a-lifecycle", "sha256": sha256(data).hexdigest(), "uri": "hia://lifecycle"}
        args = {"artifact": ref, "max_bytes": 2}
        db = CountingDatabase()
        opened.append(db)
        service = SimpleNamespace(store=SimpleNamespace(get=lambda selected: (data, {}), db=db))
        return page.PageSession(owner, service, args), service, args, db

    def sql_pending(session):
        for _ in range(256):
            code = session.step()
            if code != 1:
                raise AssertionError(("SQL request was not reached", code))
            opcode, sequence = struct.unpack_from("<2Q", session.workspace, 8)
            if opcode == 13:
                return sequence
            session.observe()
        raise AssertionError("private request bound exceeded")

    def observe_call(session):
        try:
            value = session.observe()
            return {"returned_packet_bytes": len(value)}
        except BaseException as exc:
            return {"exception_type": type(exc).__name__, "message": str(exc)}

    try:
        with patch.dict(os.environ, {}, clear=True):
            session, service, args, db = new()
            _, old_service, old_args, old_db = new()
            expected = service_module.HIAAgentService._hia_read(old_service, old_args)
            actual = session.run()
            observations.append({"case": "normal_single_sql_effect", "passed":
                                 actual == expected and db.rows() == old_db.rows()
                                 and db.inserts == old_db.inserts == 1
                                 and actual["artifact"] is args["artifact"],
                                 "insert_calls": db.inserts, "cursor_rows": db.rows(),
                                 "finished": session.finished, "result": actual})

            session, _, _, db = new()
            sequence = sql_pending(session)
            code = session.step(struct.pack("<8Q", page.MAGIC, sequence + 1, 13, 0, 0, 0, 0, 0))
            first = observe_call(session)
            second = observe_call(session)
            observations.append({"case": "malformed_ack_then_stale_sql_observe",
                                 "passed": code == 199 and session.finished and db.inserts == 0
                                 and first.get("exception_type") == "RuntimeError"
                                 and second.get("exception_type") == "RuntimeError",
                                 "terminal_code": code, "finished": session.finished,
                                 "observe_after_terminal": first, "observe_again": second,
                                 "insert_calls": db.inserts, "cursor_rows": db.rows()})

            session, _, _, db = new()
            sql_pending(session)
            session.observe()
            repeated = observe_call(session)
            observations.append({"case": "duplicate_observe_before_ack",
                                 "passed": db.inserts == 1 and repeated.get("exception_type") == "RuntimeError",
                                 "repeated": repeated, "insert_calls": db.inserts,
                                 "cursor_rows": db.rows()})

            session, _, _, db = new()
            sql_pending(session)
            session.observe()
            code = session.step()
            stale = observe_call(session)
            observations.append({"case": "successful_terminal_refuses_observe",
                                 "passed": code == 2 and session.finished and db.inserts == 1
                                 and stale.get("exception_type") == "RuntimeError",
                                 "terminal_code": code, "finished": session.finished,
                                 "stale": stale, "insert_calls": db.inserts, "cursor_rows": db.rows()})

            session, _, _, db = new()
            sql_pending(session)
            try:
                foreign_origin()
            except ForeignStop as original:
                sentinel = original
            origin_tb = sentinel.__traceback__
            db.failure = sentinel
            ambient = OSError("existing handled ambient exception")
            caught = None
            try:
                raise ambient
            except OSError:
                try:
                    session.observe()
                except BaseException as exc:
                    caught = exc
                    first_tb = exc.__traceback__
                    first_context = exc.__context__
                    first_frames = trace_frames(exc)
            repeated = observe_call(session)
            origin_present = False
            at = caught.__traceback__
            while at is not None:
                origin_present = origin_present or at is origin_tb
                at = at.tb_next
            observations.append({"case": "foreign_base_exception_closes_without_replay_or_traceback_change",
                                 "passed": caught is sentinel and session.finished and db.inserts == 1
                                 and repeated.get("exception_type") == "RuntimeError"
                                 and sentinel.__traceback__ is first_tb
                                 and sentinel.__context__ is first_context is ambient
                                 and db.handled_at_insert == [ambient] and origin_present,
                                 "same_exception": caught is sentinel, "finished": session.finished,
                                 "repeated": repeated, "insert_calls": db.inserts,
                                 "traceback_preserved_after_refusal": sentinel.__traceback__ is first_tb,
                                 "original_traceback_tail_present": origin_present,
                                 "ambient_context_preserved": sentinel.__context__ is first_context is ambient,
                                 "first_traceback": first_frames, "final_traceback": trace_frames(sentinel),
                                 "cursor_rows": db.rows()})

            session, _, _, db = new()
            sequence = sql_pending(session)
            try:
                foreign_origin()
            except ForeignStop as original:
                sentinel = original
            origin_tb = sentinel.__traceback__
            raw_entry = policy._entry
            entry_observation = {}

            def after_native(*arguments):
                entry_observation["code"] = raw_entry(*arguments)
                entry_observation["handled"] = sys.exception()
                raise sentinel

            ambient = OSError("handled ambient around native entry")
            caught = None
            with patch.object(policy, "_entry", after_native):
                try:
                    raise ambient
                except OSError:
                    try:
                        session.step(struct.pack("<8Q", page.MAGIC, sequence + 1, 13, 0, 0, 0, 0, 0))
                    except BaseException as exc:
                        caught = exc
                        first_tb = exc.__traceback__
                        first_context = exc.__context__
                        first_frames = trace_frames(exc)
            closed_before_stale = session.finished
            stale = observe_call(session)
            try:
                after = {"returned_code": session.step()}
            except BaseException as exc:
                after = {"exception_type": type(exc).__name__, "message": str(exc)}
            origin_present = False
            at = caught.__traceback__
            while at is not None:
                origin_present = origin_present or at is origin_tb
                at = at.tb_next
            observations.append({"case": "native_entry_after_return_base_exception_closes_pending_sql",
                                 "passed": entry_observation.get("code") == 199 and caught is sentinel
                                 and closed_before_stale and db.inserts == 0
                                 and stale.get("exception_type") == "RuntimeError"
                                 and after.get("exception_type") == "RuntimeError"
                                 and sentinel.__traceback__ is first_tb
                                 and sentinel.__context__ is first_context is ambient
                                 and entry_observation.get("handled") is ambient and origin_present,
                                 "real_native_return": entry_observation.get("code"),
                                 "same_exception": caught is sentinel,
                                 "closed_before_stale": closed_before_stale,
                                 "observe_after_exception": stale, "step_after_exception": after,
                                 "insert_calls": db.inserts, "cursor_rows": db.rows(),
                                 "traceback_preserved_after_refusal": sentinel.__traceback__ is first_tb,
                                 "original_traceback_tail_present": origin_present,
                                 "ambient_context_preserved": sentinel.__context__ is first_context is ambient,
                                 "entry_saw_existing_handled_exception": entry_observation.get("handled") is ambient,
                                 "first_traceback": first_frames, "final_traceback": trace_frames(sentinel)})
        report["status"] = ("DEVELOPMENT_PROTOCOL_CONTROLS_PASS" if all(x["passed"] for x in observations)
                            else "DEVELOPMENT_PROTOCOL_BOUNDARY_FAILURES_OBSERVED")
    except BaseException as exc:
        report.update(status="DEVELOPMENT_PROTOCOL_CONTROLS_HOLD", error=repr(exc),
                      traceback=traceback.format_exc())
    finally:
        for db in opened:
            db.connection.close()
    report["source_after"] = [file_record(path) for path in paths]
    report["source_preserved"] = report["source_after"] == before
    report["elapsed_ns"] = time.monotonic_ns() - started
    if not report["source_preserved"]:
        report["status"] = "DEVELOPMENT_PROTOCOL_CONTROLS_HOLD"
    raw = (json.dumps(report, indent=2, ensure_ascii=False) + "\n").encode()
    with destination.open("xb") as output:
        output.write(raw)
    print(json.dumps({"status": report["status"], "cases": len(observations),
                      "passed": sum(x["passed"] for x in observations),
                      "elapsed_ns": report["elapsed_ns"], "source_preserved": report["source_preserved"],
                      "report_sha256": sha256(raw).hexdigest()}))
    return 0 if (report["status"] == "DEVELOPMENT_PROTOCOL_CONTROLS_PASS"
                 or config.expect == "observe" and report["status"] == "DEVELOPMENT_PROTOCOL_BOUNDARY_FAILURES_OBSERVED") else 1


if __name__ == "__main__":
    raise SystemExit(main())
