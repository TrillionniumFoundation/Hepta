"""Fixed parent/child observation for the unchanged original eight-test module.

This guard belongs to the development controller, not to product dispatch.
It observes all actual selected read calls and refuses entry into the retained
original Python code object, including entry through an unexpected alias.
"""
from __future__ import annotations
import atexit
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import traceback

from source_common import create, read, require, wire

SELECTOR = "HEPTA_HIA_BOUNDED_READ_MANIFEST"
POLICY_VARIABLE = "HIA_BOUNDED_READ_CHILD_POLICY"
POLICY_SHA_VARIABLE = "HIA_BOUNDED_READ_CHILD_POLICY_SHA256"


def pin_file(path, maximum=32 << 20):
    raw, record = read(Path(path), maximum)
    return raw, record


class Observation:
    def __init__(self, policy, policy_sha, role):
        self.policy, self.policy_sha, self.role = policy, policy_sha, role
        self.source = Path(policy["source"])
        self.manifest = Path(policy["manifest"])
        require(os.environ.get(SELECTOR) == str(self.manifest), "original callers selector differs")
        require(role in ("parent", "child"), "unknown caller observation role")
        if role == "child":
            require(os.getppid() == policy["parent_pid"], "original caller child parent differs")
        import hepta.hia_program_tools as public
        from hepta.hia_bounded_read_native import installed_bounded_read
        self.public = public
        require(Path(public.__file__).absolute() == self.source / "hepta/hia_program_tools.py",
                "original caller imported another product module")
        self.owner = installed_bounded_read(self.manifest)
        self.reference = public._READ_BOUNDED_REFERENCE
        self.retained_code = self.reference.__code__
        self.retained = []
        self.calls = []
        self.original_public = public.read_bounded
        self.original_retained = public._RETAINED_READ_BOUNDED
        self.profile_before = sys.getprofile()
        require(self.profile_before is None, "unexpected caller profiler")
        self.finished = False
        self.record = {"schema": "hepta.hia.bounded-read-original-caller-observer.v1",
            "status": "HOLD", "role": role, "pid": os.getpid(), "parent_pid": os.getppid(),
            "policy_sha256": policy_sha, "actual_executable": str(Path(sys.executable).resolve()),
            "manifest": str(self.manifest), "source": str(self.source),
            "retained_owner_calls": self.retained, "read_calls": self.calls,
            "original_CLI_timeout_seconds_unchanged": 20,
            "product_full_qualification": False}
        self.record["source_before"] = self.sources()
        self.record["bundle_before"] = self.bundle()
        self.record["native_before"] = self.owner.identity()
        self.record["ledger_before"] = self.ledger()

        def forbidden(*args, **kwargs):
            self.retained.append({"kind": "retained_alias", "argument_count": len(args)})
            raise AssertionError("retained bounded-read Python owner entered")

        def profile(frame, event, arg):
            if event == "call" and frame.f_code is self.retained_code:
                self.retained.append({"kind": "original_code_object",
                    "name": frame.f_code.co_name, "filename": frame.f_code.co_filename})
                raise AssertionError("retained bounded-read code object entered")

        def observed(*args, **kwargs):
            row = {"ordinal": len(self.calls), "outcome": "PENDING",
                   "native_calls_before": self.owner.calls,
                   "native_transitions_before": self.owner.transitions}
            self.calls.append(row)
            try:
                value = self.original_public(*args, **kwargs)
            except BaseException as error:
                row.update(outcome="raised", type=type(error).__name__,
                           native_calls_after=self.owner.calls,
                           native_transitions_after=self.owner.transitions)
                raise
            else:
                row.update(outcome="returned", type=type(value).__name__,
                           native_calls_after=self.owner.calls,
                           native_transitions_after=self.owner.transitions)
                return value
        self.profile = profile
        public._RETAINED_READ_BOUNDED = forbidden
        public.read_bounded = observed
        sys.setprofile(profile)
        self.record["status"] = "OBSERVER_INSTALLED_NOT_COMPLETED"

    def sources(self):
        result = {}
        for name, expected in self.policy["source_pins"].items():
            _, actual = pin_file(self.source / name)
            require(actual["sha256"] == expected["sha256"] and actual["bytes"] == expected["bytes"],
                    "original caller source changed: " + name)
            result[name] = actual
        return result

    def bundle(self):
        raw, manifest = pin_file(self.manifest, 16384)
        require(manifest["sha256"] == self.policy["manifest_sha256"],
                "original caller manifest differs")
        value = json.loads(raw)
        path = self.manifest.parent / value["image_path"]
        require(path.parent == self.manifest.parent, "nonlocal native image path")
        _, image = pin_file(path)
        require(image["sha256"] == value["image_sha256"]
                and image["sha256"] == self.policy["image_sha256"],
                "original caller actual image differs")
        return {"manifest": manifest, "image": image}

    def ledger(self):
        return {"calls": self.owner.calls, "transitions": self.owner.transitions,
                "attempts": dict(self.owner.effect_attempts),
                "returns": dict(self.owner.effect_returns),
                "errors": dict(self.owner.effect_errors)}

    def finish(self):
        require(not self.finished, "caller observer terminal already consumed")
        self.finished = True
        sys.setprofile(self.profile_before)
        self.public.read_bounded = self.original_public
        self.public._RETAINED_READ_BOUNDED = self.original_retained
        self.record["argv"] = list(sys.argv)
        try:
            self.record["source_after"] = self.sources()
            self.record["bundle_after"] = self.bundle()
            self.record["native_after"] = self.owner.identity()
            self.record["ledger_after"] = self.ledger()
            require(self.record["source_before"] == self.record["source_after"]
                    and self.record["bundle_before"] == self.record["bundle_after"]
                    and self.record["native_before"] == self.record["native_after"],
                    "original caller source or bundle drift")
            require(not self.retained and self.calls
                    and all(row["outcome"] in ("returned", "raised")
                            and row["native_calls_after"] == row["native_calls_before"] + 1
                            and row["native_transitions_after"] > row["native_transitions_before"]
                            for row in self.calls),
                    "retained entry or incomplete actual selected read")
            require(self.record["ledger_after"]["calls"] - self.record["ledger_before"]["calls"]
                    == len(self.calls), "selected parent/child call denominator differs")
            self.record["status"] = "ORIGINAL_CALLER_OBSERVER_PASS"
        except BaseException as error:
            self.record["status"] = "HOLD"
            self.record["error"] = {"type": type(error).__name__, "text": str(error),
                                    "traceback": traceback.format_exc()}
        target = (Path(self.policy["children"]) / ("child-%d.json" % os.getpid())
                  if self.role == "child" else Path(self.policy["parent_record"]))
        create(target, wire(self.record))
        return self.record


def load_policy():
    path = Path(os.environ[POLICY_VARIABLE])
    raw, record = pin_file(path, 1 << 20)
    require(record["sha256"] == os.environ[POLICY_SHA_VARIABLE], "fixed caller policy SHA differs")
    policy = json.loads(raw)
    require(policy["schema"] == "hepta.hia.bounded-read-original-eight-child-policy.v1",
            "fixed caller policy schema differs")
    return policy, record["sha256"]


def install_child():
    policy, digest = load_policy()
    observation = Observation(policy, digest, "child")
    start = {"schema": "hepta.hia.bounded-read-original-caller-start.v1",
             "pid": os.getpid(), "parent_pid": os.getppid(), "policy_sha256": digest,
             "source": policy["source"], "manifest": policy["manifest"],
             "native_identity": observation.owner.identity()}
    create(Path(policy["children"]) / ("start-%d.json" % os.getpid()), wire(start))
    atexit.register(observation.finish)
