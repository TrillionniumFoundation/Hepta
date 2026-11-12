"""Delegate fresh v87 probes to the exact original 972d preparer.

Only new supply admission and the private Cargo setting are added. No original
probe, source match, storage check, run(), save(), or launcher is substituted.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import sys
import types

from full_common import PACKAGE_PINS, PREPARER_SHA256, file_record, read_json, require


PROFILES = ("ranking", "raw", "dynamic", "recursive", "finite", "stream")


def adapted_class(original, supply, supply_record, expected_source, expected_path):
    class CurrentPreparation(original.Preparation):
        def __init__(self, args):
            super().__init__(args)
            self.env["CARGO_HOME"] = supply["cargo_home"]
            self.tool_variables.add("CARGO_HOME")
            self.report["v87_supply_admission"] = {
                "schema": "hia.v87.fresh-supply-admission.v1",
                "supply_original": supply_record,
                "expected_source": expected_source,
                "original_preparer_sha256": PREPARER_SHA256,
                "original_run_and_save_unchanged": True,
                "cache_tree_immutability_claimed": False,
                "offline_build_completeness_claimed": False,
                "historical_fixture_result_reused": False,
            }

        def pinned_inputs(self):
            require(supply.get("schema") == "hia.v87.full-prerequisite-supply.v1"
                    and supply.get("status") == "INPUTS_BUILT_PENDING_ORIGINAL_PREPARATION"
                    and supply.get("qualification_executed") is False
                    and supply.get("source") == expected_source,
                    "fresh supply status/source differs")
            require(self.base == Path(supply["prerequisite_root"])
                    and self.source == expected_path,
                    "supply/preparer root differs")
            require(str(self.args.python) == supply["python"]["path"]
                    and self.args.candidate_environment == Path(supply["hints_path"]),
                    "supplied Python/hints path differs")
            hints, hint_record = read_json(self.args.candidate_environment)
            require(hint_record["sha256"] == supply["hints_sha256"]
                    and hints == self.hints, "fresh hints bytes/settings differ")
            checks = [row["check"] for row in supply["fixed_tools"]]
            require(len(checks) == len(set(checks))
                    and set(checks) == {"clang", "clangxx", "lld", "objdump", "profdata", "readobj",
                                        "gcc", "qemu_x86_64", "qemu_riscv64", "qemu_aarch64",
                                        "cargo", "rustc", "lean", "strace"},
                    "all original executable probes must have fresh supply pins")
            require(sorted(row["profile"] for row in supply["fixture_receipts"]) == sorted(PROFILES),
                    "six original NDU fixture profiles are required")
            pinned = {}
            for row in [supply["python"], *supply["fixed_tools"], *supply["fixture_receipts"]]:
                requested = Path(row["path"])
                # Executable aliases may be symlinks; preserve both the actual
                # resolved bytes and original preparer's requested-path binding.
                actual = self.info(requested, executable=row in [supply["python"], *supply["fixed_tools"]],
                                   bind=True)
                require(all(actual[key] == row[key] for key in ("bytes", "sha256")),
                        "fresh supplied file changed: " + str(requested))
                pinned[str(requested)] = actual
            for path, expected in supply["input_bindings"].items():
                actual = self.info(path, bind=True)
                require(actual["sha256"] == expected, "supplied provenance input changed: " + path)
                pinned[path] = actual

            home = Path(supply["cargo_home"])
            require(home.is_absolute() and home.resolve(strict=True) == home
                    and not any(path.is_symlink() for path in (home, *home.parents)),
                    "Cargo cache has a link ancestor")
            info = home.stat()
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
                    and not (stat.S_IMODE(info.st_mode) & 0o022), "Cargo cache is not private/owned")
            manifest_pin = supply["cargo_manifest"]
            manifest, manifest_record = read_json(Path(manifest_pin["path"]), manifest_pin)
            require(set(manifest) == {"archives", "offline_full_regression_not_yet_executed", "path", "schema"}
                    and manifest["schema"] == "hia.private-cargo-cache-observation.v1"
                    and manifest["path"] == str(home)
                    and manifest["offline_full_regression_not_yet_executed"] is True
                    and manifest_pin["archives"] == len(manifest["archives"]) == 55,
                    "actual fixed 55-crate archive inventory differs")
            archives = {}
            for path, expected in sorted(manifest["archives"].items()):
                path = Path(path)
                require(path.is_absolute() and path.is_relative_to(home / "registry/cache")
                        and path.suffix == ".crate", "crate path escapes private cache")
                actual = file_record(path)
                require(actual["identity"][3] == os.getuid() and actual["identity"][5] == 1
                        and actual["sha256"] == expected, "crate archive identity differs")
                self.bindings[str(path)] = expected
                archives[str(path)] = actual
            self.bindings[str(manifest_pin["path"])] = manifest_record["sha256"]
            self.report["v87_supply_admission"].update(
                current_inputs=pinned, current_hints=hint_record,
                current_crate_manifest=manifest_record, current_crate_archives=archives,
                scope="fixed archives; cache index/locks/extracted sources may change")

        def selected_inputs(self):
            require(self.python == supply["python"]["path"], "preparer chose another Python")
            python = self.report["checks"]["python"]
            require(python.get("available") is True and python.get("version_info") == [3, 14, 4]
                    and all(python.get("packages", {}).get(name) == version
                            for name, version in PACKAGE_PINS.items()),
                    "Python 3.14.4/four exact package pins differ")
            for row in supply["fixed_tools"]:
                actual = self.report["checks"].get(row["check"], {})
                require(actual.get("available") is True and actual.get("path") == row["path"]
                        and actual.get("sha256") == row["sha256"],
                        "original probe selected another supplied tool: " + row["check"])
            for row in supply["fixture_receipts"]:
                actual = self.report["checks"].get("ndu_" + row["profile"], {})
                require(actual.get("available") is True and actual.get("path") == row["path"]
                        and actual.get("sha256") == row["sha256"],
                        "original probe did not admit current fixture: " + row["profile"])
            require(self.env.get("CARGO_HOME") == supply["cargo_home"]
                    and self.env.get("CARGO_NET_OFFLINE") == "true"
                    and self.env.get("CARGO_TARGET_DIR") == str(self.out / "cargo-target"),
                    "offline Cargo or fresh target setting differs")

        def run(self):
            try:
                self.pinned_inputs()
            except Exception as error:
                self.report["v87_supply_admission"]["input_error"] = repr(error)
                self.missing("v87_supplied_inputs", "Fixed fresh input refused before any original tool probe.")
                return
            super().run()
            try:
                self.selected_inputs()
            except Exception as error:
                self.report["v87_supply_admission"]["selection_error"] = repr(error)
                self.missing("v87_current_selection", "Original probes did not admit every fixed fresh input.")
    return CurrentPreparation


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--supply", required=True, type=Path)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--head", required=True)
    parser.add_argument("--tree", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--temporary-root", required=True, type=Path)
    args = parser.parse_args()
    supply, supply_record = read_json(args.supply, limit=16 << 20)
    preparer = Path(__file__).with_name("prepare_remote_qualification_v2.py")
    _, raw = file_record(preparer, body_limit=1 << 20)
    require(sha256(raw).hexdigest() == PREPARER_SHA256, "original 972d bytes differ")
    module = types.ModuleType("v87_exact_972d_preparer")
    module.__file__ = str(preparer)
    exec(compile(raw, str(preparer), "exec"), module.__dict__)
    expected = {"head": args.head, "tree": args.tree}
    module.Preparation = adapted_class(module, supply, supply_record, expected, args.source)
    sys.argv = [str(preparer), "--source", str(args.source), "--output", str(args.output),
                "--temporary-root", str(args.temporary_root), "--prereq-root", supply["prerequisite_root"],
                "--python", supply["python"]["path"], "--candidate-environment", supply["hints_path"]]
    return module.main()


if __name__ == "__main__":
    raise SystemExit(main())
