"""Setuptools-only build receipt for the CPython Slot mechanical extension.

This module never imports hepta, runs an HIA generator, or claims qualification.
It is used by setup.py for ordinary wheels and explicit source builds.
"""
from __future__ import annotations
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import shutil
import stat
import sys
import sysconfig
from setuptools import Extension
from setuptools.command.build_ext import build_ext

ROOT = Path(__file__).resolve().parents[2]
ABI = "hepta.slot.mechanical.cpython-gil-linux.v1"
SOURCES = (
    "hepta/native/slot_mechanical.c",
    "hepta/hia_slot_continuations.py",
    "hepta/hia_slot_mechanical.py",
    "hepta/hia_slot_operations_native.py",
    "hepta/hia_slot_operations_selection.py",
    "hepta/hia_slot_operations_protocol.py",
    "hepta/hia_slot_operation_series.py",
    "hepta/hia_native_delivery.py",
    "hepta/hia_native_helpers.py",
    "hepta/hia_mechanical_worker_bundle.py",
    "hepta/native/slot_mechanical_build.py",
)


def supported_profile():
    return (sys.implementation.name == "cpython" and sys.platform == "linux"
            and (3, 11) <= sys.version_info[:2] <= (3, 14)
            and not bool(sysconfig.get_config_var("Py_GIL_DISABLED"))
            and platform.machine() == "x86_64"
            and sysconfig.get_config_var("SIZEOF_VOID_P") == 8)


def extensions():
    # The package keeps its existing >=3.11 claim for unselected Python code.
    # This optional selected ABI has an explicit, independently qualified
    # CPython/GIL/Linux profile; unsupported profiles do not get a false .so.
    if not supported_profile():
        return []
    return [Extension("hepta._hia_slot_mechanical",
                      sources=["hepta/native/slot_mechanical.c"],
                      extra_compile_args=["-std=c11"],
                      py_limited_api=False)]


def pin(raw):
    return {"bytes": len(raw), "sha256": sha256(raw).hexdigest()}


class MechanicalBuildExt(build_ext):
    def initialize_options(self):
        super().initialize_options()
        self._mechanical_outputs = []

    def build_extension(self, extension):
        if extension.name != "hepta._hia_slot_mechanical":
            return super().build_extension(extension)
        if not supported_profile():
            raise RuntimeError("unsupported selected Slot mechanical build profile")
        before = {name: (ROOT / name).read_bytes() for name in SOURCES}
        commands, binaries = [], {}
        prior_spawn = self.compiler.spawn

        def observed_spawn(command, **keywords):
            argv = [str(value) for value in command]
            if not argv or not argv[0]:
                raise ValueError("empty mechanical compiler command")
            executable = shutil.which(argv[0])
            if executable is None:
                raise ValueError("mechanical compiler executable is unavailable")
            executable = str(Path(executable).resolve(strict=True))
            raw = Path(executable).read_bytes()
            observed = {"path": executable, **pin(raw)}
            previous = binaries.get(executable)
            if previous is not None and previous != observed:
                raise ValueError("mechanical compiler changed between commands")
            binaries[executable] = observed
            commands.append(argv)
            result = prior_spawn(command, **keywords)
            if Path(executable).read_bytes() != raw:
                raise ValueError("mechanical compiler changed during execution")
            return result

        self.compiler.spawn = observed_spawn
        prior_force, prior_compiler_force = self.force, self.compiler.force
        self.force = self.compiler.force = True
        try:
            super().build_extension(extension)
        finally:
            self.compiler.spawn = prior_spawn
            self.force, self.compiler.force = prior_force, prior_compiler_force
        if not commands:
            raise ValueError("mechanical extension was not actually compiled; force a fresh build")
        if any((ROOT / name).read_bytes() != raw for name, raw in before.items()):
            raise ValueError("mechanical extension inputs changed during compilation")
        binary = Path(self.get_ext_fullpath(extension.name))
        raw = binary.read_bytes()
        suffix = sysconfig.get_config_var("EXT_SUFFIX")
        if binary.name != "_hia_slot_mechanical" + suffix:
            raise ValueError("mechanical extension output has a different ABI filename")
        report = {
            "schema": "hepta.slot.mechanical.build.v2", "abi": ABI,
            "profile": {"implementation": "cpython", "python": list(sys.version_info[:3]),
                        "platform": sys.platform, "machine": platform.machine(),
                        "soabi": sysconfig.get_config_var("SOABI"),
                        "extension_suffix": suffix, "gil_disabled": False},
            "binary": {"name": binary.name, **pin(raw)},
            "sources": {name: pin(before[name]) for name in sorted(before)},
            "compiler_commands": commands, "compiler_executables": binaries,
            "build_scope": "CPYTHON_MECHANICAL_EXTENSION_ONLY",
            "product_qualification_claimed": False,
        }
        identity = binary.parent / "_slot_mechanical_build.json"
        identity.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
        self._mechanical_outputs.append(str(identity))

    def copy_extensions_to_source(self):
        # setuptools temporarily builds into build_lib even for --inplace.
        # Copy exactly the already validated receipt beside the exact binary.
        super().copy_extensions_to_source()
        for extension in self.extensions:
            if extension.name != "hepta._hia_slot_mechanical":
                continue
            relative = Path(self.get_ext_filename(extension.name))
            source = Path(self.build_lib) / relative.parent / "_slot_mechanical_build.json"
            target = ROOT / relative.parent / "_slot_mechanical_build.json"
            if not source.is_file():
                raise ValueError("mechanical build receipt is absent before in-place copy")
            raw = source.read_bytes()
            target.write_bytes(raw)
            if target.read_bytes() != raw:
                raise ValueError("mechanical in-place receipt differs")
            self._mechanical_outputs.append(str(target))

    def get_outputs(self):
        return super().get_outputs() + list(self._mechanical_outputs)
