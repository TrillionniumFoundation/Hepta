"""Setuptools-only build receipt for the CPython native carrier mechanical extension.

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
BUILD_PROFILES = {'hepta._hia_native_image': ('hepta.native-image.three-writable-buffers.v1',
                             'hepta.native-image.build.v1',
                             '_native_image_build.json',
                             ('hepta/native/native_image.c',
                              'hepta/native/native_carrier_build.py',
                              'hepta/hia_native_image.py',
                              'hepta/hia_native_helpers.py',
                              'hepta/hia_native_carrier_worker_bundle.py',
                              'hepta/hia_service_artifact_native.py',
                              'hepta/hia_service_artifact_bridge.py')),
 'hepta._hia_cell_frame': ('hepta.cell-frame.real-cells.v1',
                           'hepta.cell-frame.build.v1',
                           '_cell_frame_build.json',
                           ('hepta/native/cell_frame.c',
                            'hepta/native/native_carrier_build.py',
                            'hepta/hia_cell_frame.py',
                            'hepta/hia_native_helpers.py',
                            'hepta/hia_native_carrier_worker_bundle.py',
                            'hepta/hia_service_verification_native.py'))}


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
    return [Extension(name, sources=[record[3][0]],
                      extra_compile_args=["-std=c11", "-Wall", "-Wextra", "-Werror", "-Wno-unused-parameter"],
                      py_limited_api=False)
            for name, record in BUILD_PROFILES.items()]


def pin(raw):
    return {"bytes": len(raw), "sha256": sha256(raw).hexdigest()}


class NativeCarrierBuildExt(build_ext):
    def initialize_options(self):
        super().initialize_options()
        self._native_carrier_outputs = []

    def build_extension(self, extension):
        if extension.name not in BUILD_PROFILES:
            return super().build_extension(extension)
        abi, schema, receipt_name, sources = BUILD_PROFILES[extension.name]
        if not supported_profile():
            raise RuntimeError("unsupported selected native carrier mechanical build profile")
        before = {name: (ROOT / name).read_bytes() for name in sources}
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
        if binary.name != extension.name.rsplit(".", 1)[1] + suffix:
            raise ValueError("mechanical extension output has a different ABI filename")
        report = {
            "schema": schema, "abi": abi,
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
        identity = binary.parent / receipt_name
        identity.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
        self._native_carrier_outputs.append(str(identity))

    def copy_extensions_to_source(self):
        # setuptools temporarily builds into build_lib even for --inplace.
        # Copy exactly the already validated receipt beside the exact binary.
        super().copy_extensions_to_source()
        for extension in self.extensions:
            if extension.name not in BUILD_PROFILES:
                continue
            receipt_name = BUILD_PROFILES[extension.name][2]
            relative = Path(self.get_ext_filename(extension.name))
            source = Path(self.build_lib) / relative.parent / receipt_name
            target = ROOT / relative.parent / receipt_name
            if not source.is_file():
                raise ValueError("mechanical build receipt is absent before in-place copy")
            raw = source.read_bytes()
            target.write_bytes(raw)
            if target.read_bytes() != raw:
                raise ValueError("mechanical in-place receipt differs")
            self._native_carrier_outputs.append(str(target))

    def get_outputs(self):
        return super().get_outputs() + list(self._native_carrier_outputs)
