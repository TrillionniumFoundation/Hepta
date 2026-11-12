"""HIA native P2/P7: hostile parent startup environment must not reach worker.

Real Clang and sealed memfd child observer; finite Linux transport only.
Not a whole-compiler qualification or proof of hostile-native containment.
"""
from __future__ import annotations

import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from hepta import hia_native_differential as native

_SUPPORTED = (
    platform.system() == "Linux"
    and platform.machine().lower() in {"x86_64", "amd64"}
    and shutil.which("clang") is not None
    and hasattr(os, "memfd_create")
    and hasattr(signal, "SIGSYS")
)


@unittest.skipUnless(_SUPPORTED, "needs Linux x86-64, Clang, memfd and seccomp")
class NativeWorkerStartupIsolationTests(unittest.TestCase):
    @staticmethod
    def build(root: Path, name: str, code: str) -> Path:
        c = root / (name + ".c")
        so = root / (name + ".so")
        c.write_text(code, encoding="utf-8")
        subprocess.run(["clang", "-O0", "-shared", "-fPIC", str(c), "-o", str(so)],
                       check=True, capture_output=True, timeout=30)
        return so

    @staticmethod
    def observe(library: Path, symbol: str):
        original, identity, fd = native._pin_native_artifact(library)
        try:
            native._check_artifact_unchanged(library, original, identity)
            return native._observe_native(
                library, symbol, "i32", [], timeout=3.0, pinned_fd=fd)
        finally:
            os.close(fd)

    def test_site_and_ambient_env_absent_before_installing_native_seccomp(self):
        with tempfile.TemporaryDirectory(prefix="hia-nosite-") as tmp:
            lib = self.build(Path(tmp), "controls", """
#include <stdlib.h>
int healthy(void) { return 7; }
int defined_abort(void) { abort(); }
""")
            # This preamble executes before the original _WORKER installs
            # seccomp. Even -I without -S initializes Python site modules.
            preamble = (
                "import os, sys\n"
                "if 'site' in sys.modules or 'sitecustomize' in sys.modules:\n"
                "    raise RuntimeError('unqualified pre-seccomp site hook')\n"
                "if dict(os.environ) != {'LC_ALL':'C','LANG':'C','TZ':'UTC'}:\n"
                "    raise RuntimeError('unqualified inherited worker environment')\n"
            )
            with patch.object(native, "_WORKER", preamble + native._WORKER):
                self.assertEqual(self.observe(lib, "healthy"), ("value", 7))
                self.assertEqual(self.observe(lib, "defined_abort"), ("trap", None))

    def test_inherited_preload_constructor_cannot_write_before_seccomp(self):
        with tempfile.TemporaryDirectory(prefix="hia-preload-") as tmp:
            root = Path(tmp)
            lib = self.build(root, "controls", "int healthy(void) { return 7; }\n")
            marker = root / "injected_constructor_marker"
            preload = self.build(root, "preload", r"""
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
__attribute__((constructor)) static void injected(void) {
    const char *path = getenv("HIA_PRELOAD_PROBE_MARKER");
    if (path != NULL) {
        int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (fd >= 0) { (void)write(fd, "X", 1); close(fd); }
    }
}
""")
            # Without an explicit Popen environment LD_PRELOAD runs this
            # constructor before interpreter startup and before seccomp.
            with patch.dict(os.environ, {
                "LD_PRELOAD": str(preload),
                "LD_LIBRARY_PATH": str(root),
                "HIA_PRELOAD_PROBE_MARKER": str(marker),
                "PYTHONPATH": str(root),
            }):
                self.assertEqual(self.observe(lib, "healthy"), ("value", 7))
            self.assertFalse(marker.exists(), "ambient ELF constructor bypassed seccomp")

    def test_isolated_nosite_still_supports_worker_standard_library(self):
        result = subprocess.run(
            [os.sys.executable, "-I", "-S", "-c",
             "import ctypes,json,os,resource,sys;"
             "assert 'site' not in sys.modules;"
             "assert ctypes.CDLL(None);print('ok',flush=True)"],
            capture_output=True, timeout=15, check=False,
            env={"LC_ALL":"C", "LANG":"C", "TZ":"UTC"})
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        self.assertEqual(result.stdout, b"ok\n")


if __name__ == "__main__":
    unittest.main()
