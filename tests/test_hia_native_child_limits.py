"""Hard kernel budgets on finite HIA native differential child processes.

These tests compile only an independent C transport control with host Clang.
They do NOT qualify the Hepta compiler, Rust reference gate, or executable
HIA owner/memory backend; those retain their separate full-suite acceptance.
"""
from __future__ import annotations

from pathlib import Path
import json
import platform
import shutil
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

from hepta import hia_native_differential as differential


_CONTROL = r"""
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

int32_t healthy(void) { return 7; }
int32_t force_abort(void) { abort(); return 7; }

int32_t flood_stdout(void) {
    char bytes[512];
    for (int i = 0; i < 512; ++i) bytes[i] = 'X';
    for (int i = 0; i < 64; ++i) (void)write(1, bytes, sizeof bytes);
    return 7;
}
int32_t flood_stderr(void) {
    char bytes[512];
    for (int i = 0; i < 512; ++i) bytes[i] = 'E';
    for (int i = 0; i < 64; ++i) (void)write(2, bytes, sizeof bytes);
    return 7;
}
int32_t huge_virtual_allocation(void) {
    volatile size_t size = (size_t)512 * 1024 * 1024;
    void *p = malloc(size);
    if (p != NULL) {
        free(p);
        return 99;
    }
    return 7;
}
"""


@unittest.skipUnless(platform.system() == "Linux" and shutil.which("clang"),
                     "real Linux host Clang required for finite C transport")
class NativeChildHardLimitTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix="hia-hard-child-")
        cls.root = Path(cls.directory.name)
        source = cls.root / "control.c"
        cls.library = cls.root / "control.so"
        source.write_text(_CONTROL, encoding="utf-8")
        subprocess.run(["clang", "-O0", "-shared", "-fPIC",
                        str(source), "-o", str(cls.library)],
                       check=True, timeout=30)

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def observe(self, function):
        return differential._observe_native(
            self.library, function, "i32", [], timeout=3.0)

    def test_nonflooding_return_and_true_sigabrt_unchanged(self):
        self.assertEqual(self.observe("healthy"), ("value", 7))
        self.assertEqual(self.observe("force_abort"), ("trap", None))

    def test_stdout_and_stderr_flood_are_kernel_capped_not_just_read_capped(self):
        # Existing post-execution 4097-byte read is insufficient: an uncapped
        # file-backed child could write GiB before the bounded read executes.
        for function in ("flood_stdout", "flood_stderr"):
            with self.subTest(function=function), tempfile.TemporaryDirectory(
                    prefix="hia-child-capture-") as scratch:
                files = []

                def capture():
                    # Retain the exact file used for subprocess stdout/stderr,
                    # so we can independently measure the bytes actually
                    # written even after the with-block closes it.
                    stream = tempfile.NamedTemporaryFile(
                        mode="w+b", dir=scratch, delete=False)
                    files.append(Path(stream.name))
                    return stream

                with patch.object(differential.tempfile, "TemporaryFile",
                                  side_effect=capture):
                    with self.assertRaisesRegex(
                            differential.HIADifferentialRejected, "output budget"):
                        self.observe(function)
                self.assertEqual(len(files), 2)
                lengths = [f.stat().st_size for f in files]
                self.assertTrue(all(size <= 4096 for size in lengths), lengths)
                self.assertEqual(lengths[0 if function == "flood_stdout" else 1], 4096)

    def test_native_virtual_allocation_is_bounded_before_function_call(self):
        # Under an RLIMIT_AS of 512 MiB a *new* 512 MiB allocation must fail
        # because the child interpreter + dynamic loader already occupy
        # address space. This is an evaluator budget, not the language's
        # native heap bound or a general process security sandbox.
        self.assertEqual(self.observe("huge_virtual_allocation"), ("value", 7))


    def test_timeout_kills_worker_and_forked_child_process_group(self):
        # Direct-child-only subprocess.run(timeout=...) leaves a native-forked
        # grandchild alive. Observe a marker it would write after the timeout.
        with tempfile.TemporaryDirectory(prefix="hia-killgroup-") as folder:
            root = Path(folder)
            marker = root / "grandchild-survived"
            library = root / "forked.so"
            c_file = root / "forked.c"
            c_file.write_text("""
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
int32_t fork_and_stall(void) {
    pid_t pid = fork();
    if (pid == 0) {
        sleep(2);
        int fd = open(""" + json.dumps(str(marker)) + """, O_WRONLY | O_CREAT, 0600);
        if (fd >= 0) close(fd);
        _exit(0);
    }
    sleep(6);
    return 7;
}
""", encoding="utf-8")
            subprocess.run(["clang", "-O0", "-shared", "-fPIC",
                            str(c_file), "-o", str(library)],
                           check=True, timeout=30)
            with self.assertRaisesRegex(
                    differential.HIADifferentialRejected, "timed out"):
                differential._observe_native(
                    library, "fork_and_stall", "i32", [], timeout=0.3)
            # Enough wall time for a surviving child to write the marker.
            time.sleep(2.3)
            self.assertFalse(marker.exists(),
                             "timeout must not leave an in-group child alive")


if __name__ == "__main__":
    unittest.main()
