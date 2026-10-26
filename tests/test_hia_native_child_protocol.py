"""Native scalar differential output is exactly one typed worker record.

This is a Clang C shared-object protocol-control suite, NOT a Hepta compiler,
Rust reference, source-semantic or hostile-code sandbox qualification.
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

from hepta import hia_native_differential as differential


_CONTROL = r"""
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

int32_t normal_return(void) { return 7; }
int32_t normal_abort(void) { abort(); return 7; }

int32_t log_then_return(void) {
    const char note[] = "unexpected native warning";
    write(2, note, sizeof(note) - 1);
    return 7;
}
int32_t log_then_abort(void) {
    const char note[] = "allocator diagnostic";
    write(2, note, sizeof(note) - 1);
    abort();
    return 7;
}
int32_t duplicate_json(void) {
    const char wire[] = "{\"value\":0,\"value\":7}\n";
    write(1, wire, sizeof(wire) - 1);
    _exit(0);
}
int32_t space_json(void) {
    const char wire[] = "{\"value\": 7}\n";
    write(1, wire, sizeof(wire) - 1);
    _exit(0);
}
int32_t trailing_json(void) {
    const char wire[] = "{\"value\":7}\n\n";
    write(1, wire, sizeof(wire) - 1);
    _exit(0);
}
"""


@unittest.skipUnless(platform.system() == "Linux" and hasattr(os, "memfd_create")
                     and shutil.which("clang"),
                     "Linux sealed memfd and real Clang are required")
class NativeObservationProtocolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workdir = tempfile.TemporaryDirectory(prefix="hia-observation-wire-")
        cls.root = Path(cls.workdir.name)
        cls.library = cls.root / "wire.so"
        src = cls.root / "wire.c"
        src.write_text(_CONTROL, encoding="utf-8")
        subprocess.run(["clang", "-O0", "-shared", "-fPIC", str(src),
                        "-o", str(cls.library)], check=True, timeout=30)

    @classmethod
    def tearDownClass(cls):
        cls.workdir.cleanup()

    def observe(self, symbol):
        data, identity, fd = differential._pin_native_artifact(self.library)
        try:
            differential._check_artifact_unchanged(self.library, data, identity)
            return differential._observe_native(
                self.library, symbol, "i32", [], timeout=3.0, pinned_fd=fd)
        finally:
            os.close(fd)

    def test_canonical_normal_result_and_silent_abort_preserved(self):
        self.assertEqual(self.observe("normal_return"), ("value", 7))
        self.assertEqual(self.observe("normal_abort"), ("trap", None))

    def test_unexpected_stderr_does_not_qualify_result_or_checked_trap(self):
        with self.assertRaisesRegex(
                differential.HIADifferentialRejected, "unexpected stderr"):
            self.observe("log_then_return")
        with self.assertRaisesRegex(
                differential.HIADifferentialRejected, "trap emitted unqualified"):
            self.observe("log_then_abort")

    def test_duplicate_valid_json_and_whitespace_variant_are_not_worker_records(self):
        for symbol in ("duplicate_json", "space_json", "trailing_json"):
            with self.subTest(symbol=symbol):
                with self.assertRaisesRegex(
                        differential.HIADifferentialRejected, "canonical worker record"):
                    self.observe(symbol)


    def test_process_group_kill_precedes_waitpid_reap(self):
        # The direct worker's PID must remain reserved while it is used as a
        # process-group identity. This checks real Linux waitid(WNOWAIT), not
        # a mocked exit status or a separate unverified implementation.
        native_killpg = os.killpg
        observed = []

        def inspect_before_cleanup(group, chosen_signal):
            self.assertEqual(chosen_signal, signal.SIGKILL)
            state = os.waitid(os.P_PID, group,
                              os.WEXITED | os.WNOWAIT | os.WNOHANG)
            self.assertIsNotNone(state, "worker must have exited but not been reaped")
            self.assertEqual(state.si_pid, group)
            observed.append(state.si_pid)
            return native_killpg(group, chosen_signal)

        with patch.object(differential.os, "killpg",
                          side_effect=inspect_before_cleanup):
            self.assertEqual(self.observe("normal_return"), ("value", 7))
        self.assertEqual(len(observed), 1)

if __name__ == "__main__":
    unittest.main()
