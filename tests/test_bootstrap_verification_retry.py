"""Tiny simulated HTTP payloads exercise real checksums/staging, not tool runs."""
from contextlib import redirect_stderr
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import socket
import ssl
import tarfile
import tempfile
import unittest
from unittest.mock import Mock, call, patch
import urllib.error

from tools import bootstrap_verification as bootstrap


def digest(value):
    return hashlib.sha256(value).hexdigest()


def tar_bytes(files):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        for name, data in files.items():
            member = tarfile.TarInfo(name)
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
    return stream.getvalue()


class InterruptedResponse(io.BytesIO):
    def __init__(self, payload):
        super().__init__(payload)
        self.first = True

    def read(self, size=-1):
        if self.first:
            self.first = False
            return super().read(max(1, len(self.getvalue()) // 2))
        raise TimeoutError("simulated network read timeout")


class VerificationDownloadRetryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="hepta-download-tests-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name) / "repo"
        (self.root / "formal").mkdir(parents=True)
        self.parent = Path(self.directory.name) / "installed"
        self.parent.mkdir()
        self.binary = b"small fixture executable bytes; never executed\n"
        self.package = b"small simulated deb payload; extraction is separately stubbed\n"
        self.qemu_url = "https://locked.invalid/qemu.deb"
        self.qemu_metadata = {"source": self.qemu_url, "package_sha256": digest(self.package),
                              "binary_sha256": digest(self.binary)}
        self.write_qemu_metadata()
        self.stderr = io.StringIO()
        root_patch = patch.object(bootstrap, "ROOT", self.root)
        root_patch.start()
        self.addCleanup(root_patch.stop)
        sleep_patch = patch.object(bootstrap.time, "sleep")
        self.sleep = sleep_patch.start()
        self.addCleanup(sleep_patch.stop)

    def write_qemu_metadata(self):
        (self.root / "formal/qemu-toolchain-lock.json").write_text(json.dumps(self.qemu_metadata))

    def process(self, binary=None):
        process = Mock()
        process.stdout = io.BytesIO(tar_bytes({"./usr/bin/qemu-aarch64-static": self.binary if binary is None else binary}))
        process.wait.return_value = process.poll.return_value = 0
        return process

    def install_qemu(self, responses, *, binary=None):
        with patch.object(bootstrap.urllib.request, "urlopen", side_effect=responses) as opened, \
             patch.object(bootstrap.shutil, "which", return_value="/fixture/dpkg-deb"), \
             patch.object(bootstrap.subprocess, "Popen", return_value=self.process(binary)) as unpack, \
             redirect_stderr(self.stderr):
            result = bootstrap.install_qemu(self.parent)
        return Path(result), opened, unpack

    def http_error(self, code):
        return urllib.error.HTTPError(self.qemu_url, code, "simulated status", {}, None)

    def test_503_then_payload_keeps_locked_url_checksums_and_atomic_publish(self):
        result, opened, unpack = self.install_qemu([self.http_error(503), io.BytesIO(self.package)])
        self.assertEqual(result.read_bytes(), self.binary)
        self.assertEqual(bootstrap.sha(result), self.qemu_metadata["binary_sha256"])
        self.assertEqual(opened.call_args_list, [call(self.qemu_url, timeout=60)] * 2)
        self.assertEqual(self.sleep.call_args_list, [call(1)])
        self.assertEqual(unpack.call_count, 1)
        self.assertEqual([path.name for path in self.parent.iterdir()], ["qemu-8.2.2"])
        diagnostics = [json.loads(line) for line in self.stderr.getvalue().splitlines()]
        self.assertEqual([row["attempt"] for row in diagnostics if row["event"] == "download_attempt"], [1, 2])
        failure = next(row for row in diagnostics if row["event"] == "download_transient_failure")
        self.assertEqual(failure["http_status"], 503)
        self.assertEqual(failure["retry_after_seconds"], 1)
        self.assertIs(failure["exhausted"], False)

    def test_transient_failure_exhausts_exact_bound_and_leaves_no_target(self):
        with patch.object(bootstrap.urllib.request, "urlopen", side_effect=[self.http_error(503) for _ in range(4)]) as opened, \
             patch.object(bootstrap.shutil, "which", return_value="/fixture/dpkg-deb"), \
             patch.object(bootstrap.subprocess, "Popen") as unpack, redirect_stderr(self.stderr):
            with self.assertRaises(urllib.error.HTTPError) as caught:
                bootstrap.install_qemu(self.parent)
        self.assertEqual(caught.exception.code, 503)
        self.assertEqual(opened.call_args_list, [call(self.qemu_url, timeout=60)] * 4)
        self.assertEqual(self.sleep.call_args_list, [call(1), call(2), call(4)])
        unpack.assert_not_called()
        self.assertEqual(list(self.parent.iterdir()), [])
        final = json.loads(self.stderr.getvalue().splitlines()[-1])
        self.assertIs(final["exhausted"], True)
        self.assertIsNone(final["retry_after_seconds"])
        self.assertEqual(final["attempt"], 4)

    def test_nontransient_http_certificate_dns_and_unstructured_errors_do_not_retry(self):
        errors = [self.http_error(code) for code in (400, 401, 403, 404, 501)] + [
            urllib.error.URLError(ssl.SSLCertVerificationError(1, "certificate verify failed")),
            ssl.SSLCertVerificationError(1, "certificate verify failed"),
            urllib.error.URLError(socket.gaierror(socket.EAI_NONAME, "unknown host")),
            urllib.error.URLError("timeout text without a structured timeout identity"),
        ]
        for error in errors:
            with self.subTest(error=repr(error)), \
                 patch.object(bootstrap.urllib.request, "urlopen", side_effect=error) as opened, \
                 patch.object(bootstrap.shutil, "which", return_value="/fixture/dpkg-deb"), \
                 patch.object(bootstrap.subprocess, "Popen") as unpack, redirect_stderr(self.stderr):
                with self.assertRaises(type(error)):
                    bootstrap.install_qemu(self.parent)
                self.assertEqual(opened.call_count, 1)
                unpack.assert_not_called()
                self.sleep.assert_not_called()
                self.assertEqual(list(self.parent.iterdir()), [])

    def test_allowed_structured_network_failures_retry_but_disk_timeout_does_not(self):
        errors = [self.http_error(code) for code in sorted(bootstrap.TRANSIENT_HTTP_STATUS)] + [
            TimeoutError("connect timeout"), ConnectionResetError("connection reset"),
            ConnectionAbortedError("connection aborted"),
            urllib.error.URLError(TimeoutError("wrapped connect timeout")),
            urllib.error.URLError(socket.gaierror(socket.EAI_AGAIN, "temporary DNS failure")),
        ]
        for error in errors:
            with self.subTest(error=repr(error)), \
                 patch.object(bootstrap.urllib.request, "urlopen", side_effect=[error, io.BytesIO(b"body")]) as opened, \
                 redirect_stderr(self.stderr):
                def download():
                    with bootstrap._download_response(self.qemu_url) as response:
                        return response.read()
                self.assertEqual(bootstrap._retry_download("fixture", download), b"body")
                self.assertEqual(opened.call_count, 2)
        self.sleep.reset_mock()
        disk_action = Mock(side_effect=TimeoutError("fixture filesystem write timeout"))
        with redirect_stderr(self.stderr), self.assertRaises(TimeoutError):
            bootstrap._retry_download("fixture", disk_action)
        self.assertEqual(disk_action.call_count, 1)
        self.sleep.assert_not_called()

    def test_partial_qemu_response_is_discarded_before_full_retry(self):
        interrupted = InterruptedResponse(self.package)
        result, opened, unpack = self.install_qemu([interrupted, io.BytesIO(self.package)])
        self.assertTrue(interrupted.closed)
        self.assertEqual(result.read_bytes(), self.binary)
        self.assertEqual(opened.call_count, 2)
        self.assertEqual(unpack.call_count, 1)
        self.assertEqual(self.sleep.call_args_list, [call(1)])
        self.assertEqual([path.name for path in self.parent.iterdir()], ["qemu-8.2.2"])

    def test_package_and_executable_checksum_errors_never_retry_or_publish(self):
        for damaged_package, damaged_binary in ((True, False), (False, True)):
            self.sleep.reset_mock()
            with self.subTest(package=damaged_package), \
                 patch.object(bootstrap.urllib.request, "urlopen", return_value=io.BytesIO(b"damaged" if damaged_package else self.package)) as opened, \
                 patch.object(bootstrap.shutil, "which", return_value="/fixture/dpkg-deb"), \
                 patch.object(bootstrap.subprocess, "Popen", return_value=self.process(b"damaged" if damaged_binary else self.binary)) as unpack, \
                 patch.object(bootstrap.os, "replace") as publish, redirect_stderr(self.stderr):
                with self.assertRaises(RuntimeError):
                    bootstrap.install_qemu(self.parent)
                self.assertEqual(opened.call_count, 1)
                self.assertEqual(unpack.call_count, 0 if damaged_package else 1)
                self.sleep.assert_not_called()
                publish.assert_not_called()
                self.assertEqual(list(self.parent.iterdir()), [])

    def lean_archive(self):
        # The existing optional installer dependency performs real tiny zstd
        # decompression here. No Lean binary or compiler is executed.
        import zstandard
        files = {name: b"small fixture " + name.encode() for name in (
            "bin/lean", "lib/lean/libInit_shared.so", "lib/lean/libleanshared.so",
            "lib/lean/libleanshared_1.so", "lib/lean/Init.olean")}
        payload = zstandard.ZstdCompressor().compress(tar_bytes({"lean-4.19.0/" + name: data for name, data in files.items()}))
        metadata = {"url": "https://locked.invalid/lean.tar.zst", "archive_sha256": digest(payload),
                    "lean_binary_sha256": digest(files["bin/lean"])}
        (self.root / "formal/toolchain-lock.json").write_text(json.dumps(metadata))
        (self.root / "formal/proof-dependencies.txt").write_text("Init.olean\n")
        return payload, files, metadata

    @unittest.skipUnless(importlib.util.find_spec("zstandard"), "optional Lean installer dependency zstandard")
    def test_lean_stream_restarts_digest_and_staging_after_503_or_read_timeout(self):
        for kind in ("503", "read_timeout"):
            payload, files, metadata = self.lean_archive()
            first = urllib.error.HTTPError(metadata["url"], 503, "fixture", {}, None) if kind == "503" else InterruptedResponse(payload)
            with self.subTest(kind=kind), tempfile.TemporaryDirectory(dir=self.parent) as parent, \
                 patch.object(bootstrap.urllib.request, "urlopen", side_effect=[first, io.BytesIO(payload)]) as opened, \
                 redirect_stderr(self.stderr):
                result = Path(bootstrap.install_lean(Path(parent)))
                self.assertEqual(result.read_bytes(), files["bin/lean"])
                self.assertEqual(opened.call_args_list, [call(metadata["url"], timeout=60)] * 2)
                self.assertEqual([path.name for path in Path(parent).iterdir()], ["lean-4.19.0"])
                for name, data in files.items():
                    self.assertEqual((result.parent.parent / name).read_bytes(), data)

    @unittest.skipUnless(importlib.util.find_spec("zstandard"), "optional Lean installer dependency zstandard")
    def test_lean_archive_checksum_failure_never_retries_or_publishes(self):
        payload, _, metadata = self.lean_archive()
        metadata["archive_sha256"] = "0" * 64
        (self.root / "formal/toolchain-lock.json").write_text(json.dumps(metadata))
        with patch.object(bootstrap.urllib.request, "urlopen", return_value=io.BytesIO(payload)) as opened, \
             patch.object(bootstrap.os, "replace") as publish, redirect_stderr(self.stderr):
            with self.assertRaisesRegex(RuntimeError, "archive identity"):
                bootstrap.install_lean(self.parent)
            self.assertEqual(opened.call_count, 1)
            self.sleep.assert_not_called()
            publish.assert_not_called()
            self.assertEqual(list(self.parent.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
