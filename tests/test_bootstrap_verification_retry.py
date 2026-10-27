"""Regression controls for fail-closed downloads of hash-pinned QEMU packages."""
import hashlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import urllib.error

from tools import bootstrap_verification as bootstrap

URL = "https://snapshot.ubuntu.com/ubuntu/20260828T000000Z/pool/universe/q/qemu/qemu-user-static_8.2.2+ds-0ubuntu1.18_amd64.deb"
FALLBACK_URL = "https://security.ubuntu.com/ubuntu/pool/universe/q/qemu/qemu-user-static_8.2.2+ds-0ubuntu1.18_amd64.deb"


def http_error(code):
    return urllib.error.HTTPError(URL, code, "test", None, None)


class DownloadQemuTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.package = Path(self.temp.name) / "qemu.deb"
        self.data = b"archive content is an exact pinned identity"
        self.digest = hashlib.sha256(self.data).hexdigest()

    def test_503_then_success_preserves_hash_and_source(self):
        with patch.object(bootstrap.urllib.request, "urlopen", side_effect=[
            http_error(503), io.BytesIO(self.data)
        ]) as urlopen, patch.object(bootstrap.time, "sleep") as sleep:
            bootstrap.download_qemu_package(URL, self.package, self.digest)
        self.assertEqual(self.package.read_bytes(), self.data)
        self.assertEqual(urlopen.call_count, 2)
        self.assertEqual(urlopen.call_args_list[0].args[0], URL)
        self.assertEqual(urlopen.call_args_list[1].args[0], URL)
        sleep.assert_called_once_with(1)

    def test_429_then_502_then_success_is_bounded(self):
        with patch.object(bootstrap.urllib.request, "urlopen", side_effect=[
            http_error(429), http_error(502), io.BytesIO(self.data)
        ]) as request, patch.object(bootstrap.time, "sleep") as sleep:
            bootstrap.download_qemu_package(URL, self.package, self.digest)
        self.assertEqual(request.call_count, 3)
        self.assertEqual([c.args for c in sleep.call_args_list], [(1,), (2,)])
        self.assertEqual(self.package.read_bytes(), self.data)

    def test_persistent_503_fails_closed_without_archive(self):
        with patch.object(bootstrap.urllib.request, "urlopen", side_effect=[
            http_error(503)
        ] * 3) as request, patch.object(bootstrap.time, "sleep") as sleep:
            with self.assertRaises(urllib.error.HTTPError) as caught:
                bootstrap.download_qemu_package(URL, self.package, self.digest)
        self.assertEqual(caught.exception.code, 503)
        self.assertEqual(request.call_count, 3)
        self.assertEqual(sleep.call_count, 2)
        self.assertFalse(self.package.exists())

    def test_404_not_retried(self):
        with patch.object(bootstrap.urllib.request, "urlopen",
                          side_effect=http_error(404)) as request, \
                patch.object(bootstrap.time, "sleep") as sleep:
            with self.assertRaises(urllib.error.HTTPError):
                bootstrap.download_qemu_package(URL, self.package, self.digest)
        self.assertEqual(request.call_count, 1)
        sleep.assert_not_called()
        self.assertFalse(self.package.exists())

    def test_mismatched_sha_not_retried(self):
        with patch.object(bootstrap.urllib.request, "urlopen",
                          return_value=io.BytesIO(b"wrong bytes")) as request, \
                patch.object(bootstrap.time, "sleep") as sleep:
            with self.assertRaisesRegex(RuntimeError, "checksum mismatch"):
                bootstrap.download_qemu_package(URL, self.package, self.digest)
        self.assertEqual(request.call_count, 1)
        sleep.assert_not_called()
        self.assertFalse(self.package.exists())

    def test_non_http_transport_failure_not_retried(self):
        with patch.object(bootstrap.urllib.request, "urlopen",
                          side_effect=OSError("broken stream")) as request, \
                patch.object(bootstrap.time, "sleep") as sleep:
            with self.assertRaises(OSError):
                bootstrap.download_qemu_package(URL, self.package, self.digest)
        self.assertEqual(request.call_count, 1)
        sleep.assert_not_called()
        self.assertFalse(self.package.exists())


    def test_official_mirror_after_persistent_503(self):
        with patch.object(bootstrap.urllib.request, "urlopen",
                          side_effect=[http_error(503)] * 3 + [io.BytesIO(self.data)]) as fetch, \
                patch.object(bootstrap.time, "sleep") as sleep:
            bootstrap.download_qemu_package(URL, self.package, self.digest, FALLBACK_URL)
        self.assertEqual([call.args[0] for call in fetch.call_args_list],
                         [URL] * 3 + [FALLBACK_URL])
        self.assertEqual([call.args[0] for call in sleep.call_args_list], [1, 2])
        self.assertEqual(self.package.read_bytes(), self.data)

    def test_official_mirror_http_exhaustion_fails_closed(self):
        with patch.object(bootstrap.urllib.request, "urlopen",
                          side_effect=[http_error(503)] * 6) as fetch, \
                patch.object(bootstrap.time, "sleep") as sleep:
            with self.assertRaises(urllib.error.HTTPError):
                bootstrap.download_qemu_package(URL, self.package, self.digest, FALLBACK_URL)
        self.assertEqual([call.args[0] for call in fetch.call_args_list],
                         [URL] * 3 + [FALLBACK_URL] * 3)
        self.assertEqual([call.args[0] for call in sleep.call_args_list], [1, 2, 1, 2])
        self.assertFalse(self.package.exists())

    def test_official_mirror_checksum_mismatch_never_installed(self):
        with patch.object(bootstrap.urllib.request, "urlopen",
                          side_effect=[http_error(503)] * 3 + [io.BytesIO(b"incorrect")]) as fetch, \
                patch.object(bootstrap.time, "sleep"):
            with self.assertRaisesRegex(RuntimeError, "checksum mismatch"):
                bootstrap.download_qemu_package(URL, self.package, self.digest, FALLBACK_URL)
        self.assertEqual(fetch.call_count, 4)
        self.assertFalse(self.package.exists())

    def test_primary_404_does_not_try_official_mirror(self):
        with patch.object(bootstrap.urllib.request, "urlopen",
                          side_effect=http_error(404)) as fetch, \
                patch.object(bootstrap.time, "sleep") as sleep:
            with self.assertRaises(urllib.error.HTTPError):
                bootstrap.download_qemu_package(URL, self.package, self.digest, FALLBACK_URL)
        self.assertEqual(fetch.call_count, 1)
        sleep.assert_not_called()
        self.assertFalse(self.package.exists())

    def test_non_http_failure_does_not_try_official_mirror(self):
        with patch.object(bootstrap.urllib.request, "urlopen",
                          side_effect=OSError("broken stream")) as fetch, \
                patch.object(bootstrap.time, "sleep") as sleep:
            with self.assertRaises(OSError):
                bootstrap.download_qemu_package(URL, self.package, self.digest, FALLBACK_URL)
        self.assertEqual(fetch.call_count, 1)
        sleep.assert_not_called()
        self.assertFalse(self.package.exists())



if __name__ == "__main__":
    unittest.main()
