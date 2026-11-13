"""Frozen small format/IO controls; no network, provider, supplier or product.

These controls are a separate proposed source-only invocation. Merely freezing
this file does not claim they passed, or that any of the ten parts were read.
"""
from pathlib import Path
from hashlib import sha256
import gzip
import importlib.util
import io
import json
import os
import stat
import struct
import sys
import tarfile
import tempfile
import types
import unittest
from unittest.mock import patch
import zipfile
import zlib

ROOT = Path(__file__).resolve().parent.parent
def load(name):
    spec = importlib.util.spec_from_file_location('stream_control_' + name, ROOT / 'control' / (name + '.py'))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module
fmt, local = load('stream_format'), load('local_io')

class NonSeekable(io.BytesIO):
    def seekable(self):
        return False
    def seek(self, *args):
        raise io.UnsupportedOperation('nonseekable fixture')

def zip_fixture(descriptors=False, force_zip64=False):
    names = ['hia-v87-full-public/FINAL.json', 'hia-v87-full-public/ORIGINAL-CATALOG.json',
             'hia-v87-full-public/CUSTODY.json', fmt.TAR_NAME]
    output = NonSeekable() if descriptors else io.BytesIO()
    with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_STORED) as archive:
        for i, name in enumerate(names):
            info = zipfile.ZipInfo(name, (2026, 11, 12, 1, 2, 4)); info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o600) << 16
            with archive.open(info, 'w', force_zip64=force_zip64) as stream:
                stream.write((('value-%d-' % i).encode() * (i + 1)))
    raw = output.getvalue(); directory = []; inventory = []
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        for index, info in enumerate(archive.infolist()):
            body = archive.read(info)
            directory.append({'index': index, 'name': info.filename, 'kind': 'regular',
                'compressed_bytes': info.compress_size, 'uncompressed_bytes': info.file_size,
                'compression': info.compress_type, 'flags': info.flag_bits, 'header_offset': info.header_offset,
                'crc32_from_directory': info.CRC, 'date_time': list(info.date_time),
                'create_version': info.create_version, 'create_system': info.create_system,
                'extract_version': info.extract_version, 'external_attr': info.external_attr,
                'internal_attr': info.internal_attr, 'extra_hex': info.extra.hex(), 'comment_hex': info.comment.hex()})
            inventory.append({'path': info.filename, 'kind': 'regular', 'bytes': len(body),
                              'sha256': sha256(body).hexdigest(), 'crc32': '%08x' % info.CRC})
    return raw, {'members': directory, 'declared_total_bytes': sum(x['bytes'] for x in inventory)}, {'complete': True, 'files': inventory}

def read_zip(raw, directory, inventory, width=7, consumer=None):
    stream = fmt.ChunkReader((raw[i:i + width] for i in range(0, len(raw), width)), len(raw) + 1)
    records = []
    def consume(name, body, expected):
        while body.read(fmt.CHUNK):
            pass
    result = fmt.original_zip(stream, directory, inventory, consumer or consume, records.append, {})
    return result, records

def gzip_read(raw, decoded, *, compressed_sha=None, expected_raw_sha=None):
    state = {}
    output = b''.join(fmt.gzip_chunks(io.BytesIO(raw), compressed_bytes=len(raw),
        compressed_sha256=compressed_sha or sha256(raw).hexdigest(), raw_limit=len(decoded),
        raw_bytes=len(decoded), raw_sha256=expected_raw_sha or sha256(decoded).hexdigest(), state=state))
    return output, state

def tar_fixture(*, wrong_body=False, nonzero_after_end=False, special=False):
    stamp = 1700000000
    rows = [{'path': '.', 'kind': 'directory', 'identity': [1, 1, stat.S_IFDIR | 0o700, 1000, 1000, 2, 4096, stamp * 10**9, stamp * 10**9]},
            {'path': 'a', 'kind': 'directory', 'identity': [1, 2, stat.S_IFDIR | 0o700, 1000, 1000, 2, 4096, stamp * 10**9, stamp * 10**9]},
            {'path': 'a/body', 'kind': 'regular', 'identity': [1, 3, stat.S_IFREG | 0o600, 1000, 1000, 1, 3, stamp * 10**9, stamp * 10**9],
             'bytes': 3, 'sha256': sha256(b'abc').hexdigest()}]
    if special:
        rows.append({'path': 'a/pipe', 'kind': 'fifo', 'identity': [1, 4, stat.S_IFIFO | 0o600, 1000, 1000, 1, 0, stamp * 10**9, stamp * 10**9]})
    catalog = {'schema': 'hia.v87.full-retained-typed-custody.v1', 'originals': rows,
               'unreadable_regular_paths': [], 'unlisted_directory_paths': []}
    catalog_raw = (json.dumps(catalog, sort_keys=True) + '\n').encode()
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w', format=tarfile.PAX_FORMAT) as archive:
        for row in rows[1:]:
            info = tarfile.TarInfo(row['path']); info.mode = stat.S_IMODE(row['identity'][2])
            info.uid = info.gid = 1000; info.mtime = stamp
            if row['kind'] == 'directory':
                info.type = tarfile.DIRTYPE; archive.addfile(info)
            elif row['kind'] == 'fifo':
                info.type = tarfile.FIFOTYPE; archive.addfile(info)
            else:
                info.size = 3; archive.addfile(info, io.BytesIO(b'abX' if wrong_body else b'abc'))
        info = tarfile.TarInfo(fmt.CATALOG_NAME); info.size = len(catalog_raw)
        archive.addfile(info, io.BytesIO(catalog_raw))
    plain = buffer.getvalue()
    if nonzero_after_end:
        # Last TAR body is padded to 512; plant data after the first zero terminal block.
        data_blocks = (len(catalog_raw) + 511) // 512
        terminal = 512 + 512 + 512 + (512 if special else 0) + 512 + data_blocks * 512
        plain = plain[:terminal + 512] + b'X' + plain[terminal + 513:]
    compressed = gzip.compress(plain, compresslevel=1, mtime=0)
    custody = {'archive': {'bytes': len(compressed), 'sha256': sha256(compressed).hexdigest()},
               'catalog': {'bytes': len(catalog_raw), 'sha256': sha256(catalog_raw).hexdigest()},
               'original_members': len(rows), 'archive_members': len(rows), 'regular_bytes': 3,
               'unreadable_regular_paths': [], 'unlisted_directory_paths': []}
    return compressed, catalog_raw, custody

def read_tar(args, capture=lambda name, row: None):
    raw, catalog, custody = args
    records = []
    result = fmt.inner_tar(io.BytesIO(raw), catalog, custody, records.append, capture, {})
    return result, records

class StreamFormatControls(unittest.TestCase):
    def test_01_stored_complete_zip(self):
        raw, directory, inventory = zip_fixture()
        report, rows = read_zip(raw, directory, inventory)
        self.assertEqual(report['whole_ZIP_sha256'], sha256(raw).hexdigest())
        self.assertEqual(len(rows), 4)
        self.assertTrue(all(row['whole_body_independently_read'] for row in rows))
    def test_02_signed_data_descriptors(self):
        raw, directory, inventory = zip_fixture(descriptors=True)
        report, rows = read_zip(raw, directory, inventory)
        self.assertEqual(report['whole_ZIP_bytes'], len(raw))
        self.assertTrue(all(row['descriptor_hex'].startswith('504b0708') for row in rows))
    def test_03_zip64_local_headers(self):
        raw, directory, inventory = zip_fixture(descriptors=True, force_zip64=True)
        _, rows = read_zip(raw, directory, inventory)
        self.assertTrue(all(len(bytes.fromhex(row['descriptor_hex'])) == 24 for row in rows))
    def test_04_every_boundary_chunk(self):
        raw, directory, inventory = zip_fixture(descriptors=True)
        for width in (1, 2, 7, 31, 512, 65536):
            with self.subTest(width=width):
                report, _ = read_zip(raw, directory, inventory, width)
                self.assertEqual(report['whole_ZIP_sha256'], sha256(raw).hexdigest())
    def test_05_truncated_original_stops(self):
        raw, directory, inventory = zip_fixture()
        with self.assertRaises(fmt.Refusal): read_zip(raw[:100], directory, inventory)
    def test_06_descriptor_corruption_rejected(self):
        raw, directory, inventory = zip_fixture(descriptors=True)
        index = raw.index(b'PK\x07\x08') + 4
        changed = raw[:index] + bytes([raw[index] ^ 1]) + raw[index + 1:]
        with self.assertRaises(fmt.Refusal): read_zip(changed, directory, inventory)
    def test_07_central_metadata_corruption_rejected(self):
        raw, directory, inventory = zip_fixture()
        index = raw.index(b'PK\x01\x02') + 16
        changed = raw[:index] + bytes([raw[index] ^ 1]) + raw[index + 1:]
        with self.assertRaises(fmt.Refusal): read_zip(changed, directory, inventory)
    def test_08_missing_end_record_rejected(self):
        raw, directory, inventory = zip_fixture()
        with self.assertRaises(fmt.Refusal): read_zip(raw[:-22], directory, inventory)
    def test_09_bytes_after_end_rejected(self):
        raw, directory, inventory = zip_fixture()
        with self.assertRaises(fmt.Refusal): read_zip(raw + b'x', directory, inventory)
    def test_10_duplicate_directory_names_rejected(self):
        raw, directory, inventory = zip_fixture()
        directory['members'][1]['name'] = directory['members'][0]['name']
        with self.assertRaises(fmt.Refusal): read_zip(raw, directory, inventory)
        raw, directory, inventory = zip_fixture()
        inventory['files'].append(dict(inventory['files'][0]))
        with self.assertRaises(fmt.Refusal): read_zip(raw, directory, inventory)
    def test_11_overlap_or_gap_rejected(self):
        raw, directory, inventory = zip_fixture()
        directory['members'][1]['header_offset'] -= 1
        with self.assertRaises(fmt.Refusal): read_zip(raw, directory, inventory)
    def test_12_single_gzip_full_read(self):
        data = bytes(range(256)) * 8193
        actual, report = gzip_read(gzip.compress(data, mtime=0), data)
        self.assertEqual(actual, data); self.assertTrue(report['complete'])
    def test_13_gzip_crc_corruption_rejected(self):
        raw = bytearray(gzip.compress(b'abc', mtime=0)); raw[-8] ^= 1
        with self.assertRaises((fmt.Refusal, zlib.error)): gzip_read(bytes(raw), b'abc')
    def test_14_second_gzip_stream_rejected(self):
        raw = gzip.compress(b'abc', mtime=0) + gzip.compress(b'def', mtime=0)
        with self.assertRaises(fmt.Refusal): gzip_read(raw, b'abcdef')
    def test_15_raw_range_hash_is_not_inherited(self):
        with self.assertRaises(fmt.Refusal): gzip_read(gzip.compress(b'abc', mtime=0), b'abc', expected_raw_sha='0' * 64)
    def test_16_inner_all_bodies_and_embedded_catalog(self):
        report, rows = read_tar(tar_fixture())
        self.assertEqual(report['TAR_members'], 3)
        self.assertEqual(report['regular_bytes'], 3)
        self.assertEqual({r['path'] for r in rows}, {'a', 'a/body', fmt.CATALOG_NAME})
    def test_17_inner_body_mismatch_rejected(self):
        with self.assertRaises(fmt.Refusal): read_tar(tar_fixture(wrong_body=True))
    def test_18_buffered_nonzero_tar_tail_rejected(self):
        with self.assertRaises(fmt.Refusal): read_tar(tar_fixture(nonzero_after_end=True))
    def test_19_special_original_is_metadata_only(self):
        calls = []
        report, rows = read_tar(tar_fixture(special=True), lambda name, row: calls.append(name))
        self.assertEqual(calls, ['a/body'])
        self.assertFalse(report['special_nodes_opened_or_extracted'])
        self.assertEqual(next(r for r in rows if r['path'] == 'a/pipe')['kind'], 'fifo')
    def test_20_original_callback_exception_stops(self):
        sentinel = RuntimeError('fixed consumer stopped')
        def failed(name, row): raise sentinel
        try: read_tar(tar_fixture(), failed)
        except RuntimeError as got: self.assertIs(got, sentinel)
        else: self.fail('exception suppressed')

class LocalBoundaryControls(unittest.TestCase):
    def limits(self):
        return {'metadata_bytes': 1000, 'captured_original_bytes': 2000,
                'parent_metadata_bytes': 100, 'filesystem_reserve_bytes': 500}
    def test_21_unwritten_reservation_still_requires_free_space(self):
        status = types.SimpleNamespace(f_bavail=5000, f_frsize=1, f_favail=4096)
        with patch.object(local.os, 'statvfs', return_value=status):
            budget = local.Budget('/fixed', {'limits': self.limits()})
            before = budget.capacity()['remaining_persistent_reservation']
            budget.reserve(1200, 'original')
            self.assertEqual(budget.capacity()['remaining_persistent_reservation'], before)
            budget.wrote(100, 'original')
            self.assertEqual(budget.capacity()['remaining_persistent_reservation'], before - 100)
            status.f_bavail = 2000
            with self.assertRaises(local.Refusal): budget.capacity()
        for elapsed in (True, False, float('nan'), float('inf'), -0.01, 720.0001):
            with self.subTest(elapsed=repr(elapsed)), self.assertRaises(local.Refusal):
                local.require_elapsed(elapsed, 720)
        local.require_elapsed(0, 720)
        local.require_elapsed(720.0, 720)
        with patch.object(local.time, 'monotonic', return_value=721):
            with self.assertRaises(local.Refusal): local.check_deadline(720)
    def test_22_provider_host_and_auth_boundary(self):
        self.assertEqual(local.provider_host('https://sdmntprfixture.oaiusercontent.com/a?q=signed'), 'sdmntprfixture.oaiusercontent.com')
        for url in ('http://sdmntprfixture.oaiusercontent.com/a', 'https://user:secret@sdmntprfixture.oaiusercontent.com/a',
                    'https://evil.invalid/a', 'https://sdmntprfixture.oaiusercontent.com:444/a'):
            with self.subTest(url=url), self.assertRaises(local.Refusal): local.provider_host(url)
    def test_23_configured_proxy_kept_or_rejected_before_serialization(self):
        operation = '/tmp/source-only-private-proxy-fixture'
        inherited = {'HTTPS_PROXY': 'http://user:fixture-secret@proxy.invalid:3128',
                     'HTTP_PROXY': 'http://proxy.invalid:3128',
                     'ALL_PROXY': 'socks5h://unused.invalid:1080',
                     'all_proxy': 'socks5h://other-unused.invalid:1080',
                     'NO_PROXY': '.internal.invalid:443,loop.invalid',
                     'SSL_CERT_FILE': '/fixed/original-ca.pem'}
        configuration = local.capture_proxy_configuration(operation, inherited)
        public = local.configured_environment(configuration, inherited)
        self.assertEqual(configuration['effective_proxies']['https'], inherited['HTTPS_PROXY'])
        self.assertEqual(configuration['effective_proxies']['all'], inherited['all_proxy'])
        self.assertEqual(public['SSL_CERT_FILE'], inherited['SSL_CERT_FILE'])
        self.assertFalse(any(local._is_proxy_key(key) for key in public))
        self.assertNotIn('HOME', public)
        self.assertNotIn('fixture-secret', json.dumps(public))
        self.assertNotIn('socks5h', json.dumps(public))
        drift = dict(inherited, HTTPS_PROXY='http://other.invalid:3128')
        with self.assertRaises(local.Refusal): local.configured_environment(configuration, drift)
        for environment, expected in (
            ({'HTTP_PROXY': 'http://upper.invalid', 'http_proxy': 'http://lower.invalid'},
             {'http': 'http://lower.invalid'}),
            ({'HTTP_PROXY': 'http://upper.invalid', 'http_proxy': ''}, {}),
            ({'HTTP_PROXY': 'http://upper.invalid', 'REQUEST_METHOD': 'POST'}, {}),
            ({'HTTP_PROXY': 'http://upper.invalid', 'http_proxy': 'http://lower.invalid',
              'REQUEST_METHOD': 'POST'}, {'http': 'http://lower.invalid'}),
            ({'ALL_PROXY': 'socks5h://unused.invalid:1080'}, {'all': 'socks5h://unused.invalid:1080'}),
        ):
            with self.subTest(environment_keys=list(environment)):
                self.assertEqual(local.capture_proxy_configuration(operation, environment)['effective_proxies'], expected)
        for value in ('http://user:fixture-secret@proxy.invalid:99999',
                      'http://proxy.invalid:3128?secret=fixture-secret',
                      'http://proxy.invalid:3128#fixture-secret', 'http://proxy.invalid/other',
                      'http://proxy.invalid:3128\nfixture-secret'):
            with self.subTest(value_hash=sha256(value.encode()).hexdigest()):
                with self.assertRaises(local.Refusal) as error:
                    local.capture_proxy_configuration(operation, {'HTTPS_PROXY': value})
                self.assertNotIn('fixture-secret', str(error.exception))
        changed = json.loads(json.dumps(configuration))
        changed['effective_proxies']['https'] = 'http://other.invalid'
        with self.assertRaises(local.Refusal): local.validate_proxy_configuration(changed, operation)
        changed = json.loads(json.dumps(configuration))
        changed['proxy_rows'].append(changed['proxy_rows'][0])
        with self.assertRaises(local.Refusal): local.validate_proxy_configuration(changed, operation)
        with tempfile.TemporaryDirectory(prefix='stream-private-proxy-source-control-') as name:
            root = Path(name); private = root / 'network.json'
            pin = local.create(private, configuration)
            actual, actual_pin = local.read_private_proxy(private, operation, pin['sha256'])
            self.assertEqual(actual, configuration); self.assertEqual(actual_pin, pin)
            self.assertEqual(stat.S_IMODE(private.stat().st_mode), 0o600)
            self.assertNotIn('fixture-secret', json.dumps(pin))
            with self.assertRaises(local.Refusal): local.read_private_proxy(private, operation, '0' * 64)
            private.chmod(0o644)
            with self.assertRaises(local.Refusal): local.read_private_proxy(private, operation, pin['sha256'])
            private.chmod(0o600)
            alias = root / 'alias.json'; os.link(private, alias)
            with self.assertRaises(local.Refusal): local.read_private_proxy(private, operation, pin['sha256'])
            alias.unlink()
            link = root / 'link.json'; link.symlink_to(private.name)
            with self.assertRaises(local.Refusal): local.read_private_proxy(link, operation, pin['sha256'])
        # All URLs below are inert synthetic values. No socket or opener.open.
        proxy = configuration['effective_proxies']['https']
        handler = local.ConfiguredProxyHandler(dict(configuration['effective_proxies']))
        request = local.urllib.request.Request('https://service.invalid/whole-original')
        with patch.dict(os.environ, {'NO_PROXY': '*'}, clear=True):
            self.assertIsNone(handler.proxy_open(request, proxy, 'https'))
        self.assertEqual(request.host, 'proxy.invalid:3128')
        self.assertEqual(request._tunnel_host, 'service.invalid')
        self.assertEqual(request.get_header('Proxy-authorization'),
                         'Basic ' + local.base64.b64encode(b'user:fixture-secret').decode('ascii'))
        self.assertIsNone(request.get_header('Authorization'))
        bypass = local.urllib.request.Request('https://child.internal.invalid:443/a')
        self.assertIsNone(handler.proxy_open(bypass, proxy, 'https'))
        self.assertEqual(bypass.host, 'child.internal.invalid:443')
        self.assertIsNone(bypass.get_header('Proxy-authorization'))
        self.assertFalse(local.urllib.request.proxy_bypass_environment('notinternal.invalid:443', handler.proxies))
        sentinel = RuntimeError('synthetic proxy failure')
        request = local.urllib.request.Request('https://service.invalid/whole-original')
        with patch.object(request, 'set_proxy', side_effect=sentinel):
            try: handler.proxy_open(request, proxy, 'https')
            except RuntimeError as got: self.assertIs(got, sentinel)
            else: self.fail('proxy failure was suppressed or redirected to a fallback')
        context = types.SimpleNamespace(check_hostname=True, verify_mode=local.ssl.CERT_REQUIRED)
        with patch.dict(os.environ, public, clear=True), \
             patch.object(local.ssl, 'create_default_context', return_value=context) as tls, \
             patch.object(local.urllib.request, 'build_opener', side_effect=lambda *handlers: handlers):
            handlers = local.configured_provider_client(configuration, {'redirects': []}, 720)
            self.assertEqual(handlers[0].proxies, configuration['effective_proxies'])
            self.assertIs(handlers[1]._context, context)
            tls.assert_called_once_with()
        with patch.dict(os.environ, {**public, 'HTTPS_PROXY': proxy}, clear=True):
            with self.assertRaises(local.Refusal): local.configured_provider_client(configuration, {}, 720)
        with patch.dict(os.environ, {**public, 'SSL_CERT_FILE': '/different-ca.pem'}, clear=True):
            with self.assertRaises(local.Refusal): local.configured_provider_client(configuration, {}, 720)
        unsafe_error = local.urllib.error.URLError('http://user:fixture-secret@proxy.invalid')
        self.assertNotIn('fixture-secret', json.dumps(local.safe_error(unsafe_error)))
    def test_24_only_exact_verified_temporary_can_be_disposed(self):
        with tempfile.TemporaryDirectory(prefix='stream-consumer-source-control-') as name:
            root = Path(name); path = root / 'official-part.original.zip'; path.write_bytes(b'fixture')
            expected = local.seal(path, 1024)
            class FakeBudget:
                def reserve(self, *args): pass
                def wrote(self, *args): pass
            with self.assertRaises(local.Refusal): local.dispose_verified_temporary(root / 'old-original.zip', expected, root, FakeBudget())
            changed = dict(expected); changed['identity'] = list(expected['identity']); changed['identity'][1] += 1
            with self.assertRaises(local.Refusal): local.dispose_verified_temporary(path, changed, root, FakeBudget())
            self.assertTrue(path.exists())
            local.dispose_verified_temporary(path, expected, root, FakeBudget())
            self.assertFalse(path.exists())
            self.assertTrue(json.loads((root / 'TEMPORARY-DISPOSAL-ACK.json').read_bytes())['absent_observed'])

if __name__ == '__main__':
    unittest.main(verbosity=2)
