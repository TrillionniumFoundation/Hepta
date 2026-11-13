"""Fixed local custody IO and tokenless provider transport, not product IO."""
from pathlib import Path
import base64
import hashlib
import json
import math
import os
import stat
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

CHUNK = 1 << 20
class Refusal(Exception):
    pass
def require(value, message):
    if not value:
        raise Refusal(message)
def wire(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()
def json_value(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate JSON object key')
            result[key] = value
        return result
    def bad_constant(_):
        raise Refusal('non-finite JSON constant refused')
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=bad_constant)
def ident(s):
    return [s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid, s.st_nlink,
            s.st_size, s.st_mtime_ns, s.st_ctime_ns]
def safe_error(error):
    return {'type': type(error).__name__, 'errno': getattr(error, 'errno', None),
            'http_status': error.code if isinstance(error, urllib.error.HTTPError) else None,
            'fixed_refusal': str(error) if type(error) is Refusal else None}
def check_deadline(deadline):
    require(time.monotonic() < deadline, '720-second complete local reader deadline reached')

def require_elapsed(value, maximum):
    require(type(value) in (int, float) and math.isfinite(value) and 0 <= value <= maximum,
            'complete elapsed time is not finite or exceeds the unchanged deadline')

def seal(path, maximum, *, body=False, deadline=None):
    path = Path(path)
    old = path.lstat()
    require(stat.S_ISREG(old.st_mode) and old.st_nlink == 1 and old.st_size <= maximum,
            'bounded single-link regular file required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    digest, count, chunks = hashlib.sha256(), 0, []
    try:
        require(ident(os.fstat(fd)) == ident(old), 'opened original identity differs')
        while True:
            if deadline is not None:
                check_deadline(deadline)
            raw = os.read(fd, min(CHUNK, maximum + 1 - count))
            if not raw:
                break
            count += len(raw); require(count <= maximum, 'whole original exceeds fixed bound')
            digest.update(raw)
            if body:
                chunks.append(raw)
        require(count == old.st_size and ident(old) == ident(os.fstat(fd)) == ident(path.lstat()),
                'complete original read identity changed')
    finally:
        os.close(fd)
    result = {'path': str(path), 'bytes': count, 'sha256': digest.hexdigest(), 'identity': ident(old)}
    return (result, b''.join(chunks)) if body else result

class Budget:
    """Persistent bytes include the two whole omitted bodies and all new reports."""
    def __init__(self, root, policy):
        self.root, self.limits = Path(root), policy['limits']
        self.metadata_reserved, self.original_reserved = 0, 0
        self.metadata_written, self.original_written = 0, 0
    def capacity(self, upcoming=0):
        s = os.statvfs(self.root)
        # Reserving a whole future file does not mean its bytes occupy storage.
        # Keep all not-yet-written bytes in the physical free-space requirement.
        remaining = ((self.limits['metadata_bytes'] - self.metadata_written)
                     + (self.limits['captured_original_bytes'] - self.original_written)
                     + self.limits['parent_metadata_bytes'])
        require(s.f_bavail * s.f_frsize >= self.limits['filesystem_reserve_bytes'] + remaining + upcoming
                and s.f_favail >= 1024, 'fixed disk/inode reserve unavailable')
        return {'free_bytes': s.f_bavail * s.f_frsize, 'free_inodes': s.f_favail,
                'remaining_persistent_reservation': remaining, 'upcoming_bytes': upcoming}
    def reserve(self, count, category):
        require(type(count) is int and count >= 0, 'nonnegative whole-file reservation required')
        self.capacity()
        if category == 'metadata':
            require(self.metadata_reserved + count <= self.limits['metadata_bytes'], 'metadata bound exceeded')
            self.metadata_reserved += count
        elif category == 'original':
            require(self.original_reserved + count <= self.limits['captured_original_bytes'], 'whole original bound exceeded')
            self.original_reserved += count
        else:
            raise Refusal('unknown write budget category')
    def wrote(self, count, category):
        if category == 'metadata':
            self.metadata_written += count
            require(self.metadata_written <= self.metadata_reserved, 'unreserved metadata write')
        else:
            self.original_written += count
            require(self.original_written <= self.original_reserved, 'unreserved original write')

def create(path, value, *, raw=False, budget=None, category='metadata', deadline=None):
    if deadline is not None:
        check_deadline(deadline)
    body = value if raw else wire(value)
    if budget is not None:
        budget.reserve(len(body), category)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as out:
        out.write(body); out.flush(); os.fsync(out.fileno())
    if budget is not None:
        budget.wrote(len(body), category)
    record, actual = seal(path, max(len(body), 1), body=True, deadline=deadline)
    require(actual == body, 'new whole original readback differs')
    parent = os.open(Path(path).parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)
    if deadline is not None:
        check_deadline(deadline)
    return record

class Journal:
    def __init__(self, path, budget, maximum):
        self.path, self.budget, self.maximum = Path(path), budget, maximum
        self.count, self.lines, self.closed = 0, 0, False
        self.stream = os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), 'wb')
    def add(self, row):
        raw = (json.dumps(row, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()
        require(self.count + len(raw) <= self.maximum, 'complete journal bound exceeded')
        self.budget.reserve(len(raw), 'metadata')
        self.stream.write(raw); self.count += len(raw); self.lines += 1
        self.budget.wrote(len(raw), 'metadata')
        if self.lines % 128 == 0:
            self.stream.flush(); os.fsync(self.stream.fileno())
    def close(self):
        if not self.closed:
            self.stream.flush(); os.fsync(self.stream.fileno()); self.stream.close(); self.closed = True
    def finish(self, deadline=None):
        if deadline is not None:
            check_deadline(deadline)
        self.close()
        result = seal(self.path, self.maximum, deadline=deadline)
        result['complete_lines'] = self.lines
        return result

class OriginalCapture:
    def __init__(self, path, expected, budget, deadline, records):
        self.path, self.expected, self.budget, self.deadline, self.records = Path(path), expected, budget, deadline, records
        self.count, self.closed = 0, False
        budget.reserve(expected['bytes'], 'original')
        self.stream = os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), 'wb')
    def write(self, raw):
        check_deadline(self.deadline); self.budget.capacity()
        require(self.count + len(raw) <= self.expected['bytes'], 'complete selected body exceeds exact bound')
        self.stream.write(raw); self.count += len(raw)
        self.budget.wrote(len(raw), 'original')
    def close(self):
        if not self.closed:
            self.stream.flush(); os.fsync(self.stream.fileno()); self.stream.close(); self.closed = True
    def finish(self, count, digest):
        self.close()
        require(count == self.count == self.expected['bytes'] and digest == self.expected['sha256'],
                'selected whole original writer differs')
        actual = seal(self.path, self.expected['bytes'], deadline=self.deadline)
        require(actual['bytes'] == count and actual['sha256'] == digest, 'selected original independent full readback differs')
        self.records.append({'original_path': self.expected['path'], 'original_pin': self.expected,
                             'actual_complete_copy': actual, 'whole_original': True, 'truncated': False})

TRUST_KEYS = ('SSL_CERT_FILE', 'SSL_CERT_DIR', 'REQUESTS_CA_BUNDLE', 'CURL_CA_BUNDLE')
PROXY_SCHEMA = 'hia.full32.private-original-proxy-configuration.v1'

def _is_proxy_key(name):
    return len(name) > 5 and name[-6] == '_' and name[-5:].lower() == 'proxy'

def _effective_proxies(rows, request_method_present):
    """The pinned CPython getproxies_environment two passes, without globals."""
    proxies = {}
    for name, value in rows:
        if value:
            proxies[name[:-6].lower()] = value
    if request_method_present:
        proxies.pop('http', None)
    for name, value in rows:
        if name[-6:] == '_proxy':
            if value:
                proxies[name[:-6].lower()] = value
            else:
                proxies.pop(name[:-6].lower(), None)
    return proxies

def validate_proxy_configuration(value, operation_root):
    require(type(value) is dict and set(value) == {'schema', 'operation_root', 'proxy_rows',
                'request_method_present', 'effective_proxies', 'trust_environment'}
            and value['schema'] == PROXY_SCHEMA and value['operation_root'] == operation_root
            and type(value['request_method_present']) is bool,
            'private proxy configuration identity or fields differ')
    rows = value['proxy_rows']
    require(type(rows) is list and len(rows) <= 64, 'private proxy variable population differs')
    seen = set()
    for row in rows:
        require(type(row) is list and len(row) == 2 and all(type(x) is str for x in row),
                'private proxy variable shape differs')
        name, raw = row
        require(0 < len(name) <= 128 and name.isascii() and _is_proxy_key(name)
                and name not in seen and len(raw) <= 8192
                and not any(c in name + raw for c in ('\0', '\r', '\n')),
                'private proxy variable has an unsafe name, extent or control character')
        seen.add(name)
    effective = _effective_proxies(rows, value['request_method_present'])
    require(type(value['effective_proxies']) is dict and value['effective_proxies'] == effective,
            'private effective proxy map differs from the original environment rules')
    # urllib does not treat ALL_PROXY as a fallback for its HTTPS handler.
    # Preserve every dormant scheme verbatim; do not reject or reinterpret it.
    for scheme in ('http', 'https'):
        if scheme not in effective:
            continue
        try:
            parsed = urllib.parse.urlsplit(effective[scheme])
            port = parsed.port
            valid = (parsed.scheme in ('http', 'https') and bool(parsed.hostname)
                     and (port is None or 1 <= port <= 65535)
                     and parsed.path in ('', '/') and not parsed.query and not parsed.fragment)
        except (ValueError, UnicodeError):
            valid = False
        require(valid, 'selected HTTP proxy URL shape refused without recording its value')
    trust = value['trust_environment']
    require(type(trust) is dict and set(trust) <= set(TRUST_KEYS), 'private CA key set differs')
    for raw in trust.values():
        require(type(raw) is str and len(raw) <= 8192
                and not any(c in raw for c in ('\0', '\r', '\n'))
                and (not raw or os.path.isabs(raw)), 'configured CA path is not a safe absolute path')
    require(len(wire(value)) <= 65536, 'private proxy configuration exceeds its fixed bound')
    return value

def capture_proxy_configuration(operation_root, inherited=None):
    """Read only the original network settings; never serialize other secrets."""
    inherited = os.environ if inherited is None else inherited
    rows = [[name, inherited[name]] for name in inherited if _is_proxy_key(name)]
    cgi = 'REQUEST_METHOD' in inherited
    value = {'schema': PROXY_SCHEMA, 'operation_root': operation_root,
             'proxy_rows': rows, 'request_method_present': cgi,
             'effective_proxies': _effective_proxies(rows, cgi),
             'trust_environment': {key: inherited[key] for key in TRUST_KEYS if key in inherited}}
    return validate_proxy_configuration(value, operation_root)

def public_environment(configuration):
    validate_proxy_configuration(configuration, configuration['operation_root'])
    env = {'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8', 'PATH': '',
           'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONNOUSERSITE': '1', 'PYTHONUNBUFFERED': '1'}
    env.update(configuration['trust_environment'])
    return env

def configured_environment(configuration, inherited=None):
    require(configuration == capture_proxy_configuration(configuration['operation_root'], inherited),
            'private proxy input differs from the actual inherited original configuration')
    return public_environment(configuration)

def read_private_proxy(path, operation_root, expected_sha256):
    require(type(expected_sha256) is str and len(expected_sha256) == 64
            and all(c in '0123456789abcdef' for c in expected_sha256), 'private proxy seal is invalid')
    old = Path(path).lstat()
    require(stat.S_ISREG(old.st_mode) and stat.S_IMODE(old.st_mode) == 0o600
            and old.st_uid == os.geteuid() and old.st_nlink == 1 and old.st_size <= 65536,
            'proxy input must be a private owned single-link regular file')
    pin, raw = seal(path, 65536, body=True)
    require(pin['identity'] == ident(old) and pin['sha256'] == expected_sha256,
            'private proxy original bytes or identity differ')
    value = validate_proxy_configuration(json_value(raw), operation_root)
    return value, pin

class ConfiguredProxyHandler(urllib.request.ProxyHandler):
    """Original proxy_open, with explicit original NO_PROXY instead of globals."""
    def proxy_open(self, req, proxy, type):
        orig_type = req.type
        proxy_type, user, password, hostport = urllib.request._parse_proxy(proxy)
        if proxy_type is None:
            proxy_type = orig_type
        if req.host and urllib.request.proxy_bypass_environment(req.host, self.proxies):
            return None
        if user and password:
            user_pass = '%s:%s' % (urllib.parse.unquote(user), urllib.parse.unquote(password))
            creds = base64.b64encode(user_pass.encode()).decode('ascii')
            req.add_header('Proxy-authorization', 'Basic ' + creds)
        hostport = urllib.parse.unquote(hostport)
        req.set_proxy(hostport, proxy_type)
        if orig_type == proxy_type or orig_type == 'https':
            return None
        else:
            return self.parent.open(req, timeout=req.timeout)

def configured_provider_client(configuration, report, deadline):
    validate_proxy_configuration(configuration, configuration['operation_root'])
    require(not any(_is_proxy_key(key) for key in os.environ),
            'worker proxy values must come only from the sealed private input')
    require({key: os.environ[key] for key in TRUST_KEYS if key in os.environ}
            == configuration['trust_environment'], 'worker CA environment differs from the original configuration')
    # Same SSL_CERT_FILE/SSL_CERT_DIR environment as the original process;
    # an explicit verified context retains standard default CA loading too.
    context = ssl.create_default_context()
    require(context.check_hostname is True and context.verify_mode == ssl.CERT_REQUIRED,
            'provider TLS certificate verification must remain enabled')
    return urllib.request.build_opener(ConfiguredProxyHandler(dict(configuration['effective_proxies'])),
        urllib.request.HTTPSHandler(context=context), ProviderRedirect(report, deadline))

def provider_host(url):
    p = urllib.parse.urlsplit(url)
    require(p.scheme == 'https' and p.hostname and p.username is None and p.password is None
            and p.port in (None, 443) and not p.fragment, 'provider URL shape refused')
    host = p.hostname.lower()
    require(host.startswith('sdmntpr') and host.endswith('.oaiusercontent.com')
            or host.startswith('oaisdmntpr') and host.endswith('.blob.core.windows.net')
            or host.startswith('oaisdsorpr') and host.endswith('.blob.core.windows.net')
            or host.startswith('oaisdmntpr') and 'aws.s3.' in host and host.endswith('.amazonaws.com'),
            'provider host outside allowed file reference service')
    return host

class ProviderRedirect(urllib.request.HTTPRedirectHandler):
    def __init__(self, report, deadline):
        self.report, self.deadline = report, deadline
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        check_deadline(self.deadline)
        host = provider_host(newurl)
        require(len(self.report['redirects']) < 3 and code in (301, 302, 303, 307, 308), 'provider redirect bound exceeded')
        self.report['redirects'].append({'code': code, 'host': host, 'location_sha256': hashlib.sha256(newurl.encode()).hexdigest()})
        # Recreate headers from the fixed non-secret allowlist, not from the prior request.
        return urllib.request.Request(newurl, headers={'User-Agent': 'HIA-sequential-original-reader/1'}, method='GET')

def download(url, artifact, directory, budget, deadline, proxy_configuration):
    """One GET, no retry; both the downloaded bytes and on-disk bytes must seal."""
    require(artifact['id'] != 13982129929 and 0 < artifact['bytes'] <= 320 << 20,
            'only the exact bounded derived part artifacts may be downloaded')
    output = Path(directory) / 'official-part.original.zip'
    partial = Path(directory) / 'official-part.original.zip.partial'
    require(not os.path.lexists(output) and not os.path.lexists(partial), 'no replay of existing part paths')
    report = {'schema': 'hia.full32.sequential-part-download.v1', 'status': 'HOLD',
              'artifact': artifact, 'host': provider_host(url), 'get_attempts': 0,
               'redirects': [], 'origin_authorization_sent': False, 'cookies_sent': False,
               'configured_proxies_used': True, 'signed_URL_recorded': False,
               'original_proxy_authentication_preserved': True,
               'private_proxy_values_recorded': False, 'direct_fallback_after_proxy_error': False}
    budget.capacity(artifact['bytes'])
    count, digest = 0, hashlib.sha256()
    try:
        check_deadline(deadline)
        client = configured_provider_client(proxy_configuration, report, deadline)
        request = urllib.request.Request(url, headers={'User-Agent': 'HIA-sequential-original-reader/1'}, method='GET')
        report['get_attempts'] = 1
        with client.open(request, timeout=min(30, max(0.001, deadline - time.monotonic()))) as response:
            require(response.status == 200, 'provider response status differs')
            header = response.headers.get('Content-Length')
            require(header is None or int(header) == artifact['bytes'], 'provider content length differs')
            fd = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                while True:
                    check_deadline(deadline)
                    budget.capacity(artifact['bytes'] - count)
                    raw = response.read(min(CHUNK, artifact['bytes'] + 1 - count))
                    if not raw:
                        break
                    count += len(raw); require(count <= artifact['bytes'], 'provider body exceeds exact size')
                    digest.update(raw); stream.write(raw)
                stream.flush(); os.fsync(stream.fileno())
        require(count == artifact['bytes'] and digest.hexdigest() == artifact['sha256'], 'official transport seal differs')
        before = seal(partial, artifact['bytes'], deadline=deadline)
        require(before['bytes'] == count and before['sha256'] == digest.hexdigest(), 'independent downloaded file seal differs')
        os.rename(partial, output)
        after = output.lstat()
        require([after.st_dev, after.st_ino, after.st_size] == [before['identity'][0], before['identity'][1], count]
                and after.st_nlink == 1, 'same-device temporary publication identity differs')
        report.update(status='ONE_GET_TWO_FULL_SEALS_PASS', first_read={'bytes': count, 'sha256': digest.hexdigest()},
                      independent_readback=before, current_identity=ident(after))
    except BaseException as error:
        report['status'] = 'HOLD'; report['error'] = safe_error(error)
        raise
    finally:
        report.update(bytes_read=count, sha256=digest.hexdigest())
        create(Path(directory) / 'DOWNLOAD.json', report, budget=budget)
    return output, report

def dispose_verified_temporary(path, expected, directory, budget):
    """Only this operation's sealed temp file; never old evidence or failed parts."""
    path = Path(path)
    require(path.parent == Path(directory) and path.name == 'official-part.original.zip', 'fixed temporary path required')
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        actual = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        require(stat.S_ISREG(actual.st_mode) and actual.st_uid == os.geteuid() and actual.st_nlink == 1
                and ident(actual) == expected['identity'], 'verified temp identity changed before disposal')
        create(Path(directory) / 'TEMPORARY-DISPOSAL-INTENT.json',
               {'path': str(path), 'verified_record': expected, 'permanent_original_byte_retention_claimed': False}, budget=budget)
        os.unlink(path.name, dir_fd=parent); os.fsync(parent)
        try:
            os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            absent = True
        else:
            absent = False
        require(absent, 'temporary removal outcome not observed')
        create(Path(directory) / 'TEMPORARY-DISPOSAL-ACK.json',
               {'path': str(path), 'absent_observed': True, 'original_provider_artifact_unchanged': True}, budget=budget)
    finally:
        os.close(parent)
