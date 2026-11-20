"""Strict bytes and owned subprocess receipts for the explicit cold transport.

The process supervisor is mechanically retained from the recorded Slot support
module, with this new lane's explicit three-second cleanup cap. It imports no
product. It never changes the original child's own 180-second cold deadline.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import time

CLEANUP_SECONDS = 3
JSON_KW = dict(ensure_ascii=True, sort_keys=True, separators=(',', ':'), allow_nan=False)


def canonical(value):
    return json.dumps(value, **JSON_KW).encode('ascii')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def write_json(path, value):
    Path(path).write_bytes(canonical(value) + b'\n')


def unique_pairs(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError('duplicate JSON key: ' + name)
        result[name] = value
    return result


def read_json(path):
    return json.loads(regular_bytes(path), object_pairs_hook=unique_pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))


def regular_bytes(path):
    path = Path(path)
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or path.is_symlink():
        raise ValueError('expected regular immutable input: ' + str(path))
    raw = path.read_bytes()
    after = path.lstat()
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
        raise ValueError('input changed while reading: ' + str(path))
    if len(raw) != after.st_size:
        raise ValueError('short source read')
    return raw


def pin(path):
    raw = regular_bytes(path)
    return {'bytes': len(raw), 'sha256': sha(raw)}


def checked_int(value, expected=None):
    if type(value) is not int or (expected is not None and value != expected):
        raise ValueError('integer identity differs: ' + repr(value))
    return value


def clean_environment():
    return {key: value for key, value in os.environ.items()
            if not key.startswith(('HEPTA_HIA', 'PYTHON'))}


def group_members(group):
    found = []
    for directory in Path('/proc').iterdir():
        if not directory.name.isdecimal():
            continue
        try:
            raw = (directory / 'stat').read_text()
            parts = raw[raw.rfind(')') + 2:].split()
            if int(parts[2]) == group and int(parts[3]) == group:
                found.append({'pid': int(directory.name), 'pgid': int(parts[2]),
                              'sid': int(parts[3]), 'state': parts[0],
                              'start_ticks': int(parts[19])})
        except (FileNotFoundError, ProcessLookupError):
            continue
    return sorted(found, key=lambda row: row['pid'])


def stop_owned(process):
    start = time.monotonic()
    before, signals = group_members(process.pid), []
    if before:
        try:
            os.killpg(process.pid, signal.SIGTERM)
            signals.append('SIGTERM')
        except ProcessLookupError:
            pass
    try:
        process.wait(timeout=max(.001, CLEANUP_SECONDS / 2 - (time.monotonic() - start)))
    except subprocess.TimeoutExpired:
        pass
    middle = group_members(process.pid)
    if middle:
        try:
            os.killpg(process.pid, signal.SIGKILL)
            signals.append('SIGKILL')
        except ProcessLookupError:
            pass
    reaped = True
    try:
        process.wait(timeout=max(.001, CLEANUP_SECONDS - (time.monotonic() - start)))
    except subprocess.TimeoutExpired:
        reaped = False
    return {'before': before, 'middle': middle, 'after': group_members(process.pid),
            'signals': signals, 'reaped': reaped,
            'cleanup_elapsed_seconds': time.monotonic() - start}


def run_owned(command, *, cwd, directory, timeout_seconds, environment=None, stdin=None, deadline=None):
    checked_int(timeout_seconds)
    directory = Path(directory)
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    environment = clean_environment() if environment is None else environment
    start, process, timed_out, interruption = time.monotonic(), None, False, None
    started_ns = time.monotonic_ns()
    stdout_path, stderr_path = directory / 'stdout.log', directory / 'stderr.log'
    spec = {'argv': list(map(str, command)), 'cwd': str(Path(cwd).resolve()),
            'timeout_seconds': timeout_seconds, 'cleanup_seconds': CLEANUP_SECONDS,
            'new_session': True, 'parent_pid': os.getpid(), 'started_monotonic_ns': started_ns,
            'environment': {key: value for key, value in environment.items()
                            if key in ('PATH', 'LD_LIBRARY_PATH', 'CLANG', 'HEPTA_CLANG')
                            or key.startswith(('HEPTA_HIA', 'PYTHON'))}}
    write_json(directory / 'command.json', spec)
    cleanup = None
    try:
        with stdout_path.open('xb') as stdout, stderr_path.open('xb') as stderr:
            process = subprocess.Popen(spec['argv'], cwd=cwd, env=environment,
                stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
                stdout=stdout, stderr=stderr, start_new_session=True)
            try:
                spec.update({'pid': process.pid, 'pgid': process.pid,
                             'owned_initial_members': group_members(process.pid)})
                write_json(directory / 'command.json', spec)
                effective = timeout_seconds if deadline is None else min(timeout_seconds, max(.001, deadline - time.monotonic()))
                spec['effective_timeout_seconds'] = effective
                write_json(directory / 'command.json', spec)
                process.communicate(stdin, timeout=effective)
            except subprocess.TimeoutExpired:
                timed_out = True
            except BaseException as error:
                interruption = {'type': type(error).__module__ + '.' + type(error).__qualname__,
                                'message': str(error)}
                raise
            finally:
                cleanup = stop_owned(process)
    finally:
        result = {'command': spec, 'pid': None if process is None else process.pid,
                  'exit_code': None if process is None else process.returncode,
                  'timed_out': timed_out, 'interruption': interruption,
                  'elapsed_seconds': time.monotonic() - start, 'ended_monotonic_ns': time.monotonic_ns(),
                  'owned_cleanup': cleanup,
                  'stdout': pin(stdout_path) if stdout_path.exists() else None,
                  'stderr': pin(stderr_path) if stderr_path.exists() else None}
        write_json(directory / 'result.json', result)
    return result


def successful_exit(result):
    cleanup = result.get('owned_cleanup')
    return (type(result.get('exit_code')) is int and result['exit_code'] == 0
            and result.get('timed_out') is False and result.get('interruption') is None
            and type(cleanup) is dict and cleanup.get('reaped') is True
            and cleanup.get('after') == [] and cleanup.get('signals') == [])

def parse(raw):
    return json.loads(raw, object_pairs_hook=unique_pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))


def data_pin(raw):
    return {"bytes": len(raw), "sha256": sha(raw)}


class Captures:
    def __init__(self):
        self.raws = {}

    def raw(self, path, expected=None):
        path = Path(path).resolve(strict=True)
        raw = regular_bytes(path)
        if expected is not None and (
                type(expected) is not dict or type(expected.get("bytes")) is not int
                or type(expected.get("sha256")) is not str or data_pin(raw) != expected):
            raise ValueError("captured raw identity differs: " + str(path))
        prior = self.raws.setdefault(path, raw)
        if prior != raw:
            raise ValueError("captured file changed between consumption points")
        return raw

    def json(self, path, expected=None):
        return parse(self.raw(path, expected))

    def unchanged(self):
        for path, raw in self.raws.items():
            if regular_bytes(path) != raw:
                raise ValueError("terminal captured bytes changed: " + str(path))

    def pins(self):
        return {str(path): data_pin(raw) for path, raw in sorted(self.raws.items(), key=lambda row: str(row[0]))}



# Source relation only: these exact successor bytes are not a past PASS.
# The original R3 fixture remains immutable. Four allocation/copy changes and
# three additional controls must reconstruct the complete original byte files.
OBSERVER_GATE_SHA = "8720447c115e1737dc395271ebb91bb4c8bd5a83bc89558224058b09371bc1d5"
OBSERVER_ADDITIONAL_IDS = [
    "tests.test_hia_selfhost_native_observer.NativeObserverFrameValidationTests.test_frame_bytes_and_descriptor_domain_remain_exact",
    "tests.test_hia_selfhost_native_observer.NativeObserverFrameValidationTests.test_invalid_frame_is_refused_before_shared_output_allocation",
    "tests.test_hia_selfhost_native_observer.NativeObserverTests.test_workspace_fields_require_complete_words_at_every_boundary"
]
OBSERVER_SUCCESSORS = {
    "tools/hia_selfhost_native_observer.py": {
        "old": {
            "bytes": 14486,
            "sha256": "aacff6857ecbc88f6f541c06db5427065d86fbb331f1fa83ddf8bb3dfa3361af"
        },
        "current": {
            "bytes": 14689,
            "sha256": "61afdc546a450aa0d6f297cb38f648838dfee08565eb9acf19c9e02e37230f73"
        },
        "splices": [
            {
                "old_offset": 4806,
                "new_offset": 4806,
                "old_hex": "646566206672616d6528696d6167652c20736f757263652c2063617061636974792c20776f726b73706163655f73697a652c20776f726b73706163655f66696c6c2c206f75747075745f66643d4e6f6e65293a0a20202020696620286e6f74206973696e7374616e636528696d6167652c20627974657329206f72206e6f742030203c206c656e28696d61676529203c3d20342a4c494d49540a2020202020202020202020206f72206e6f74206973696e7374616e636528736f757263652c20627974657329206f72206c656e28736f7572636529203e204c494d49540a2020202020202020202020206f72207479706528636170616369747929206973206e6f7420696e74206f72206e6f742030203c3d206361706163697479203c3d204c494d49540a2020202020202020202020206f72207479706528776f726b73706163655f73697a6529206973206e6f7420696e74206f72206e6f742030203c3d20776f726b73706163655f73697a65203c3d204c494d49540a2020202020202020202020206f72207479706528776f726b73706163655f66696c6c29206973206e6f7420696e74206f72206e6f742030203c3d20776f726b73706163655f66696c6c203c3d203235350a2020202020202020202020206f7220286f75747075745f6664206973206e6f74204e6f6e6520616e64202874797065286f75747075745f666429206973206e6f7420696e74206f72206e6f742033203c3d206f75747075745f6664203c3d20323134373438333634372929293a0a202020202020202072616973652056616c75654572726f7228276e6174697665206f62736572766572206672616d6520657863656564732074686520756e6368616e676564206279746520414249206c696d69747327290a",
                "new_hex": "646566205f76616c69646174655f6672616d6528696d6167652c20736f757263652c2063617061636974792c20776f726b73706163655f73697a652c20776f726b73706163655f66696c6c2c206f75747075745f66643d4e6f6e65293a0a20202020696620286e6f74206973696e7374616e636528696d6167652c20627974657329206f72206e6f742030203c206c656e28696d61676529203c3d20342a4c494d49540a2020202020202020202020206f72206e6f74206973696e7374616e636528736f757263652c20627974657329206f72206c656e28736f7572636529203e204c494d49540a2020202020202020202020206f72207479706528636170616369747929206973206e6f7420696e74206f72206e6f742030203c3d206361706163697479203c3d204c494d49540a2020202020202020202020206f72207479706528776f726b73706163655f73697a6529206973206e6f7420696e74206f72206e6f742030203c3d20776f726b73706163655f73697a65203c3d204c494d49540a2020202020202020202020206f72207479706528776f726b73706163655f66696c6c29206973206e6f7420696e74206f72206e6f742030203c3d20776f726b73706163655f66696c6c203c3d203235350a2020202020202020202020206f7220286f75747075745f6664206973206e6f74204e6f6e6520616e64202874797065286f75747075745f666429206973206e6f7420696e74206f72206e6f742033203c3d206f75747075745f6664203c3d20323134373438333634372929293a0a202020202020202072616973652056616c75654572726f7228276e6174697665206f62736572766572206672616d6520657863656564732074686520756e6368616e676564206279746520414249206c696d69747327290a0a0a646566206672616d6528696d6167652c20736f757263652c2063617061636974792c20776f726b73706163655f73697a652c20776f726b73706163655f66696c6c2c206f75747075745f66643d4e6f6e65293a0a202020205f76616c69646174655f6672616d6528696d6167652c20736f757263652c2063617061636974792c20776f726b73706163655f73697a652c20776f726b73706163655f66696c6c2c206f75747075745f6664290a"
            },
            {
                "old_offset": 8525,
                "new_offset": 8709,
                "old_hex": "202020206672616d6528696d6167655f62797465732c736f757263652c63617061636974792c776f726b73706163655f73697a652c776f726b73706163655f66696c6c290a",
                "new_hex": "202020205f76616c69646174655f6672616d6528696d6167655f62797465732c736f757263652c63617061636974792c776f726b73706163655f73697a652c776f726b73706163655f66696c6c290a"
            },
            {
                "old_offset": 11433,
                "new_offset": 11627,
                "old_hex": "202020202020202020202020202020202020202020202020776f726b7370616365203d207261775b32342b6c656e28736f75726365292b63617061636974793a5d0a",
                "new_hex": "202020202020202020202020202020202020202020202020776f726b73706163655f6f6666736574203d2032342b6c656e28736f75726365292b63617061636974790a"
            },
            {
                "old_offset": 12168,
                "new_offset": 12363,
                "old_hex": "2020202020202020202020202020202020202020202020202020202027776f726b73706163655f686561646572273a7b737472286174293a696e742e66726f6d5f627974657328776f726b73706163655b61743a61742b385d2c276c6974746c6527290a",
                "new_hex": "2020202020202020202020202020202020202020202020202020202027776f726b73706163655f686561646572273a7b737472286174293a7374727563742e756e7061636b5f66726f6d28273c51272c7261772c776f726b73706163655f6f66667365742b6174295b305d0a"
            }
        ]
    },
    "tests/test_hia_selfhost_native_observer.py": {
        "old": {
            "bytes": 11041,
            "sha256": "d88346f9278cb38efe42c96db83ac1d088c62c59c2a0d0ccda093956b8f1d49a"
        },
        "current": {
            "bytes": 14102,
            "sha256": "abb072533dcde5a042e8e522f881a8b2402fc035dbae61cecc30a8e1850e1d3f"
        },
        "splices": [
            {
                "old_offset": 302,
                "new_offset": 302,
                "old_hex": "40756e6974746573742e736b6970556e6c65737328706c6174666f726d2e73797374656d28293d3d274c696e75782720616e6420706c6174666f726d2e6d616368696e6528292e6c6f776572282920696e2028277838365f3634272c27616d64363427290a",
                "new_hex": "636c617373204e61746976654f627365727665724672616d6556616c69646174696f6e546573747328756e6974746573742e5465737443617365293a0a2020202064656620746573745f6672616d655f62797465735f616e645f64657363726970746f725f646f6d61696e5f72656d61696e5f65786163742873656c66293a0a2020202020202020666f722064657363726970746f7220696e20284e6f6e652c332c32313437343833363437293a0a202020202020202020202020776974682073656c662e73756254657374286f75747075745f66643d64657363726970746f72293a0a2020202020202020202020202020202065787065637465643d62274849414f42533032272b7374727563742e7061636b28273c3651272c322c332c313c3c32302c313c3c32302c3235352c0a202020202020202020202020202020202020202028313c3c3634292d312069662064657363726970746f72206973204e6f6e6520656c73652064657363726970746f72292b62275c7863335c783930415c305c786666270a2020202020202020202020202020202073656c662e617373657274457175616c286672616d652862275c7863335c783930272c6227415c305c786666272c313c3c32302c313c3c32302c3235352c64657363726970746f72292c6578706563746564290a2020202020202020666f722064657363726970746f7220696e202846616c73652c547275652c2d312c302c312c322c323134373438333634382c332e302c273327293a0a202020202020202020202020776974682073656c662e73756254657374286f75747075745f66643d64657363726970746f72293a0a20202020202020202020202020202020776974682073656c662e6173736572745261697365732856616c75654572726f72293a0a20202020202020202020202020202020202020206672616d652862275c786333272c6227272c302c302c302c64657363726970746f72290a0a2020202064656620746573745f696e76616c69645f6672616d655f69735f726566757365645f6265666f72655f7368617265645f6f75747075745f616c6c6f636174696f6e2873656c66293a0a202020202020202066726f6d20756e6974746573742e6d6f636b20696d706f72742070617463680a2020202020202020696e76616c69643d5b284e6f6e652c302c302c30292c2862797465617272617928292c302c302c30295d0a2020202020202020666f7220636170616369747920696e20282d312c547275652c312e302c312b28313c3c323029293a0a202020202020202020202020696e76616c69642e617070656e6428286227272c63617061636974792c302c3029290a2020202020202020666f722073697a6520696e20282d312c547275652c312e302c312b28313c3c323029293a0a202020202020202020202020696e76616c69642e617070656e6428286227272c302c73697a652c3029290a2020202020202020666f722066696c6c20696e20282d312c547275652c312e302c323536293a0a202020202020202020202020696e76616c69642e617070656e6428286227272c302c302c66696c6c29290a2020202020202020776974682074656d7066696c652e54656d706f726172794469726563746f7279287072656669783d276869612d6e61746976652d6672616d652d646f6d61696e2d2729206173206469726563746f72793a0a202020202020202020202020726f6f743d50617468286469726563746f7279290a202020202020202020202020696d6167653d726f6f742f27696d6167652e62696e273b696d6167652e77726974655f62797465732862275c78633327290a2020202020202020202020206f627365727665723d726f6f742f276f627365727665722e656c66273b6f627365727665722e77726974655f62797465732862276e6f742d657865637574656427290a202020202020202020202020776974682070617463682827746f6f6c732e6869615f73656c66686f73745f6e61746976655f6f627365727665722e7368617265645f6f75747075742729206173207368617265643a0a20202020202020202020202020202020666f7220736f757263652c63617061636974792c73697a652c66696c6c20696e20696e76616c69643a0a2020202020202020202020202020202020202020776974682073656c662e7375625465737428736f757263653d736f757263652c63617061636974793d63617061636974792c73697a653d73697a652c66696c6c3d66696c6c293a0a202020202020202020202020202020202020202020202020776974682073656c662e6173736572745261697365732856616c75654572726f72293a0a202020202020202020202020202020202020202020202020202020206e61746976655f696e766f6b6528726f6f742c27696e76616c6964272c6f627365727665722c696d6167652c736f757263652c63617061636974793d63617061636974792c0a2020202020202020202020202020202020202020202020202020202020202020776f726b73706163655f73697a653d73697a652c776f726b73706163655f66696c6c3d66696c6c2c6f6273657276655f747261705f7772697465733d54727565290a202020202020202020202020202020207368617265642e6173736572745f6e6f745f63616c6c656428290a20202020202020202020202073656c662e617373657274457175616c28736f7274656428706174682e6e616d6520666f72207061746820696e20726f6f742e697465726469722829292c5b27696d6167652e62696e272c276f627365727665722e656c66275d290a0a0a40756e6974746573742e736b6970556e6c65737328706c6174666f726d2e73797374656d28293d3d274c696e75782720616e6420706c6174666f726d2e6d616368696e6528292e6c6f776572282920696e2028277838365f3634272c27616d64363427290a"
            },
            {
                "old_offset": 3259,
                "new_offset": 5320,
                "old_hex": "2020202064656620746573745f736f757263655f6d75746174696f6e5f69735f61637475616c6c795f6f627365727665645f6e6f745f617373756d65642873656c66293a0a",
                "new_hex": "2020202064656620746573745f776f726b73706163655f6669656c64735f726571756972655f636f6d706c6574655f776f7264735f61745f65766572795f626f756e646172792873656c66293a0a202020202020202023204e6f6e656d70747920736f757263652f6f7574707574206d616b652074686520776f726b7370616365206f6666736574206e6f6e7a65726f20616e6420756e616c69676e65642e0a20202020202020206669656c64733d28302c382c31362c32342c34302c34382c35362c36342c37322c38302c38382c39362c3130342c3131322c3232342c3234382c31303234290a202020202020202073697a65733d736f72746564287b302c2a2861742b64656c746120666f7220617420696e206669656c647320666f722064656c746120696e2028372c3829297d290a2020202020202020736f757263653d6227415c305c786666272a31330a2020202020202020666f722073697a6520696e2073697a65733a0a202020202020202020202020776974682073656c662e7375625465737428776f726b73706163655f73697a653d73697a65293a0a20202020202020202020202020202020726573756c742c6f75747075743d73656c662e63616c6c2827776f726b73706163652d626f756e646172792d272b7374722873697a65292c0a202020202020202020202020202020202020202062797465732e66726f6d6865782827333120633020633327292c736f757263652c31332c73697a652c313939290a2020202020202020202020202020202073656c662e617373657274457175616c28726573756c745b27737461747573275d2c2772657475726e656427290a2020202020202020202020202020202073656c662e617373657274457175616c28726573756c745b27636f72655f753332275d2c30290a2020202020202020202020202020202073656c662e6173736572745472756528726573756c745b27736f757263655f756e6368616e676564275d290a2020202020202020202020202020202073656c662e617373657274457175616c286f75747075742c62275c786135272a3133290a2020202020202020202020202020202073656c662e617373657274457175616c28726573756c745b27776f726b73706163655f686561646572275d2c0a20202020202020202020202020202020202020207b737472286174293a30786337633763376337633763376337633720666f7220617420696e206669656c64732069662061742b383c3d73697a657d290a2020202020202020202020202020202073656c662e617373657274457175616c28726573756c745b276c696d697473275d5b27776f726b73706163655f6279746573275d2c73697a65290a0a2020202064656620746573745f736f757263655f6d75746174696f6e5f69735f61637475616c6c795f6f627365727665645f6e6f745f617373756d65642873656c66293a0a"
            }
        ]
    }
}


def restore_observer_source(name, raw, original_pin):
    """Prove the exact whole-source inverse without executing old source."""
    if name not in OBSERVER_SUCCESSORS:
        if data_pin(raw) != original_pin:
            raise ValueError("unchanged original observer/test source differs")
        return raw
    record = OBSERVER_SUCCESSORS[name]
    if (type(raw) is not bytes or data_pin(raw) != record["current"]
            or canonical(original_pin) != canonical(record["old"])):
        raise ValueError("observer successor whole-source authority differs")
    entries = []
    old_end = new_end = displacement = 0
    for item in record["splices"]:
        old_at, new_at = item["old_offset"], item["new_offset"]
        before, after = bytes.fromhex(item["old_hex"]), bytes.fromhex(item["new_hex"])
        if (type(old_at) is not int or type(new_at) is not int
                or old_at < old_end or new_at < new_end or old_at + displacement != new_at
                or not before or not after or before == after
                or raw[new_at:new_at + len(after)] != after):
            raise ValueError("observer successor exact splice differs")
        entries.append((old_at, new_at, before, after))
        old_end, new_end = old_at + len(before), new_at + len(after)
        displacement += len(after) - len(before)
    restored = raw
    for old_at, new_at, before, after in reversed(entries):
        restored = restored[:new_at] + before + restored[new_at + len(after):]
    if data_pin(restored) != original_pin:
        raise ValueError("observer successor does not restore the full original")
    replay = restored
    for old_at, new_at, before, after in reversed(entries):
        if replay[old_at:old_at + len(before)] != before:
            raise ValueError("observer original splice differs")
        replay = replay[:old_at] + after + replay[old_at + len(before):]
    if replay != raw:
        raise ValueError("observer successor whole forward replay differs")
    return restored


def observer_source_profile(root, capture):
    root = Path(root)
    fixture = capture.raw(root / "tests/fixtures/cold_native_transport_original_gates_v3.json")
    if sha(fixture) != OBSERVER_GATE_SHA:
        raise ValueError("original observer fixture changed")
    plan = parse(fixture)
    originals = plan["original_method_ids"]
    if (plan["original_method_count"] != 44 or not (len(originals) == len(set(originals)) == 44)):
        raise ValueError("complete original observer method inventory differs")
    # Compare every current complete source against the frozen original through
    # only the two exact reviewed source relations above.
    for name, expected in plan["original_tests"].items():
        restore_observer_source(name, capture.raw(root / name), expected)
    for item in plan["original_observers"]:
        source = capture.raw(root / item["path"])
        tail, execute = item["selection_tail"].encode(), item["execute_source"].encode()
        if not source.endswith(tail):
            raise ValueError("observer exact selection tail differs")
        body = source[:-len(tail)]
        restore_observer_source(item["path"], body, item["before"])
        if body.count(execute) != 1 or data_pin(execute) != item["execute"]:
            raise ValueError("original observer execute function differs")
    all_ids = originals + list(OBSERVER_ADDITIONAL_IDS)
    current = [identity for module in plan["original_modules"]
               for identity in sorted(all_ids) if identity.startswith(module + ".")]
    if (len(current) != 47 or len(set(current)) != 47
            or [identity for identity in current if identity in originals] != originals):
        raise ValueError("complete current47/original44 observer domains differ")
    capture.unchanged()
    return plan, current, {
        "scope": "CURRENT_OBSERVER47_RETAINING_EXACT_ORIGINAL44",
        "original_fixture_sha256": OBSERVER_GATE_SHA,
        "original_method_ids": list(originals),
        "current_method_ids": current,
        "additional_method_ids": list(OBSERVER_ADDITIONAL_IDS),
        "source_relations": {name: {"original": row["old"], "current": row["current"],
            "exact_splices": len(row["splices"]), "whole_inverse_and_forward_verified": True}
            for name, row in OBSERVER_SUCCESSORS.items()},
        "original_execute_functions_unchanged": True,
        "selection_tails_unchanged": True,
        "past_results_are_current_qualification": False,
    }


def terminal_owned(capture, directory, *, seconds, expected_argv=None, cwd=None):
    directory = Path(directory)
    command = capture.json(directory / "command.json")
    result = capture.json(directory / "result.json")
    checked_int(command["timeout_seconds"], seconds)
    checked_int(command["cleanup_seconds"], CLEANUP_SECONDS)
    if command.get("new_session") is not True or result["command"] != command:
        raise ValueError("actual owned command receipt differs")
    if expected_argv is not None and command["argv"] != list(map(str, expected_argv)):
        raise ValueError("actual owned argv differs")
    if cwd is not None and command["cwd"] != str(Path(cwd).resolve()):
        raise ValueError("actual owned cwd differs")
    pid = checked_int(command["pid"])
    if pid <= 0 or command["pgid"] != pid or checked_int(result["pid"]) != pid:
        raise ValueError("actual owned child identity differs")
    capture.raw(directory / "stdout.log", result["stdout"])
    capture.raw(directory / "stderr.log", result["stderr"])
    if not successful_exit(result):
        raise ValueError("owned child is incomplete or anomalous")
    return command, result
