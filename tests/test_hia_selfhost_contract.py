"""Adversarial source identity and clean export checks for Selfhost-Core."""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import platform
import shutil
import tempfile
import unittest

from tools.hia_selfhost_contract import (CONTRACT_PATH, PROFILE, ROOT,
                                       validate_contract)
from tools.replay_hia_selfhost_cold import cold_replay


class SelfhostContractTests(unittest.TestCase):
    @staticmethod
    def _source_path_reference(root):
        from tools import hia_selfhost_contract as contract
        root = Path(root)
        paths = sorted(set(contract.SOURCE_FILES) | {
            p.relative_to(root).as_posix() for p in (root / "hepta").rglob("*.py")
        })
        return {path: contract.sha256((root / path).read_bytes()).hexdigest() for path in paths}

    def test_fresh_path_allocation_preserves_complete_original_map_and_order(self):
        from tools import hia_selfhost_contract as contract
        original = self._source_path_reference(ROOT)
        actual = contract.file_digests(ROOT)
        self.assertEqual(actual, original)
        self.assertEqual(list(actual), list(original))
        self.assertEqual(actual, validate_contract()["source_identity"]["files"])

    def test_fresh_path_allocation_preserves_lexical_roots_and_foreign_path_lifetime(self):
        import gc
        import os
        from unittest.mock import patch
        from tools import hia_selfhost_contract as contract
        original = self._source_path_reference
        with tempfile.TemporaryDirectory(prefix="hia-source-path-domain-") as temporary:
            root = Path(temporary) / "domain"
            (root / "hepta/sub").mkdir(parents=True)
            for name in ("declared", "hepta/a.py", "hepta/sub/\u03b1.py", "hepta/sub/space name.py"):
                (root / name).write_bytes(name.encode())
            if os.name == "posix":
                (root / "hepta/sub/a\\b.py").write_bytes(b"backslash")
                (root / "hepta/sub/link.py").symlink_to("../a.py")
                (root / "hepta/link-dir").symlink_to("sub", target_is_directory=True)
            with patch.object(contract, "SOURCE_FILES", ("declared",)):
                roots = [root, str(root) + "/", str(root) + "/.", str(root / "hepta/..")]
                if os.name == "posix":
                    roots.append("/" + str(root))
                for value in roots:
                    with self.subTest(root=value):
                        expected = original(value)
                        actual = contract.file_digests(value)
                        self.assertEqual(actual, expected)
                        self.assertEqual(list(actual), list(expected))
                previous = Path.cwd()
                try:
                    os.chdir(root)
                    for value in (".", "", "../domain"):
                        with self.subTest(root=value):
                            self.assertEqual(contract.file_digests(value), original(value))
                finally:
                    os.chdir(previous)
                calls = []
                class RootPath:
                    def __fspath__(self):
                        calls.append("fspath")
                        return str(root)
                expected = original(RootPath())
                self.assertEqual(calls, ["fspath"])
                calls.clear()
                self.assertEqual(contract.file_digests(RootPath()), expected)
                self.assertEqual(calls, ["fspath"])

                def foreign(function):
                    events = []
                    class ForeignPath(type(root)):
                        def relative_to(self, *args, **kwargs):
                            events.append("relative_to")
                            return super().relative_to(*args, **kwargs)
                        def as_posix(self):
                            events.append("as_posix")
                            return super().as_posix()
                        def __del__(self):
                            events.append("drop")
                    def enumerate_paths(*args, **kwargs):
                        yield ForeignPath(root / "hepta/a.py")
                    read_bytes = Path.read_bytes
                    def read(path):
                        events.append("read:" + path.name)
                        return read_bytes(path)
                    with patch.object(Path, "rglob", enumerate_paths), patch.object(Path, "read_bytes", read):
                        value = function(root)
                    gc.collect()
                    return events, list(value.items())
                self.assertEqual(foreign(original), foreign(contract.file_digests))

            if os.name == "posix":
                for root_name in ("/", "//"):
                    values = [Path(root_name) / "hepta/a.py", Path(root_name) / "hepta/sub/b.py"]
                    with patch.object(contract, "SOURCE_FILES", ()), \
                         patch.object(Path, "rglob", lambda *args, **kwargs: iter(values)), \
                         patch.object(Path, "read_bytes", lambda path: path.as_posix().encode()):
                        self.assertEqual(contract.file_digests(root_name), original(root_name))
                outside = root.parent / (root.name + "-other") / "hepta/a.py"
                with patch.object(contract, "SOURCE_FILES", ()), \
                     patch.object(Path, "rglob", lambda *args, **kwargs: iter((outside,))), \
                     patch.object(Path, "read_bytes", side_effect=AssertionError("non-subtree reached read")):
                    with self.assertRaises(ValueError) as expected:
                        original(root)
                    with self.assertRaises(ValueError) as actual:
                        contract.file_digests(root)
                    self.assertEqual(actual.exception.args, expected.exception.args)

    def test_fresh_path_allocation_keeps_all_eleven_ordered_freshness_controls(self):
        import io
        import os
        from unittest.mock import patch
        from tools import hia_selfhost_contract as contract
        original = self._source_path_reference
        real_open, real_sha = io.open, sha256
        with tempfile.TemporaryDirectory(prefix="hia-source-path-errors-") as temporary:
            root = Path(temporary)
            (root / "hepta").mkdir()
            for name in ("a", "b", "c", "hepta/original.py"):
                (root / name).write_bytes(name.encode())
            with patch.object(contract, "SOURCE_FILES", ("c", "b", "a")):
                baseline = original(root)
                names = list(baseline)
                def observe(function, *, read_error=None, close_error=None, hash_error=None, hex_error=None):
                    events, current = [], [None]
                    class Stream:
                        def __init__(self, stream, name): self.stream, self.name = stream, name
                        def __enter__(self):
                            events.append(("enter", self.name)); self.stream.__enter__(); return self
                        def read(self, *args, **kwargs):
                            events.append(("read", self.name))
                            if self.name == read_error: raise OSError(5, "injected read failure", self.name)
                            return self.stream.read(*args, **kwargs)
                        def __exit__(self, *args):
                            events.append(("close", self.name)); result = self.stream.__exit__(*args)
                            if self.name == close_error: raise OSError(5, "injected close failure", self.name)
                            return result
                    def opened(path, *args, **kwargs):
                        name = Path(path).relative_to(root).as_posix()
                        current[0] = name; events.append(("open", name))
                        return Stream(real_open(path, *args, **kwargs), name)
                    class Hash:
                        def __init__(self, value, name): self.value, self.name = value, name
                        def hexdigest(self):
                            events.append(("hexdigest", self.name))
                            if self.name == hex_error: raise ValueError("injected hexdigest failure")
                            return self.value.hexdigest()
                    def digest(raw):
                        name = current[0]; events.append(("sha256", name))
                        if name == hash_error: raise ValueError("injected hash failure")
                        return Hash(real_sha(raw), name)
                    answer = error = None
                    try:
                        with patch.object(io, "open", opened), patch.object(contract, "sha256", digest):
                            answer = list(function(root).items())
                    except BaseException as exc:
                        error = (type(exc), exc.args, getattr(exc, "errno", None), getattr(exc, "filename", None),
                                 type(exc.__cause__) if exc.__cause__ is not None else None,
                                 type(exc.__context__) if exc.__context__ is not None else None)
                    return events, answer, error
                def pair(**kwargs):
                    expected, actual = observe(original, **kwargs), observe(contract.file_digests, **kwargs)
                    self.assertEqual(actual, expected)
                    return actual
                events, answer, error = pair()
                self.assertIsNone(error)
                self.assertEqual(answer, list(baseline.items()))
                self.assertEqual(events, [(event, name) for name in names
                    for event in ("open", "enter", "read", "close", "sha256", "hexdigest")])
                path = root / "a"; raw, stat = path.read_bytes(), path.stat()
                try:
                    path.write_bytes(raw + b" changed")
                    os.utime(path, ns=(stat.st_atime_ns, stat.st_mtime_ns))
                    changed = dict(pair()[1])
                    self.assertEqual({name for name in changed if changed[name] != baseline[name]}, {"a"})
                finally:
                    path.write_bytes(raw); os.utime(path, ns=(stat.st_atime_ns, stat.st_mtime_ns))
                dynamic = root / "hepta/new.py"
                dynamic.write_bytes(b"new")
                self.assertIn("hepta/new.py", dict(pair()[1]))
                dynamic.unlink()
                self.assertEqual(dict(pair()[1]), baseline)
                first, second = root / "a", root / "b"
                first.rename(root / "missing-a"); second.rename(root / "missing-b")
                try:
                    events, _, error = pair()
                    self.assertIs(error[0], FileNotFoundError)
                    self.assertEqual(events, [("open", "a")])
                finally:
                    (root / "missing-a").rename(first); (root / "missing-b").rename(second)
                second.rename(root / "directory-b"); second.mkdir()
                try:
                    events, _, error = pair()
                    self.assertIs(error[0], IsADirectoryError)
                    self.assertEqual(events[-1], ("open", "b"))
                finally:
                    second.rmdir(); (root / "directory-b").rename(second)
                for option in ("read_error", "close_error", "hash_error", "hex_error"):
                    with self.subTest(error=option):
                        events, _, error = pair(**{option: "b"})
                        self.assertIsNotNone(error)
                        self.assertNotIn(("open", "c"), events)
                second.rename(root / "later-missing-b")
                try:
                    events, _, error = pair(hash_error="a")
                    self.assertIs(error[0], ValueError)
                    self.assertNotIn(("open", "b"), events)
                finally:
                    (root / "later-missing-b").rename(second)
                self.assertEqual(contract.file_digests(root), baseline)

    def test_fresh_lexical_standard_provider_uses_exact_runtime_buffer_mode(self):
        import io
        import sys
        from unittest.mock import patch
        from tools import hia_selfhost_contract as contract
        fast = contract._source_protocol_current(ROOT)
        if (sys.implementation.name == 'cpython'
                and sys.version_info[:3] in ((3, 12, 14), (3, 14, 4))):
            self.assertTrue(fast)
        with tempfile.TemporaryDirectory(prefix='hia-fresh-lexical-profile-') as folder:
            root = Path(folder)
            (root / 'hepta').mkdir()
            (root / 'a').write_bytes(b'first')
            (root / 'hepta/b.py').write_bytes(b'second')
            def observe(function):
                seen = []
                def profile(frame, event, value):
                    if event == 'return' and frame.f_code is Path.read_bytes.__code__:
                        stream = frame.f_locals['f']
                        seen.append(('original', type(stream).__name__, stream.closed))
                    if event == 'return' and frame.f_code is contract._source_lexical_read.__code__:
                        stream = frame.f_locals.get('stream')
                        if stream is not None:
                            seen.append(('lexical', type(stream).__name__, stream.closed))
                old = sys.getprofile()
                try:
                    sys.setprofile(profile)
                    value = function(root)
                finally:
                    sys.setprofile(old)
                return value, seen
            with patch.object(contract, 'SOURCE_FILES', ('a',)):
                expected, old = observe(self._source_path_reference)
                actual, new = observe(contract.file_digests)
                self.assertEqual(actual, expected)
                self.assertEqual(len(old), 2)
                self.assertEqual(len(new), 2)
                self.assertTrue(all(row[0] == 'original' for row in old))
                expected_route = 'lexical' if fast else 'original'
                self.assertTrue(all(row[0] == expected_route for row in new))
                self.assertEqual([row[1:] for row in new], [row[1:] for row in old])
                self.assertTrue(all(row[2] is True for row in new))
                if fast:
                    expected_type = 'BufferedReader' if contract._SOURCE_PATH_PROTOCOL[4] == -1 else 'FileIO'
                    self.assertTrue(all(row[1] == expected_type for row in old))
                else:
                    self.assertEqual(new, old)

    def test_fresh_lexical_preimport_provider_replacements_use_original_protocol(self):
        import hashlib
        import importlib.util
        import io
        from contextlib import ExitStack
        from unittest.mock import patch
        from tools import hia_selfhost_contract as contract
        original_read, original_open, original_io = Path.read_bytes, Path.open, io.open
        original_sha, original_relative = hashlib.sha256, Path.relative_to
        with tempfile.TemporaryDirectory(prefix='hia-fresh-preimport-') as folder:
            root = Path(folder)
            (root / 'hepta').mkdir()
            (root / 'a').write_bytes(b'one')
            (root / 'hepta/b.py').write_bytes(b'two')
            for case in ('read_bytes', 'open', 'io', 'sha256', 'relative_to', 'opaque_read_descriptor'):
                with self.subTest(case=case):
                    events = []
                    def read(path):
                        events.append(('read', path.name))
                        return original_read(path)
                    def opened(path, *args, **kwargs):
                        events.append(('path-open', path.name))
                        return original_open(path, *args, **kwargs)
                    def io_open(path, *args, **kwargs):
                        events.append(('io-open', type(path).__name__, str(path)))
                        return original_io(path, *args, **kwargs)
                    def digest(raw):
                        events.append(('sha256', len(raw)))
                        return original_sha(raw)
                    def relative(path, *args, **kwargs):
                        events.append(('relative', path.name))
                        return original_relative(path, *args, **kwargs)
                    class OpaqueRead:
                        def __get__(self, instance, owner):
                            events.append(('descriptor', instance.name if instance is not None else None))
                            if instance is None:
                                raise AssertionError('admission must not invoke a foreign descriptor')
                            return lambda: original_read(instance)
                    with ExitStack() as stack:
                        if case == 'read_bytes': stack.enter_context(patch.object(Path, 'read_bytes', read))
                        elif case == 'open': stack.enter_context(patch.object(Path, 'open', opened))
                        elif case == 'io': stack.enter_context(patch.object(io, 'open', io_open))
                        elif case == 'sha256': stack.enter_context(patch.object(hashlib, 'sha256', digest))
                        elif case == 'relative_to': stack.enter_context(patch.object(Path, 'relative_to', relative))
                        else: stack.enter_context(patch.object(Path, 'read_bytes', OpaqueRead()))
                        spec = importlib.util.spec_from_file_location('_source_provider_' + case, contract.__file__)
                        clone = importlib.util.module_from_spec(spec)
                        spec.loader.exec_module(clone)
                        self.assertIsNone(clone._SOURCE_PATH_PROTOCOL)
                        self.assertEqual(events, [])
                        clone.SOURCE_FILES = ('a',)
                        def reference():
                            value = clone.Path(root)
                            names = sorted(set(clone.SOURCE_FILES) | {
                                p.relative_to(value).as_posix() for p in (value / 'hepta').rglob('*.py')
                            })
                            return {p: clone.sha256((value / p).read_bytes()).hexdigest() for p in names}
                        expected = reference()
                        expected_events = list(events)
                        events.clear()
                        actual = clone.file_digests(root)
                        self.assertEqual(actual, expected)
                        self.assertEqual(events, expected_events)

    def test_fresh_lexical_foreign_kwdefault_is_not_compared_during_admission(self):
        import importlib.util
        from unittest.mock import patch
        from tools import hia_selfhost_contract as contract
        events = []
        class Foreign:
            def __eq__(self, other):
                events.append('equal')
                raise AssertionError('foreign equality observed by admission')
            def __bool__(self):
                events.append('truth')
                raise AssertionError('successful relative path does not inspect walk_up')
        function = Path.relative_to
        old = function.__kwdefaults__
        try:
            function.__kwdefaults__ = {'walk_up': Foreign()}
            spec = importlib.util.spec_from_file_location('_source_foreign_kwdefault', contract.__file__)
            clone = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(clone)
            self.assertIsNone(clone._SOURCE_PATH_PROTOCOL)
            self.assertEqual(events, [])
            with tempfile.TemporaryDirectory(prefix='hia-fresh-kw-') as folder:
                root = Path(folder)
                (root / 'hepta').mkdir()
                (root / 'hepta/a.py').write_bytes(b'actual')
                clone.SOURCE_FILES = ()
                self.assertEqual(clone.file_digests(root), {'hepta/a.py': sha256(b'actual').hexdigest()})
                self.assertEqual(events, [])
        finally:
            function.__kwdefaults__ = old

    def test_fresh_lexical_real_file_errors_keep_original_identity_fields_and_context(self):
        from unittest.mock import patch
        from tools import hia_selfhost_contract as contract
        self.assertTrue(contract._source_protocol_current(ROOT))
        with tempfile.TemporaryDirectory(prefix='hia-fresh-errors-') as folder:
            root = Path(folder)
            (root / 'hepta').mkdir()
            (root / 'a').write_bytes(b'first')
            (root / 'directory').mkdir()
            (root / 'broken').symlink_to('absent')
            def observed(function, marker):
                try:
                    raise marker
                except LookupError:
                    try:
                        function(root)
                    except BaseException as error:
                        return (type(error), error.args, getattr(error, 'filename', None),
                                getattr(error, 'errno', None), error.__cause__,
                                error.__context__, error.__suppress_context__)
                self.fail('original file error was not reached')
            for name in ('missing', 'directory', 'broken', 'nul\x00path'):
                with self.subTest(name=name), patch.object(contract, 'SOURCE_FILES', ('a', name)):
                    marker = LookupError('same outer handled error')
                    expected = observed(self._source_path_reference, marker)
                    actual = observed(contract.file_digests, marker)
                    self.assertEqual(actual, expected)
                    self.assertIs(actual[5], marker)

    def test_fresh_lexical_fast_route_observes_same_size_same_mtime_and_inventory_changes(self):
        import os
        from unittest.mock import patch
        from tools import hia_selfhost_contract as contract
        self.assertTrue(contract._source_protocol_current(ROOT))
        with tempfile.TemporaryDirectory(prefix='hia-fresh-next-call-') as folder:
            root = Path(folder)
            (root / 'hepta').mkdir()
            path = root / 'a'
            path.write_bytes(b'ABCD')
            with patch.object(contract, 'SOURCE_FILES', ('a',)):
                before = contract.file_digests(root)
                metadata = path.stat()
                path.write_bytes(b'ABCE')
                os.utime(path, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
                after = contract.file_digests(root)
                self.assertNotEqual(after, before)
                self.assertEqual(after, self._source_path_reference(root))
                added = root / 'hepta/new.py'
                added.write_bytes(b'new complete source')
                self.assertIn('hepta/new.py', contract.file_digests(root))
                self.assertEqual(contract.file_digests(root), self._source_path_reference(root))
                added.unlink()
                self.assertEqual(contract.file_digests(root), after)

    def test_fresh_lexical_mid_open_provider_changes_keep_complete_original_sequence(self):
        import os
        import subprocess
        import sys
        program = r'''
from pathlib import Path
from hashlib import sha256
from unittest.mock import patch
import io, json, sys, tempfile
from tools import hia_selfhost_contract as contract
real_read, real_open, real_io, real_sha = Path.read_bytes, Path.open, io.open, contract.sha256
original_code = real_read.__code__
state = {'enabled': False}
def replacement_code(self):
    return b'changed by a code replacement'
def audit(event, args):
    if event != 'open' or not state['enabled']:
        return
    name = args[0]
    if type(name) is not str or not name.startswith(state['prefix']):
        return
    relative = name[len(state['prefix']):]
    state['events'].append(('open', relative, args[1], args[2]))
    if relative != 'a' or state['changed']:
        return
    state['changed'] = True
    case = state['case']
    def read(path):
        state['events'].append(('replacement-read', path.name))
        return real_read(path)
    def opened(path, *args, **kwargs):
        state['events'].append(('replacement-open', path.name))
        return real_open(path, *args, **kwargs)
    def io_open(path, *args, **kwargs):
        state['events'].append(('replacement-io', type(path).__name__, str(path)))
        return real_io(path, *args, **kwargs)
    def digest(raw):
        state['events'].append(('replacement-hash', bytes(raw).hex()))
        return real_sha(raw)
    if case == 'read_bytes': Path.read_bytes = read
    elif case == 'open': Path.open = opened
    elif case == 'io': io.open = io_open
    elif case == 'sha256': contract.sha256 = digest
    elif case == 'code': real_read.__code__ = replacement_code.__code__
    else: raise AssertionError(case)
sys.addaudithook(audit)
with tempfile.TemporaryDirectory(prefix='hia-mid-open-') as temporary:
    root = Path(temporary)
    (root / 'hepta').mkdir()
    (root / 'a').write_bytes(b'first')
    (root / 'b').write_bytes(b'second')
    (root / 'hepta/c.py').write_bytes(b'third')
    contract.SOURCE_FILES = ('b', 'a')
    def original(root):
        root = Path(root)
        names = sorted(set(contract.SOURCE_FILES) | {
            p.relative_to(root).as_posix() for p in (root / 'hepta').rglob('*.py')
        })
        return {p: contract.sha256((root / p).read_bytes()).hexdigest() for p in names}
    rows = []
    for case in ('read_bytes', 'open', 'io', 'sha256', 'code'):
        observations = []
        for function in (original, contract.file_digests):
            assert contract._source_protocol_current(root)
            state.update(enabled=True, changed=False, prefix=str(root) + '/', events=[], case=case)
            try:
                result = function(root)
                observations.append((list(result.items()), list(state['events'])))
            finally:
                state['enabled'] = False
                Path.read_bytes, Path.open, io.open, contract.sha256 = real_read, real_open, real_io, real_sha
                real_read.__code__ = original_code
        assert observations[0] == observations[1], (case, observations)
        rows.append({'case': case, 'equal': True, 'observations': observations})
    print(json.dumps({'cases': rows}))
'''
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
        result = subprocess.run([sys.executable, '-B', '-c', program], cwd=ROOT,
                                env=env, text=True, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        rows = json.loads(result.stdout)['cases']
        self.assertEqual([row['case'] for row in rows], ['read_bytes', 'open', 'io', 'sha256', 'code'])
        self.assertTrue(all(row['equal'] is True for row in rows))


    def test_hosted_agent_discovery_resources_are_in_actual_source_identity(self):
        from hepta.hia_agent_contract import DISCOVERY_FILES
        declared = validate_contract()["source_identity"]["files"]
        self.assertNotIn(CONTRACT_PATH, declared)  # generated identity cannot hash itself
        for filename in DISCOVERY_FILES:
            if "docs/" + filename == CONTRACT_PATH:
                continue  # validate_contract checks the generated complete content above
            path = ROOT / "docs" / filename
            self.assertEqual(declared[path.relative_to(ROOT).as_posix()],
                             sha256(path.read_bytes()).hexdigest())


    def test_release_freeze_inventory_covers_the_complete_selfhost_closure(self):
        from tools.hia_release import BOOTSTRAP_FILES
        from tools.hia_selfhost_contract import SOURCE_FILES
        declared = validate_contract()["source_identity"]["files"]
        explicit, bootstrap = set(SOURCE_FILES), set(BOOTSTRAP_FILES)
        package = {path.relative_to(ROOT).as_posix()
                   for path in (ROOT / "hepta").rglob("*.py")}
        # Bootstrap is the explicit release inventory, not a prefix partition.
        # Package modules can also be explicit native/build data resources;
        # those names must remain in both the full package closure and release.
        self.assertEqual(len(BOOTSTRAP_FILES), len(bootstrap))
        self.assertEqual(bootstrap, explicit | {CONTRACT_PATH})
        self.assertEqual(set(declared), explicit | package)
        # Retain the original complete non-package coverage constraint too.
        self.assertEqual({name for name in bootstrap
                          if name != CONTRACT_PATH and not name.startswith("hepta/")},
                         {name for name in declared if not name.startswith("hepta/")})

    def test_contract_binds_support_and_complete_seed_source_closure(self):
        contract = validate_contract()
        self.assertEqual(contract["profile"], PROFILE)
        self.assertEqual(contract["target"]["triple"], "x86_64-unknown-linux-gnu")
        self.assertEqual(contract["abi"]["entry"], "f0")
        files = contract["source_identity"]["files"]
        for path in (ROOT / "hepta").rglob("*.py"):
            self.assertEqual(files[path.relative_to(ROOT).as_posix()], sha256(path.read_bytes()).hexdigest())
        self.assertFalse(contract["claims"]["whole_HIA_language_self_hosted"])
        status = {row["area"]: row["status"] for row in contract["support"]}
        self.assertEqual(status["recursion"], "bounded_subset")
        recursion = next(row for row in contract["support"] if row["area"] == "recursion")
        self.assertEqual(recursion["limits"]["additional_frames_per_self_tail_call"], 0)
        self.assertFalse(recursion["limits"]["runtime_termination_proved"])
        self.assertIn("tools/hia_selfhost_tailcalls.py", files)
        resources = next(row for row in contract["support"] if row["area"] == "resources")
        self.assertIn("buffer.swap with both bounds before access", resources["items"])
        self.assertIn("tools/hia_selfhost_resources.py", files)
        self.assertIn("tools/hia_selfhost_select.py", files)
        self.assertIn("tools/hia_selfhost_loans.py", files)
        self.assertIn("exact capability graph joins and closed loop/edge transfers", resources["items"])
        operations = next(row for row in contract["support"] if row["area"] == "integer_operations")
        self.assertIn("select (bool condition, matching scalars including unit)", operations["items"])
        self.assertEqual(status["successor_object_output"], "bounded_subset")
        self.assertEqual(status["general_object_linking"], "not_implemented")
        self.assertEqual(status["owned_resources"], "bounded_subset")
        owned = next(row for row in contract["support"] if row["area"] == "owned_resources")
        self.assertEqual(owned["output_format"], "selfhost_elf or explicit scalar-export ELF only")
        self.assertEqual(owned["items"][:4], ["buffer.new", "buffer.try_new", "owner.move", "owner.drop"])
        self.assertFalse(owned["allocation"]["workspace_is_heap"])
        self.assertEqual(owned["allocation"]["imports"], ["calloc", "free"])
        self.assertEqual(owned["excluded"], ["more than three results"])
        self.assertEqual(contract["limits"]["internal_result_area_bytes"], 64)
        self.assertEqual(contract["limits"]["internal_result_stride_bytes"], 16)
        self.assertEqual(contract["limits"]["internal_result_descriptor_words"], 2)
        self.assertEqual(contract["limits"]["function_results"], 3)
        self.assertEqual(contract["abi"]["core_return"], "u32")
        for path in ("tools/hia_selfhost_owned_elf.py", "tools/hia_selfhost_owned_elf_cases.py",
                     "tools/qualify_hia_selfhost_owned_elf.py"):
            self.assertIn(path, files)

    def test_capacity_growth_preserves_workspace_and_core_byte_limits(self):
        from hepta.hia_program import MAX_BYTES, MAX_NODES
        from tools.hia_selfhost_limits import (MAX_INSTRUCTIONS, MAX_CORE_NODES,
            MAX_RELOCATIONS, RELOCATION_UPPER_BOUND, CORE_BYTES_UPPER_BOUND)
        contract = validate_contract()
        self.assertEqual(contract["limits"]["instructions"], MAX_INSTRUCTIONS)
        self.assertEqual(contract["limits"]["core_structural_nodes"], MAX_NODES)
        self.assertEqual(MAX_CORE_NODES, MAX_NODES)
        self.assertEqual(RELOCATION_UPPER_BOUND, 11522)
        self.assertEqual(MAX_RELOCATIONS, 12000)
        self.assertFalse(contract["limits"]["block_entry_must_be_first_in_source"])
        self.assertEqual(contract["limits"]["function_entry_block_index_record_offset"], 264)
        self.assertLessEqual(RELOCATION_UPPER_BOUND, MAX_RELOCATIONS)
        self.assertLess(CORE_BYTES_UPPER_BOUND, MAX_BYTES)
        for key in ("source_bytes", "output_capacity_bytes", "workspace_required_bytes"):
            self.assertEqual(contract["limits"][key], 1 << 20)
        self.assertFalse(contract["capacity_derivation"]["capacity_growth_changes_source_output_workspace_bytes"])

    def test_upgrade_refuses_an_unpinned_historical_image_before_execution(self):
        from tools.replay_hia_selfhost_upgrade import upgrade_replay
        with tempfile.TemporaryDirectory(prefix="hia-upgrade-refusal-") as temporary:
            root = Path(temporary)
            (root / "B3.input.bin").write_bytes(b"untrusted source")
            (root / "B3.image.bin").write_bytes(b"untrusted image")
            (root / "B3.receipt.json").write_text("{}")
            with self.assertRaisesRegex(ValueError, "pinned upgrade input"):
                upgrade_replay(root, root / "result.json")
            self.assertFalse((root / "result.evidence").exists())

    def test_changed_loader_or_broadened_support_cannot_reuse_the_contract(self):
        declared = validate_contract()
        with tempfile.TemporaryDirectory(prefix="hia-selfhost-contract-") as temporary:
            root = Path(temporary)
            for name in [*declared["source_identity"]["files"], CONTRACT_PATH]:
                destination = root / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / name, destination)
            validate_contract(root)
            loader = root / "tools/hia_selfhost_child.py"
            original = loader.read_bytes()
            loader.write_bytes(original + b"\n# changed loader\n")
            with self.assertRaisesRegex(ValueError, "source closure"):
                validate_contract(root)
            loader.write_bytes(original)
            broadened = json.loads((root / CONTRACT_PATH).read_text())
            broadened["limits"]["functions"] = 1024
            (root / CONTRACT_PATH).write_text(json.dumps(broadened))
            with self.assertRaisesRegex(ValueError, "source closure"):
                validate_contract(root)

    def test_cold_output_refuses_existing_and_symbolic_paths_before_creating_artifacts(self):
        with tempfile.TemporaryDirectory(prefix="hia-cold-output-refusal-") as temporary:
            root = Path(temporary)
            existing = root / "existing.json"
            existing.write_text("original")
            with self.assertRaisesRegex(ValueError, "new report"):
                cold_replay(existing)
            self.assertEqual(existing.read_text(), "original")
            leaf = root / "leaf.json"
            leaf.symlink_to(root / "absent.json")
            actual = root / "actual"
            actual.mkdir()
            linked = root / "linked"
            linked.symlink_to(actual, target_is_directory=True)
            dangling = root / "dangling"
            dangling.symlink_to(root / "missing", target_is_directory=True)
            for output in (leaf, linked / "report.json", dangling / "report.json"):
                with self.subTest(path=output), self.assertRaisesRegex(ValueError, "symbolic links"):
                    cold_replay(output)
            self.assertFalse((root / "absent.json").exists())
            self.assertEqual(list(actual.iterdir()), [])
            self.assertFalse((root / "missing").exists())


def cold_failure_diagnostic(output, result):
    """Retain actual bounded child diagnosis before temporary cleanup."""
    if result.get("status") == "COLD_SELFHOST_REPLAY_PASS":
        return result["checks"]
    diagnostic = {key: result.get(key) for key in
        ("status", "checks", "returncode", "wall_elapsed_ns", "process_owner")}
    directory = Path(output).with_suffix(".cold")
    for name in ("stdout.log", "stderr.log", "qualification.evidence/phase-index.json"):
        path = directory / name
        if not path.is_file():
            continue
        # The diagnostic cannot consume an unbounded log or replace the
        # original failed assertion with a secondary parser exception.
        try:
            size = path.stat().st_size
            with path.open("rb") as stream:
                stream.seek(max(0, size - 4096))
                tail = stream.read(4096)
                stream.seek(0)
                phase_bytes = stream.read(65537) if name.endswith("phase-index.json") else None
        except OSError as exc:
            diagnostic[name] = {"diagnostic_read_error": str(exc)}
            continue
        diagnostic[name] = {"bytes": size, "tail_sha256": sha256(tail).hexdigest(),
                            "actual_tail": tail.decode("utf-8", "replace")}
        if phase_bytes is not None and len(phase_bytes) <= 65536:
            try:
                phase = json.loads(phase_bytes)
                if isinstance(phase, dict):
                    diagnostic[name].update({k: phase.get(k) for k in ("completed", "exceptions")})
            except (ValueError, UnicodeError):
                diagnostic[name]["phase_json_malformed"] = True
    return diagnostic


@unittest.skipUnless(platform.system() == "Linux" and platform.machine().lower() in {"x86_64", "amd64"}
                     and shutil.which("ld"), "Linux x86-64 and GNU ld required")
class SelfhostColdReplayTests(unittest.TestCase):
    def test_source_only_clean_rebuild_has_original_and_modified_fixed_points(self):
        with tempfile.TemporaryDirectory(prefix="hia-cold-replay-test-") as temporary:
            output = Path(temporary) / "cold.json"
            result = cold_replay(output)
            self.assertEqual(result["status"], "COLD_SELFHOST_REPLAY_PASS", cold_failure_diagnostic(output, result))
            self.assertEqual(len(result["checks"]), 11)
            self.assertTrue(result["checks"]["owned_process_tree_cleanup_confirmed"])
            self.assertEqual(result["qualification_wall_limit_seconds"], 180)
            self.assertEqual(result["cleanup_wall_limit_seconds"], 3)
            self.assertEqual(result["process_owner"]["status"], "OWNED_PROCESS_COMPLETED")
            self.assertTrue(result["process_owner"]["cleanup"]["observed_echild"])
            self.assertTrue(result["process_owner"]["cleanup"]["leader_reaped"])
            self.assertEqual(len(set(result["generation_sha256"])), 1)
            first, second, third = result["modified_generation_sha256"]
            self.assertNotEqual(first, second)
            self.assertEqual(second, third)
            self.assertNotEqual(third, result["generation_sha256"][0])
            self.assertFalse(result["isolation"]["virtual_machine"])
            with self.assertRaisesRegex(ValueError, "new report"):
                cold_replay(output)


if __name__ == "__main__":
    unittest.main()
