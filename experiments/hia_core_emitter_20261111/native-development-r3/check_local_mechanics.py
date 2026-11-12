"""Finite local descriptor/mode controls; no installation, product or Actions."""
import json
import os
from pathlib import Path
import tempfile
from unittest.mock import patch
import runtime_metadata as subject
from common import wire

rows = []

def run(name, operation):
    operation()
    rows.append({'name': name, 'status': 'PASS'})

with tempfile.TemporaryDirectory(prefix='core-metadata-mode-controls-') as value:
    root = Path(value).resolve()
    def make(name, mode):
        path = root / name
        path.write_bytes(b'fixed metadata bytes\x00\n')
        path.chmod(mode)
        return path

    def normal():
        path = make('normal', 0o644)
        observed = subject.observe_file(path)
        admitted = subject.observe_file(path, repair=True, expected=observed)
        assert not admitted['mode_change_attempted']
        assert admitted['before'] == admitted['after']
        assert admitted['predicate_after']['all']
    run('0644 unchanged byte-and-identity observation', normal)

    def restrict():
        path = make('restrict', 0o666)
        observed = subject.observe_file(path)
        assert not observed['predicate_before']['all']
        admitted = subject.observe_file(path, repair=True, expected=observed)
        assert admitted['mode_change_attempted'] and admitted['after']['posix_mode'] == 0o644
        assert admitted['original'] == admitted['after_original'] == observed['original']
        assert admitted['bytes_and_nonmode_identity_unchanged'] and admitted['predicate_after']['all']
    run('0666 loses only 0022 on the same descriptor', restrict)

    def executable():
        path = make('executable', 0o775)
        observed = subject.observe_file(path)
        admitted = subject.observe_file(path, repair=True, expected=observed)
        assert admitted['after']['posix_mode'] == 0o755
        assert admitted['bytes_and_nonmode_identity_unchanged']
    run('non-write executable bits retained', executable)

    def refuse(name, configure):
        path, expected = configure()
        before = path.stat()
        seen = {}
        try:
            subject.observe_file(path, repair=True, expected=expected, observation=seen)
        except RuntimeError:
            assert path.stat().st_mode == before.st_mode
            assert seen['mode_change_attempted'] is False
        else:
            raise AssertionError(name + ' accepted')
    def linked():
        path = make('hardlink', 0o666)
        os.link(path, root / 'other-name')
        return path, subject.observe_file(path)
    run('hard-linked mutable metadata refused', lambda: refuse('hardlink', linked))
    def symlinked():
        target = make('symlink-target', 0o666)
        link = root / 'symlink'; link.symlink_to(target)
        return link, subject.observe_file(link)
    run('symlinked mutable metadata refused', lambda: refuse('symlink', symlinked))
    def changed():
        path = make('changed', 0o666)
        expected = subject.observe_file(path)
        path.write_bytes(b'changed bytes\n')
        return path, expected
    run('byte drift after installation observation refused', lambda: refuse('drift', changed))

    def after_effect_failure():
        path = make('effect-error', 0o666)
        observed = subject.observe_file(path)
        real = subject.digest_descriptor
        calls = 0
        def failing(fd, size):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError('injected post-fchmod read failure')
            return real(fd, size)
        captured = {}
        with patch.object(subject, 'digest_descriptor', failing):
            try:
                subject.observe_file(path, repair=True, expected=observed, observation=captured)
            except OSError:
                assert captured['mode_change_attempted'] is True
                assert captured['before']['posix_mode'] == 0o666
                assert captured['after']['posix_mode'] == path.stat().st_mode & 0o7777 == 0o644
                assert 'bytes_and_nonmode_identity_unchanged' not in captured
            else:
                raise AssertionError('post-effect failure accepted')
    run('post-effect failure retains attempted mutation evidence without success', after_effect_failure)

report = {'schema': 'hia.core-emitter-runtime-metadata-local-controls.v1',
          'status': 'PASS', 'runtime': __import__('sys').version,
          'scope': 'Local finite descriptor controls only. No installation or product execution.',
          'methods': rows, 'method_count': len(rows)}
with Path('LOCAL-MECHANICS.json').open('xb') as handle:
    handle.write(wire(report))
print(json.dumps(report, sort_keys=True))
