"""Real Part04 children and independent v2 deadline replay; no Lean execution."""
from copy import deepcopy
import errno
from hashlib import sha256
import json
import os
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tests import test_core_seven_part04_capture as harness
from tools import core_seven_part04_capture as collector
from tools import diagnose_core_seven_part04 as part04
from tools import diagnose_core_seven_relocation as relocated


class Part04DeadlineTests(unittest.TestCase):
    def run_child(self, setup):
        return harness.Part04CaptureTests().run_child(
            'import os;os.write(1,%r)' % harness.lines(), setup=setup)

    def test_late_wait_return_is_failed_even_when_leader_and_streams_are_closed(self):
        state = dict(offset=0, delayed=False)
        def setup(safe, stack):
            popen, clock = collector.subprocess.Popen, time.monotonic
            def launch(*args, **kwargs):
                child = popen(*args, **kwargs)
                wait = child.wait
                def observe(*args, **kwargs):
                    code = wait(*args, **kwargs)
                    state.update(offset=2, delayed=True)
                    return code
                child.wait = observe
                return child
            stack.enter_context(patch.object(collector.subprocess, 'Popen', side_effect=launch))
            stack.enter_context(patch.object(collector, 'time', SimpleNamespace(monotonic=lambda:clock()+state['offset'])))
        result, files, _ = self.run_child(setup)
        self.assertTrue(state['delayed'])
        self.assertEqual(result['status'], 'diagnostic_infrastructure_failed')
        self.assertTrue(result['leader_reaped'])
        self.assertTrue(result['drain_complete'])
        self.assertTrue(result['cleanup_deadline_exceeded'])
        self.assertTrue(result['cleanup_incomplete'])
        terminal = json.loads(files[collector.DIAGNOSTIC_FILES[2]].splitlines()[-1])
        self.assertIs(terminal['process']['cleanup_deadline_exceeded'], True)

    def test_late_waitid_exit_observation_cannot_complete(self):
        state = dict(offset=0, delayed=False)
        def setup(safe, stack):
            waitid, clock = os.waitid, time.monotonic
            def observe(*args):
                result = waitid(*args)
                if result is not None and not state['delayed']:
                    state.update(offset=2, delayed=True)
                return result
            stack.enter_context(patch.object(collector.os, 'waitid', side_effect=observe))
            stack.enter_context(patch.object(collector, 'time', SimpleNamespace(monotonic=lambda:clock()+state['offset'])))
        result, _, _ = self.run_child(setup)
        self.assertTrue(state['delayed'])
        self.assertEqual(result['status'], 'diagnostic_timeout')
        self.assertTrue(result['leader_reaped'])

    def test_late_nonempty_read_counts_bytes_without_persisting_them(self):
        state = dict(offset=0, delayed=False)
        def setup(safe, stack):
            read, clock = os.read, time.monotonic
            def receive(fd, size):
                data = read(fd, size)
                if os.isatty(fd) and data and not state['delayed']:
                    state.update(offset=2, delayed=True)
                return data
            stack.enter_context(patch.object(collector.os, 'read', side_effect=receive))
            stack.enter_context(patch.object(collector, 'time', SimpleNamespace(monotonic=lambda:clock()+state['offset'])))
        result, files, _ = self.run_child(setup)
        self.assertTrue(state['delayed'])
        self.assertEqual(result['status'], 'diagnostic_timeout')
        self.assertGreater(result['observed_bytes']['stdout'], 0)
        self.assertEqual(files[collector.DIAGNOSTIC_FILES[0]], b'')
        self.assertEqual(result['marker_count'], 0)

    def cleanup_pause(self, *, stage):
        state = dict(offset=0, killed=False, delayed=False, wait_timeout=None)
        def setup(safe, stack):
            popen, clock, read, killpg = collector.subprocess.Popen, time.monotonic, os.read, os.killpg
            make_selector = collector.selectors.DefaultSelector
            def launch(*args, **kwargs):
                child = popen(*args, **kwargs)
                state['stderr_fd'] = child.stderr.fileno()
                wait = child.wait
                def observe(*args, **kwargs):
                    state['wait_timeout'] = kwargs['timeout']
                    return wait(*args, **kwargs)
                child.wait = observe
                return child
            def kill(pid, sig):
                killpg(pid, sig)
                state['killed'] = True
            def receive(fd, size):
                child_stream = os.isatty(fd) or fd == state.get('stderr_fd')
                error = None
                try:
                    data = read(fd, size)
                except OSError as caught:
                    if not child_stream or caught.errno != errno.EIO:
                        raise
                    error, data = caught, b''
                if child_stream and not data:
                    # Keep genuine EOF pending until the owner starts cleanup;
                    # no bytes or EOF are invented by this readiness fault.
                    if not state['killed']:
                        raise BlockingIOError(errno.EAGAIN, 'controlled pending EOF')
                    if stage == 'read' and not state['delayed']:
                        state.update(offset=2, delayed=True)
                if error is not None:
                    raise error
                return data
            def selector():
                instance = make_selector()
                select = instance.select
                def ready(*args):
                    found = select(*args)
                    if stage == 'select' and state['killed'] and not state['delayed']:
                        state.update(offset=2, delayed=True)
                        return []
                    return found
                instance.select = ready
                return instance
            stack.enter_context(patch.object(collector.subprocess, 'Popen', side_effect=launch))
            stack.enter_context(patch.object(collector.os, 'killpg', side_effect=kill))
            stack.enter_context(patch.object(collector.os, 'read', side_effect=receive))
            stack.enter_context(patch.object(collector.selectors, 'DefaultSelector', side_effect=selector))
            stack.enter_context(patch.object(collector, 'time', SimpleNamespace(monotonic=lambda:clock()+state['offset'])))
        result, _, _ = self.run_child(setup)
        self.assertTrue(state['delayed'])
        self.assertEqual(state['wait_timeout'], 0)
        self.assertTrue(result['leader_reaped'])
        self.assertTrue(result['cleanup_deadline_exceeded'])
        self.assertTrue(result['cleanup_incomplete'])
        self.assertEqual(result['status'], 'diagnostic_infrastructure_failed')

    def test_late_cleanup_read_does_not_renew_deadline(self):
        self.cleanup_pause(stage='read')

    def test_late_empty_select_does_not_renew_deadline(self):
        self.cleanup_pause(stage='select')


class Part04DeadlineReplayTests(unittest.TestCase):
    def capture(self, *, late=False):
        manifest = b'{"markers":[]}\n'
        reference = dict(path='diagnostic-manifest.json', sha256=sha256(manifest).hexdigest())
        original = collector.capture_result
        def invoke(*args, **kwargs):
            kwargs['safe_root'].write(reference['path'], manifest)
            return original(*args, **kwargs, manifest_reference=reference)
        state = dict(offset=0)
        def setup(safe, stack):
            if not late:
                return
            popen, clock = collector.subprocess.Popen, time.monotonic
            def launch(*args, **kwargs):
                child = popen(*args, **kwargs)
                wait = child.wait
                def observe(*args, **kwargs):
                    code = wait(*args, **kwargs)
                    state['offset'] = 3
                    return code
                child.wait = observe
                return child
            stack.enter_context(patch.object(collector.subprocess, 'Popen', side_effect=launch))
            stack.enter_context(patch.object(collector, 'time', SimpleNamespace(monotonic=lambda:clock()+state['offset'])))
        with patch.object(collector, 'capture_result', side_effect=invoke):
            result, files, _ = harness.Part04CaptureTests().run_child(
                'import os;os.write(1,%r)' % harness.lines(), setup=setup,
                overrides=(('PROCESS_SECONDS', 60), ('CLEANUP_SECONDS', 2)))
        files[reference['path']] = manifest
        files['SevenCertificatePart04.started.json'] = b'{}'
        return result, files

    def verify(self, reader, item):
        result, files = deepcopy(item)
        if reader is relocated:
            del result['files']
        frozen = {name:sha256(raw).hexdigest() for name,raw in files.items()}
        snapshot = SimpleNamespace(read=lambda name:files[name])
        run = dict(executable=result['argv'][0], root=result['cwd'])
        diagnostic = SimpleNamespace(manifest={'markers':harness.planned()},
            stages=[None]*5+[SimpleNamespace(module_name='HiaSyntaxResearch.CertPart04')])
        stage = dict(process=result, process_started=result['process_started'])
        return reader._verify_capture(snapshot, frozen, run, diagnostic, stage)

    def rewrite(self, item, changes):
        result, files = deepcopy(item)
        name = collector.DIAGNOSTIC_FILES[2]
        rows = [json.loads(line) for line in files[name].splitlines()]
        for key,value in changes.items():
            for record in (result,rows[-1]['process']):
                if value is self.missing:
                    record.pop(key)
                else:
                    record[key] = value
        raw = b''.join(collector._record_bytes(row) for row in rows)
        files[name] = raw
        reference = dict(path=name,bytes=len(raw),sha256=sha256(raw).hexdigest())
        result['files'][name] = reference
        result['compact_receipt_reference'] = reference
        result['metadata_written_bytes'] = len(raw)
        result['metadata_remaining_bytes'] = collector.METADATA_LIMIT-len(raw)
        return result,files

    missing = object()

    def test_complete_v2_capture_replays_in_both_consumers(self):
        item = self.capture()
        self.assertEqual(item[0]['trace'], 'p04-markers-v2')
        for reader in (part04,relocated):
            with self.subTest(reader=reader.__name__):
                self.assertTrue(self.verify(reader,item))

    def test_late_wait_replays_only_as_incomplete_cleanup(self):
        item = self.capture(late=True)
        self.assertTrue(item[0]['cleanup_deadline_exceeded'])
        for reader in (part04,relocated):
            with self.subTest(reader=reader.__name__):
                self.assertFalse(self.verify(reader,item))

    def test_rehashed_deadline_lies_and_legacy_trace_do_not_qualify(self):
        item = self.capture(late=True)
        mutations = [{'cleanup_deadline_exceeded':value} for value in (0,None,self.missing)]
        mutations += [{'cleanup_incomplete':False},{'status':'diagnostic_completed'},
                      {'trace':'p04-markers-v1'}]
        for reader in (part04,relocated):
            for change in mutations:
                with self.subTest(reader=reader.__name__,change=change):
                    with self.assertRaises(ValueError):
                        self.verify(reader,self.rewrite(item,change))
            # Flipping both balancing flags cannot make a retained late-failure
            # status a valid completed/timeout replay even after full rehashing.
            changed = self.rewrite(item,dict(cleanup_deadline_exceeded=False,cleanup_incomplete=False))
            self.assertFalse(self.verify(reader,changed))
            with self.assertRaisesRegex(ValueError,'legacy traces need their original checker'):
                self.verify(reader,self.rewrite(item,{'trace':'p04-markers-v1'}))


if __name__ == '__main__':
    unittest.main()
