"""Real PTY/mock-only replay boundaries; never invokes Lean or admits proof."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tests import test_core_syntax_diagnostic_capture as harness
from tools import core_syntax_diagnostic_capture as capture
from tools import diagnose_core_byte_facts as runner
from tools.check_core_syntax_staged import SafeRoot, digest


class CaptureReplayTests(unittest.TestCase):
    def run_capture(self, script, *, markers=(), setup=None, overrides=(), observer=None):
        manifest = json.dumps({'markers': list(markers)}).encode()
        reference = {'path': 'diagnostic-manifest.json', 'sha256': digest(manifest)}
        original = capture.capture_result
        def invoke(*args, **kwargs):
            kwargs['safe_root'].write(reference['path'], manifest)
            return original(*args, **kwargs, manifest_reference=reference)
        with patch.object(capture, 'capture_result', side_effect=invoke):
            result, files, launches = harness.DiagnosticCaptureTests().run_child(
                script, target='CertPart02', markers=markers, setup=setup,
                overrides=overrides, observer=observer)
        return result, files, manifest, reference

    def verify(self, item):
        result, files, manifest, reference = item
        with tempfile.TemporaryDirectory() as folder:
            root = SafeRoot(Path(folder)/'fresh')
            try:
                root.write(reference['path'], manifest)
                for name, raw in files.items():
                    root.write(name, raw)
                runner._verify_capture(root, reference['sha256'], result)
            finally:
                root.close()

    def marker(self, index=0):
        return dict(id='HIA_DIAG_v1_P02_%03d' % index,
                    original_offset=index, instrumented_offset=index)

    def exact_budget(self, markers=(), short=0):
        # Set a tiny live budget after the real start record, using exact actual
        # serialized receive/marker sizes. Never enlarge the production budget.
        original_init = capture._Sink.__init__
        original_encode = capture._record_bytes
        sink = []
        def setup(root, stack):
            def initialize(obj, *args, **kwargs):
                original_init(obj, *args, **kwargs)
                sink.append(obj)
            def encode(value):
                raw = original_encode(value)
                if value.get('kind') == 'receive':
                    observer = capture.MarkerObserver(markers, target='CertPart02')
                    text = b''.join(('"'+m['id']+'" : String\n').encode() for m in markers)
                    events = observer('stdout', text, 0, value['received_seconds'])
                    cost = len(raw) + sum(len(original_encode(dict(kind='marker',event=e,
                        received_seconds=value['received_seconds']))) for e in events)
                    limit = sink[0].metadata_written + capture.TERMINAL_RESERVE + cost - short
                    self.assertLessEqual(limit, 12288)
                    capture.INTERNAL_METADATA_LIMIT = limit
                return raw
            stack.enter_context(patch.object(capture._Sink, '__init__', initialize))
            stack.enter_context(patch.object(capture, 'INTERNAL_METADATA_LIMIT', capture.INTERNAL_METADATA_LIMIT))
            stack.enter_context(patch.object(capture, '_record_bytes', encode))
        return setup

    def test_fragmented_default_budget_preserves_replayable_prefix(self):
        for stream in (1, 2):
            item = self.run_capture('import os,time\nfor i in range(200):\n os.write(%d,b"inert mock theorem line\\n");time.sleep(.002)' % stream)
            result, files, _, _ = item
            self.assertEqual(result['status'], 'diagnostic_infrastructure_failed')
            self.assertIn('metadata budget', result['error'])
            self.assertGreater(sum(result['observed_bytes'].values()), result['raw_written_bytes'])
            self.verify(item)
            rows = [json.loads(x) for x in files['CertPart02.events.jsonl'].splitlines()]
            self.assertEqual(sum(r['bytes'] for r in rows if r['kind']=='receive'),result['raw_written_bytes'])

    def test_exact_fit_and_one_byte_short_receive_and_marker_batches(self):
        for count in (0, 1, 2):
            markers = tuple(self.marker(i) for i in range(count))
            data = b''.join(('"'+m['id']+'" : String\n').encode() for m in markers) or b'x'
            for short in (0, 1):
                with self.subTest(count=count,short=short):
                    item = self.run_capture('import os,time;os.write(1,%r);time.sleep(10)' % data,
                        markers=markers,setup=self.exact_budget(markers,short),
                        overrides=(('PROCESS_SECONDS',.15),))
                    result, files, _, _ = item
                    self.assertEqual(result['status'], 'diagnostic_infrastructure_failed' if short else 'diagnostic_timeout')
                    self.assertEqual(files['CertPart02.stdout'], b'' if short else data)
                    self.assertEqual(result['marker_count'],0 if short else count)
                    self.assertEqual(result['observed_bytes']['stdout'],len(data))
                    self.verify(item)

    def test_split_markers_and_both_stream_orders_replay(self):
        marker = self.marker()
        data = ('"'+marker['id']+'" : String\n').encode()
        for order in (0,1):
            script = 'import os,time\n'
            if order: script += 'os.write(2,b"before\\n");time.sleep(.02)\n'
            script += 'os.write(1,%r);time.sleep(.02);os.write(1,%r)\n' % (data[:12],data[12:])
            if not order: script += 'time.sleep(.02);os.write(2,b"after\\n")\n'
            # Keep the child alive to isolate marker replay from the separately
            # tested fail-closed PTY slave-close/waitid-exit race.
            item = self.run_capture(script+'time.sleep(10)\n',markers=(marker,),
                                    overrides=(('PROCESS_SECONDS',.15),))
            self.assertEqual(item[0]['status'],'diagnostic_timeout',item[0])
            self.assertEqual(item[0]['marker_count'],1)
            self.verify(item)

    def test_observer_errors_invalid_events_and_serialization_reject_before_raw(self):
        def fail(*args): raise ValueError('observer failure')
        def cancel(*args): raise KeyboardInterrupt('cancel')
        for observer in (fail,cancel,lambda *a:[1],lambda *a:[{'bad':float('nan')}],
                         lambda *a:[{}]*25):
            item=self.run_capture('import os,time;os.write(1,b"rejected secret");time.sleep(10)',observer=observer)
            self.assertNotEqual(item[0]['status'],'diagnostic_completed')
            self.assertEqual(item[1]['CertPart02.stdout'],b'')
            self.assertEqual(item[0]['marker_count'],0)
            self.verify(item)

    def test_rejected_read_does_not_refund_raw_quota_or_claim_completion(self):
        item=self.run_capture('import os;os.write(1,b"x")',setup=self.exact_budget(short=1),
                              overrides=(('RAW_LIMIT',1),))
        self.assertEqual(item[0]['observed_bytes']['stdout'],1)
        self.assertEqual(item[0]['raw_written_bytes'],0)
        self.assertEqual(item[0]['status'],'diagnostic_infrastructure_failed')
        with patch.object(capture,'RAW_LIMIT',1):
            self.verify(item)

    def test_partial_metadata_write_remains_unreplayable(self):
        original=capture._Sink.append
        def setup(root,stack):
            def append(obj,name,data,terminal=False):
                if name.endswith('.events.jsonl') and b'"kind":"receive"' in data:
                    original(obj,name,b'{\n',terminal=terminal)
                    raise OSError('injected partial metadata write')
                return original(obj,name,data,terminal=terminal)
            stack.enter_context(patch.object(capture._Sink,'append',append))
        item=self.run_capture('import os;os.write(1,b"rejected data")',setup=setup)
        self.assertEqual(item[0]['status'],'diagnostic_infrastructure_failed')
        with self.assertRaises((ValueError,KeyError)):
            self.verify(item)

    def test_zero_metadata_write_and_raw_fsync_failure_refuse_replay(self):
        for failure in ('zero_metadata_write','raw_fsync'):
            def setup(root,stack):
                original_init=capture._Sink.__init__
                original_write=capture.os.write
                original_fsync=capture.os.fsync
                sinks=[]
                def initialize(obj,*args,**kwargs):
                    original_init(obj,*args,**kwargs)
                    sinks.append(obj)
                def write(fd,data):
                    if sinks and failure=='zero_metadata_write' and fd==sinks[0].files['CertPart02.events.jsonl']['fd'] and b'"kind":"receive"' in bytes(data):
                        return 0
                    return original_write(fd,data)
                def fsync(fd):
                    if sinks and failure=='raw_fsync' and fd==sinks[0].files['CertPart02.stdout']['fd']:
                        raise OSError('injected raw fsync failure')
                    return original_fsync(fd)
                stack.enter_context(patch.object(capture._Sink,'__init__',initialize))
                stack.enter_context(patch.object(capture.os,'write',write))
                stack.enter_context(patch.object(capture.os,'fsync',fsync))
            with self.subTest(failure=failure):
                item=self.run_capture('import os;os.write(1,b"untrusted tail")',setup=setup)
                self.assertEqual(item[0]['status'],'diagnostic_infrastructure_failed')
                self.assertEqual(item[0]['marker_count'],0)
                with self.assertRaises(ValueError):
                    self.verify(item)

    def test_split_marker_completion_rejected_keeps_prior_prefix_replayable(self):
        marker=self.marker()
        data=('"'+marker['id']+'" : String\n').encode()
        item=self.run_capture('import os,time;os.write(1,%r);time.sleep(.03);os.write(1,%r);time.sleep(10)' %
            (data[:12],data[12:]), markers=(marker,),setup=self.exact_budget((marker,),short=1))
        self.assertEqual(item[0]['status'],'diagnostic_infrastructure_failed')
        self.assertEqual(item[0]['marker_count'],0)
        self.assertEqual(item[1]['CertPart02.stdout'],data[:12])
        self.assertEqual(item[0]['observed_bytes']['stdout'],len(data))
        self.verify(item)
