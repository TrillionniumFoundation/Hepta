"""Synthetic protocol controls for permanent comparison continuation closure.

The image below is a Python reply fixture. It never loads, compiles or invokes
a native image and does not establish numeric correctness or native timing.
The original eleven source/Core-VM methods remain a separate denominator.
"""
from __future__ import annotations

import ctypes
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from hepta import hia_core_compare_native as bridge


class ReplyImage:
    def __init__(self, window=False):
        self.window = window
        self.calls = 0
        self.callback = None

    def _entry(self, input_buffer, input_size, output, output_size, state, state_size):
        self.calls += 1
        status = 1 if self.window and self.calls == 1 else 0
        if status:
            fields = (bridge.MAGIC, 1, 1, 0, 0, 1, *([0] * 10))
        else:
            fields = (bridge.MAGIC, int(self.window), 1, 1, *([0] * 12))
        raw = bridge.FRAME.pack(*fields)
        ctypes.memmove(output, raw, len(raw))
        if self.callback is not None:
            self.callback()
        return status


class NumericComparisonLifecycleSourceTests(unittest.TestCase):
    def closed(self, session, image):
        calls = image.calls
        self.assertTrue(session._closed)
        self.assertTrue(session.finished)
        self.assertFalse(session.pending or session.finish_pending or session.busy)
        self.assertIsNone(session.next_packet)
        self.assertIsNone(session.request)
        for function in (lambda: session.step(None), session.observe, session.finish):
            with self.assertRaises(RuntimeError):
                function()
        self.assertEqual(image.calls, calls)

    def caught_reentry(self, session, operation):
        try:
            {'step': lambda: session.step(None), 'observe': session.observe,
             'finish': session.finish}[operation]()
        except RuntimeError:
            return
        self.fail('invalid nested entry unexpectedly returned')

    def test_normal_done_and_window_completions_keep_single_finish(self):
        for window in (False, True):
            with self.subTest(window=window):
                image = ReplyImage(window)
                session = bridge.NumericCompareSession(image, 1, 1 << 80, 1 << 80)
                self.assertTrue(session.run())
                self.assertEqual(image.calls, 2 if window else 1)
                self.assertEqual([row[1] for row in session.actual_steps], [1, 0] if window else [0])
                self.assertEqual(len(session.actual_windows), int(window))
                self.closed(session, image)

    def test_caught_entry_reentry_cannot_restore_done_or_window(self):
        for window in (False, True):
            for operation in ('step', 'observe', 'finish'):
                with self.subTest(window=window, operation=operation):
                    image = ReplyImage(window)
                    session = bridge.NumericCompareSession(image, 1, 1 << 80, 1 << 80)
                    image.callback = lambda: self.caught_reentry(session, operation)
                    with self.assertRaises(RuntimeError):
                        session.step(session.next_packet)
                    self.assertEqual(image.calls, 1)
                    self.assertEqual(session.actual_steps, [])
                    self.closed(session, image)

    def test_caught_actual_step_ledger_reentry_does_not_grant_permission(self):
        for window in (False, True):
            for operation in ('step', 'observe', 'finish'):
                with self.subTest(window=window, operation=operation):
                    image = ReplyImage(window)
                    session = bridge.NumericCompareSession(image, 1, 1 << 80, 1 << 80)
                    seen = []
                    def append(row):
                        seen.append(row)
                        self.caught_reentry(session, operation)
                    session.actual_steps = SimpleNamespace(append=append)
                    with self.assertRaises(RuntimeError):
                        session.step(session.next_packet)
                    self.assertEqual(seen, [(0, int(window))])
                    self.closed(session, image)

    def test_caught_limb_and_representation_leaf_reentry_stops_next_leaf(self):
        for leaf in ('_limbs', '_ABS', '_TO_BYTES'):
            with self.subTest(leaf=leaf):
                image = ReplyImage(True)
                session = bridge.NumericCompareSession(image, 1, 1 << 80, 1 << 80)
                self.assertEqual(session.step(session.next_packet), 1)
                owner = session if leaf == '_limbs' else bridge
                original = getattr(owner, leaf)
                calls = []
                def returning(*args, **kwargs):
                    calls.append(leaf)
                    result = original(*args, **kwargs)
                    self.caught_reentry(session, 'finish')
                    return result
                original_to_bytes = bridge._TO_BYTES
                def later(*args, **kwargs):
                    calls.append('later_to_bytes')
                    return original_to_bytes(*args, **kwargs)
                with patch.object(owner, leaf, returning):
                    if leaf == '_ABS':
                        with patch.object(bridge, '_TO_BYTES', later), self.assertRaises(RuntimeError):
                            session.observe()
                    else:
                        with self.assertRaises(RuntimeError):
                            session.observe()
                self.assertEqual(calls, [leaf])
                self.assertEqual(session.actual_windows, [])
                self.closed(session, image)

    def test_caught_window_ledger_or_packet_return_reentry_cannot_grant_ack(self):
        for point in ('ledger', 'pack', 'unpack'):
            with self.subTest(point=point):
                image = ReplyImage(True)
                session = bridge.NumericCompareSession(image, 1, 1 << 80, 1 << 80)
                original_frame = bridge.FRAME
                if point == 'unpack':
                    def unpack(raw):
                        result = original_frame.unpack(raw)
                        self.caught_reentry(session, 'observe')
                        return result
                    frame = SimpleNamespace(pack=original_frame.pack, unpack=unpack)
                    with patch.object(bridge, 'FRAME', frame), self.assertRaises(RuntimeError):
                        session.step(session.next_packet)
                else:
                    self.assertEqual(session.step(session.next_packet), 1)
                    if point == 'ledger':
                        def append(row):
                            self.caught_reentry(session, 'step')
                        session.actual_windows = SimpleNamespace(append=append)
                        with self.assertRaises(RuntimeError):
                            session.observe()
                    else:
                        def pack(*args):
                            result = original_frame.pack(*args)
                            self.caught_reentry(session, 'step')
                            return result
                        frame = SimpleNamespace(pack=pack, unpack=original_frame.unpack)
                        with patch.object(bridge, 'FRAME', frame), self.assertRaises(RuntimeError):
                            session.observe()
                self.closed(session, image)

    def test_caught_transport_or_entry_binding_reentry_and_original_exception(self):
        for point in ('memmove', 'entry-binding', 'entry-error', 'ledger-error', 'leaf-error'):
            with self.subTest(point=point):
                image = ReplyImage(point == 'leaf-error')
                session = bridge.NumericCompareSession(image, 1, 1 << 80, 1 << 80)
                original_error = KeyboardInterrupt(point)
                def raises():
                    self.caught_reentry(session, 'finish')
                    raise original_error
                if point == 'memmove':
                    original = ctypes.memmove
                    def copy(*args):
                        result = original(*args)
                        self.caught_reentry(session, 'finish')
                        return result
                    with patch.object(ctypes, 'memmove', copy), self.assertRaises(RuntimeError):
                        session.step(session.next_packet)
                    self.assertEqual(image.calls, 0)
                elif point == 'entry-binding':
                    class EntryBinding:
                        @property
                        def _entry(inner):
                            self.caught_reentry(session, 'finish')
                            return image._entry
                    session.image = EntryBinding()
                    with self.assertRaises(RuntimeError):
                        session.step(session.next_packet)
                    self.assertEqual(image.calls, 0)
                else:
                    if point == 'entry-error':
                        image.callback = raises
                        invoke = lambda: session.step(session.next_packet)
                    elif point == 'ledger-error':
                        session.actual_steps = SimpleNamespace(append=lambda row: raises())
                        invoke = lambda: session.step(session.next_packet)
                    else:
                        self.assertEqual(session.step(session.next_packet), 1)
                        session._limbs = lambda *args: raises()
                        invoke = session.observe
                    with self.assertRaises(KeyboardInterrupt) as error:
                        invoke()
                    self.assertIs(error.exception, original_error)
                self.closed(session, image)


if __name__ == '__main__':
    unittest.main()
