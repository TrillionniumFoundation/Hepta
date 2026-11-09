"""Real relocation timeout cleanup controls separate from the relocation runner inventory."""
from contextlib import ExitStack
import errno
import os
import subprocess
import sys
import time
import unittest
from unittest.mock import patch

from tests import test_core_seven_relocation_runner as harness


class RelocationTimeoutTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        harness.Part04RunnerTests.setUpClass()

    def exercise(self, *, cleanup_pause=0, start_pause=0, clean=True):
        case = harness.Part04RunnerTests('test_complete_failure_replay_and_spawn_semantics')
        popen, read, killpg = subprocess.Popen, os.read, os.killpg
        state = dict(killed=False, paused=False)
        def launch(argv, **kwargs):
            self.assertEqual(argv[:2],[sys.executable,'-c'])
            if start_pause:
                argv = argv[:2]+['import time\ntime.sleep(%r)\n'%start_pause+argv[2]]
            child = popen(argv, **kwargs)
            state['stderr_fd'] = child.stderr.fileno()
            return child
        def kill(pid, sig):
            killpg(pid, sig)
            state['killed'] = True
        def receive(fd, size):
            if cleanup_pause and state['killed'] and fd == state.get('stderr_fd') and not state['paused']:
                state['paused'] = True
                time.sleep(cleanup_pause)
                # Preserve genuine EOF for the next poll; do not invent bytes,
                # exits or successful reads to make the capture complete.
                raise BlockingIOError(errno.EAGAIN,'controlled transient cleanup readiness')
            return read(fd,size)
        def inspect(path, report, identity, support):
            result = case.replay(path,identity,support)
            process = report['stages'][-1]['process']
            self.assertEqual(result['validated_markers'],clean)
            self.assertEqual(process['cleanup_incomplete'],not clean)
            self.assertEqual(process['cleanup_deadline_exceeded'],not clean)
            self.assertTrue(process['leader_reaped'])
            self.assertTrue(process['group_kill_sent'])
            self.assertEqual(process['timeout_seconds'],60)
            if start_pause:
                self.assertEqual(process['marker_count'],0)
                self.assertEqual(process['observed_bytes'],{'stdout':0,'stderr':0})
            elif clean:
                self.assertEqual(process['marker_count'],11)
            if cleanup_pause:
                self.assertTrue(state['paused'])
        with ExitStack() as stack:
            stack.enter_context(patch.object(harness.collector.subprocess,'Popen',side_effect=launch))
            stack.enter_context(patch.object(harness.collector.os,'killpg',side_effect=kill))
            stack.enter_context(patch.object(harness.collector.os,'read',side_effect=receive))
            case.exercise('target_timeout',inspect,timeout_ready_seconds=.1 if start_pause else 5)

    def test_short_transient_cleanup_delay_keeps_real_two_second_budget(self):
        self.exercise(cleanup_pause=.04)

    def test_cleanup_delay_over_two_seconds_still_fails(self):
        self.exercise(cleanup_pause=2.1,clean=False)

    def test_preoutput_timeout_replays_empty_prefix_without_inventing_markers(self):
        self.exercise(start_pause=.7)


if __name__ == '__main__':
    unittest.main()
