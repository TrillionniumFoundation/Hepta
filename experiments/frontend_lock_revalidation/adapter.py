"""One owner, one check, one final validation; no native or publication authority.

Only loader work is admitted. Checking, emission and hashing are synchronous and
unmetered; cancellation is cooperative at the surrounding checkpoints.
"""
import threading
from types import MappingProxyType

from hepta import pipeline
from hepta.ast import Diagnostic, Span
from experiments.policy_failures.owner import Cancelled, Failure, Policy, Rejected
from .owner import Owner


class FrontendRequest:
    """Single-use, creation-thread-bound frontend request.

    `config` is an exact dictionary containing only an optional exact bool
    `locked`. It is copied; subsequent caller mutations do not change a request.
    `cancel` may be called from another thread, but `check` may not. Returned
    frontend diagnostics (including a graph race) are ordinary Analysis outcomes,
    not first-origin exception records. Every outcome ends this request.
    """

    def __init__(self, *, policy=None, config=None, checkpoint=lambda: None):
        if config is None:
            config = {}
        if type(config) is not dict:
            raise TypeError('config must be an exact dictionary')
        if any(type(key) is not str or key != 'locked' for key in config):
            raise ValueError('only locked is admitted by the frontend adapter')
        locked = config.get('locked', False)
        if type(locked) is not bool:
            raise TypeError('locked must be an exact bool')
        if not callable(checkpoint):
            raise TypeError('checkpoint must be callable')
        self.config = MappingProxyType({'locked': locked})
        self._config = self.config
        self._locked = locked
        self.lock_revalidation = 'not_completed' if locked else 'not_requested'
        self.policy = Policy() if policy is None else policy
        self._policy = self.policy
        self._callback = checkpoint
        self._cancelled = threading.Event()
        self._thread = threading.get_ident()
        self._state = 'new'
        self.phase = 'configuration'
        self.handle = None
        # Owner is created before entry is even supplied, resolved or read.
        self.owner = Owner(self.policy, checkpoint=self._checkpoint)
        self._owner = self.owner
        self._context = self.owner.context
        self._ops = self.owner._ops
        self._reader = self._context.reader

    def cancel(self):
        """Signal this request only; never interrupt synchronous analysis."""
        self._cancelled.set()

    def _guard(self):
        context = self._context
        if (self.owner is not self._owner or self.policy is not self._policy
                or self._owner.context is not self._context
                or self._owner._ops is not self._ops
                or self._ops.context is not self._context
                or self._context.reader is not self._reader
                or self.config is not self._config
                or len(self._config) != 1
                or any(type(key) is not str or key != 'locked' for key in self._config)
                or type(self._config.get('locked')) is not bool
                or self._config['locked'] is not self._locked):
            # Preserve the original reader observations even if `context.reader`
            # itself was replaced. Never repair or operate the substituted ledger.
            if context.failure is None:
                context.failure = Failure('policy_drift', 'adapter_config',
                                          observed_bytes=self._reader.bytes_read,
                                          observed_reads=self._reader.reads)
            context.closed = True
            raise Rejected('adapter configuration drift', context.failure)

    def _checkpoint(self):
        self._guard()
        if self._cancelled.is_set():
            raise Cancelled('frontend request cancelled')
        self._callback()
        self._guard()
        if self._cancelled.is_set():
            raise Cancelled('frontend request cancelled')

    def _stage(self, phase):
        self.phase = phase
        self._guard()
        self._context.check()

    def _finish_check(self, unchanged):
        # No caller callback after the final owned validation. This is still not
        # an atomic filesystem snapshot: inherited validation has checkpoints.
        self.phase = 'after_revalidation'
        self._guard()
        self._context._drift()
        if threading.get_ident() != self._thread:
            self._context.reject('frontend request cannot cross threads', category='thread', phase='adapter')
        failure = self._context.failure
        if failure is not None and (unchanged or failure.category != 'io'):
            self._context.reject('frontend request is terminal', category='lifecycle', phase='adapter')
        if self._cancelled.is_set():
            raise Cancelled('frontend request cancelled')

    def check(self, entry, *, source_overrides=None):
        """Return the real pipeline Analysis, or preserve an original exception.

        No call to analyze_project/public load_project/public unchanged is made.
        The raw entry spelling reaches Owner.load without adapter conversion.
        """
        context = self._context
        try:
            if context.failure is not None:
                context.reject('frontend request is terminal', category='lifecycle', phase='adapter')
            self._guard()
            if threading.get_ident() != self._thread:
                context.reject('frontend request cannot cross threads', category='thread', phase='adapter')
            if self._state == 'running':
                context.reject('reentrant frontend request', category='reentrancy', phase='adapter')
            if self._state != 'new':
                context.reject('frontend request has already completed', category='lifecycle', phase='adapter')
            self._state = 'running'
            if source_overrides is not None:
                context.reject('source overrides are not admitted', category='schema', phase='adapter')
            self._stage('before_load')
            self.handle = self._owner.load(entry, locked=self._locked)
            handle = self.handle  # Retain this exact handle across the whole pipeline.
            project = handle.project
            source = project.source_bytes[str(project.entry)].decode('utf-8')
            self._stage('before_analysis')
            result = pipeline.analyze(source, str(project.entry),
                                      loaded_project=project, native=False)
            self._stage('after_analysis')
            self.phase = 'revalidation'
            unchanged = self._owner.revalidate(handle)
            # A swallowed I/O failure can yield False with a sticky original
            # record. Preserve that ordinary legacy race report, not a new throw.
            self._finish_check(unchanged)
            if not unchanged:
                result.report['ok'] = False
                result.report['status'] = 'rejected'
                result.report['diagnostics'].append(Diagnostic(
                    'E_MODULE_RACE', 'Source graph changed during validation',
                    Span(path=str(project.entry)), phase='module').to_dict())
            elif context.failure is not None:
                context.reject('frontend request is terminal', category='lifecycle', phase='adapter')
            self.lock_revalidation = (
                'post_analysis_observed' if unchanged and self._locked else
                'not_completed' if self._locked else 'not_requested')
            return result
        except BaseException as error:
            self.lock_revalidation = 'not_completed' if self._locked else 'not_requested'
            context.record(error=error, phase=self.phase)
            raise
        finally:
            self._state = 'finished'
            context.closed = True
