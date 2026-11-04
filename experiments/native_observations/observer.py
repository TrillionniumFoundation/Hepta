"""Bounded GCC depfile observations, not a Make interpreter or atomic snapshot."""
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Observation:
    raw: str
    resolved: str
    digest: str


class Observer:
    def __init__(self, context):
        self.context = context
        self.cwd = Path.cwd()
        self._records = []
        self._digests = {}

    def _fail(self, message):
        self.context.reject(message)

    def _path(self, raw):
        if not raw or len(raw) > self.context.limits.native_path_chars or '\0' in raw:
            self._fail('native dependency path quota or syntax')
        path = Path(raw)
        return path if path.is_absolute() else self.cwd / path

    def _tokens(self, text):
        # A single GCC -MD rule. Reject unsupported/ambiguous Make syntax instead
        # of interpreting shell quoting, comments, variables or multiple rules.
        token = []
        target = True
        separator = False
        ended = False
        count = 0
        index = 0
        while index < len(text):
            if index % 1024 == 0:
                self.context.check()
            char = text[index]
            if char == '\\':
                index += 1
                if index == len(text): self._fail('truncated depfile escape')
                char = text[index]
                if char == '\n' and not token:
                    index += 1
                    continue
                # GCC does not universally escape literal backslashes; at a
                # filename boundary they can mimic continuations/space escapes.
                # Admit only whitespace-separated continuation tokens. Refuse
                # all path escapes rather than silently observe another file.
                self._fail('unsupported or ambiguous depfile path escape')
            elif char == '$':
                index += 1
                if index == len(text) or text[index] != '$':
                    self._fail('unsupported depfile variable')
            elif char == ':':
                if not target or not token or separator: self._fail('unsupported depfile rule')
                token.clear()
                target = False
                separator = True
                index += 1
                continue
            elif char in ' \t\r\n':
                if token:
                    if target: self._fail('unsupported depfile target')
                    if ended: self._fail('multiple depfile rules')
                    self.context.charge('native_entries')
                    count += 1
                    yield ''.join(token)
                    token.clear()
                if char in '\r\n': ended = True
                index += 1
                continue
            elif char in '#\0' or ord(char) < 32:
                self._fail('unsupported depfile character')
            if ended: self._fail('multiple depfile rules')
            token.append(char)
            if len(token) > self.context.limits.native_path_chars:
                self._fail('native dependency path quota exceeded')
            index += 1
        if token:
            if target or ended: self._fail('invalid depfile rule')
            self.context.charge('native_entries')
            count += 1
            yield ''.join(token)
        if not separator or not count: self._fail('empty depfile rule')

    def _observe(self, raw):
        path = self._path(raw)
        resolved = str(path.resolve(strict=True))
        value = self.context.digest(path, 'native_dependency')
        if str(path.resolve(strict=True)) != resolved:
            self._fail('native dependency binding changed during observation')
        return Observation(raw, resolved, value)

    def collect(self, depfile):
        try:
            text = self.context.read(depfile, 'depfile').decode('utf-8')
            for raw in self._tokens(text):
                record = self._observe(raw)
                previous = self._digests.get(record.resolved)
                if previous is not None and previous != record.digest:
                    self._fail('native dependency changed between observations')
                # Retain each observation, not last-writer-wins across TUs.
                self._records.append(record)
                self._digests[record.resolved] = record.digest
            return self.receipt()
        except BaseException:
            self.context.closed = True
            raise

    def receipt(self):
        # Compatibility presentation only. Never used as authority for rechecks.
        return {record.raw: record.digest for record in self._records}

    def revalidate(self, *, output=None, destination=None, protected=()):
        try:
            for record in self._records:
                self.context.charge('native_entries')
                current = self._observe(record.raw)
                if current.resolved != record.resolved or current.digest != record.digest:
                    self._fail('observed native dependency changed before publication')
            self.check_destination(output, destination, protected)
        except BaseException:
            self.context.closed = True
            raise

    def check_destination(self, output, destination, protected):
        """Last cooperative guard; sequential checks cannot exclude later writers."""
        try:
            self.context.check()
            if output is None: return
            current = self._path(output).resolve()
            if current != destination:
                self._fail('output binding changed before publication')
            protected = {Path(p).resolve() for p in protected}
            for record in self._records:
                resolved = self._path(record.raw).resolve(strict=True)
                if str(resolved) != record.resolved:
                    self._fail('native dependency binding changed before publication')
                protected.add(resolved)
            if current in protected:
                self._fail('output aliases an observed native dependency')
        except BaseException:
            self.context.closed = True
            raise
