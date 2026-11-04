"""One cumulative loader/native observation ledger, with explicit native roles."""
from dataclasses import dataclass
from pathlib import Path
from experiments.request_load.context import Context as LoaderContext, Limits as LoaderLimits
from experiments.loader_budget.prototype import Reader, Limits as ReadLimits


@dataclass(frozen=True)
class Limits(LoaderLimits):
    depfile: int = 262_144
    native_dependency: int = 16_000_000
    native_entries: int = 8192
    native_path_chars: int = 4096


class Context(LoaderContext):
    def __init__(self, limits=Limits(), checkpoint=lambda: None):
        if type(limits) is not Limits:
            raise TypeError('expected native observation Limits')
        super().__init__(limits, checkpoint)
        # Established before the first load, never upgraded/reset mid-request.
        self.reader = Reader(ReadLimits(max(limits.source, limits.manifest,
            limits.lock, limits.sidecar, limits.header, limits.depfile,
            limits.native_dependency), limits.total_bytes, limits.reads), self.check)
        self.counts['native_entries'] = 0

    def _cap(self, path, role):
        if role not in ('depfile', 'native_dependency'):
            return super()._cap(path, role)
        key = str(Path(path).resolve())
        cap = min(getattr(self.limits, role), self._role_caps.get(key, getattr(self.limits, role)))
        self._role_caps[key] = cap
        return cap
