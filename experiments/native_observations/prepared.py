"""Inherited typed adapters with an explicit dependency observer only."""
from pathlib import Path
import json
from experiments.c_char_boundary.prototype import Prepared as BasePrepared, MODES, PROFILE, digest
from .context import Context
from .observer import Observer


class Prepared(BasePrepared):
    def __init__(self, *args, _context=None, **kwargs):
        if type(_context) is not Context:
            raise TypeError('native observations require the original Context')
        self.observer = Observer(_context)
        try:
            super().__init__(*args, _context=_context, **kwargs)
        except BaseException:
            _context.closed = True
            raise

    def compile(self, **options):
        try:
            return self._compile(**options)
        except BaseException:
            self.observer.context.closed = True
            raise

    def _compile(self, *, optimize=False, native_source=None, lto=False, strict_aliasing=False):
        """Only fixed qualified flags; no caller-supplied late link/compile flags."""
        self._assert_current()
        ctx = self.context
        source = self._source()
        cfile = self.directory/'program.c'
        cfile.write_text(source)
        artifact = self.directory/'program'
        flags = ['-std=c11','-O3' if optimize else '-O0',*MODES[ctx.char_mode],
                 '-fexcess-precision=standard','-ffp-contract=off','-Wall','-Wextra',
                 '-Werror=incompatible-pointer-types','-Werror=implicit-function-declaration',
                 '-fsanitize=undefined','-fno-sanitize-recover=all',
                 '-fstrict-aliasing' if strict_aliasing else '-fno-strict-aliasing']
        if lto:
            flags += ['-flto','-Werror=lto-type-mismatch']
        inputs = [cfile]
        native_hash = None
        if native_source is not None:
            native_file = self.directory/'native.c'
            native_file.write_text('#include '+json.dumps(str(self.snapshot))+'\n'+native_source)
            native_hash = digest(native_file.read_bytes())
            inputs.append(native_file)
        objects, hashes = [], {}
        for index, input_file in enumerate(inputs):
            obj = self.directory/f'unit-{index}.o'
            dep = self.directory/f'unit-{index}.d'
            self.run([ctx.compiler[0],*flags,'-c',input_file,'-MD','-MF',dep,'-o',obj])
            objects.append(obj)
            hashes = self.observer.collect(dep)
        self.run([ctx.compiler[0],*flags,*objects,'-lm','-o',artifact])
        self._assert_current()
        receipt = {'profile':PROFILE,'status':'compiled_experimental', 'source_sha256':digest(source.encode()),
                   'artifact_sha256':digest(artifact.read_bytes()),'compiler':ctx.compiler,'flags':flags,
                   'context_source_sha256':ctx.source_hash,'header_sha256':ctx.header_hash,
                   'native_source_sha256':native_hash,'dependencies_observed_after_compile':hashes,
                   'foreign_binary_authenticated':False,'atomic_system_snapshot':False}
        return artifact, receipt
