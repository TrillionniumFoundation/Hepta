"""Isolated orchestration experiment. Not imported by production or the CLI.

This is a deadline/output-budgeted request lifecycle, not a native-code sandbox
or a hard real-time guarantee. Cleanup can exceed the admission deadline.
"""
from dataclasses import dataclass
import importlib.util
import json
import math
import os
from pathlib import Path
import shutil
import sys
import tempfile
import time
import uuid

from hepta import c_import
from hepta.clang_capture import CaptureRejected, run_bounded
from hepta.modules import load_project
from .prototype import Prepared, Rejected, MODES, require, digest


@dataclass(frozen=True)
class Request:
    entry: str
    command: str
    output: str | None = None
    backend: str = 'c'
    crate_type: str = 'bin'
    profile: str = 'plain-char-v1'
    cc: str = 'gcc'
    char_mode: str = 'default'
    locked: bool = False
    optimize: bool = True
    target: str | None = None
    no_std: bool = False
    frontend_only: bool = False
    source_overrides: object = None
    link_args: tuple = ()
    debug: bool = False
    c_opt: str = 'default'


def admit(request):
    require(type(request) is Request, 'expected immutable Request')
    for value in (request.entry,request.cc,request.command,request.backend,
                  request.crate_type,request.profile,request.char_mode,request.c_opt):
        require(type(value) is str and bool(value.strip()) and '\0' not in value,
                'expected nonempty text/path options')
    require(request.output is None or (type(request.output) is str
            and bool(request.output.strip()) and '\0' not in request.output),
            'expected nonempty output path')
    require(all(type(value) is bool for value in (request.locked,request.optimize,
            request.no_std,request.frontend_only,request.debug)), 'expected boolean options')
    require(type(request.link_args) is tuple,'expected immutable link argument list')
    require(request.command in {'check','build','run'} and request.backend=='c'
            and request.crate_type=='bin' and request.profile=='plain-char-v1',
            'unsupported command/backend/artifact/profile')
    require(request.char_mode in MODES and request.target is None and not request.no_std
            and not request.frontend_only and request.source_overrides is None
            and not request.link_args and not request.debug and request.c_opt=='default',
            'unsupported request options')
    require(type(request.locked) is bool and type(request.optimize) is bool,
            'boolean options must be explicit booleans')
    require((request.command=='build') == (request.output is not None),
            'only build requires an output path')


class Budget:
    def __init__(self, seconds=60, output_bytes=2_000_000, calls=64):
        require(type(seconds) in {int,float} and math.isfinite(seconds) and 0<seconds<=120,
                'invalid deadline')
        require(type(output_bytes) is int and 0<output_bytes<=4_000_000,
                'invalid output quota')
        require(type(calls) is int and 0<calls<=128, 'invalid invocation quota')
        self.deadline=time.monotonic()+seconds
        self.remaining_output=output_bytes
        self.remaining_calls=calls
        self.closed=False
        self.commands=[]

    def checkpoint(self):
        require(not self.closed, 'budget is terminal')
        remaining=self.deadline-time.monotonic()
        if remaining<=0:
            self.closed=True
            raise Rejected('whole request deadline exceeded')
        return remaining

    def capture(self, argv, *, timeout=60, stdout_limit=512_000, stderr_limit=512_000):
        remaining=self.checkpoint()
        require(self.remaining_calls>0, 'native invocation quota exceeded')
        self.remaining_calls-=1
        command=[str(x) for x in argv]
        self.commands.append(tuple(command))
        try:
            result=run_bounded(command,timeout=min(timeout,remaining),stdin_limit=0,
                stdout_limit=min(stdout_limit,self.remaining_output),
                stderr_limit=min(stderr_limit,self.remaining_output))
            used=len(result.raw_stdout or b'')+len(result.raw_stderr or b'')
            self.remaining_output-=used
            require(self.remaining_output>=0, 'aggregate native output quota exceeded')
            self.checkpoint()
            return result
        except BaseException:
            self.closed=True
            raise

    def run(self, argv):
        result=self.capture(argv)
        require(result.returncode==0, 'native command rejected: '+result.stderr)
        return result.stdout


class PrivateImporter:
    """Experiment-only dependency injection, never patch production module globals.

    Load the same trusted repository importer in a request-private module, then
    route its existing native-process hook through the shared request budget.
    Production integration needs an explicit reviewed injection API instead.
    """
    def __init__(self,budget):
        self.name='hepta._char_plan_'+uuid.uuid4().hex
        spec=importlib.util.spec_from_file_location(self.name,c_import.__file__)
        self.module=importlib.util.module_from_spec(spec)
        sys.modules[self.name]=self.module
        try:
            spec.loader.exec_module(self.module)
            def native(argv,*,timeout,stdout_limit=64_000):
                try:
                    return budget.capture(argv,timeout=timeout,stdout_limit=stdout_limit)
                except CaptureRejected as error:
                    self.module.reject('PROBE_CAPTURE',str(error))
            self.module._native_process=native
        except BaseException:
            self.close()
            raise

    def close(self):
        sys.modules.pop(self.name,None)


def _protected_inputs(project,request):
    require(len(project.c_imports)==1, 'exactly one native import required')
    require(sum(len(data) for data in project.source_bytes.values())<=8_000_000,
            'loaded graph exceeds experimental admission quota')
    item=project.c_imports[0]
    metadata=json.loads(project.source_bytes[str(Path(item['manifest']))])
    header=Path(metadata['header'])
    if metadata.get('header_path_kind')=='relative_to_manifest':
        header=Path(item['manifest']).parent/header
    require(header.is_file() and header.stat().st_size<=1_000_000,
            'native header exceeds experimental admission quota')
    origin=Path(item['source']).resolve()
    externs=[f for f in project.program.functions if f.extern_c]
    require(externs and all(Path(f.span.path).resolve()==origin for f in externs),
            'extern declaration has no unique imported module origin')
    require(not any(f.export_c for f in project.program.functions),
            'exports are not admitted by this build-plan profile')
    compiler=Path(shutil.which(request.cc) or request.cc).resolve()
    protected={Path(p).resolve() for p in project.sources}|{header.resolve(),compiler}
    return protected


def execute(request, *, seconds=60, output_bytes=2_000_000):
    """One fresh plan per call. No context/receipt is accepted as an input."""
    admit(request)  # Must happen before budget creation, graph loading or probing.
    budget=Budget(seconds,output_bytes)
    request_id=uuid.uuid4().hex
    project=load_project(request.entry,locked=request.locked)
    protected=_protected_inputs(project,request)
    destination=Path(request.output).resolve() if request.output else None
    if destination:
        require(destination not in protected, 'output aliases a qualification input')
    budget.checkpoint()
    importer=PrivateImporter(budget)
    try:
        with Prepared(request.entry,cc=request.cc,char_mode=request.char_mode,
                      _runner=budget.run,_importer=importer.module.import_header,
                      _project=project,_locked=request.locked) as prepared:
            require(destination is None or not destination.is_relative_to(prepared.directory),
                    'output aliases private qualification inputs')
            artifact,receipt=prepared.compile(optimize=request.optimize,strict_aliasing=True)
            budget.checkpoint()
            # Final -MD observations include implicit compiler inputs absent from
            # the source graph (for example a wrapper's forced include). Protect
            # every observed input before any output staging/publication.
            protected.update(Path(p).resolve() for p in receipt['dependencies_observed_after_compile'])
            require(destination is None or destination not in protected,
                    'output aliases an observed native dependency')
            result={'experimental':True,'request_id':request_id,'command':request.command,
                    'ok':True,'receipt':receipt,'user_program_executed':False,
                    'foreign_binary_authenticated':False,'hard_realtime_bound':False}
            if request.command=='build':
                require(artifact.stat().st_size<=16_000_000,'artifact exceeds publication quota')
                destination.parent.mkdir(parents=True,exist_ok=True)
                staged=None
                try:
                    with tempfile.NamedTemporaryFile(dir=destination.parent,prefix='.char-plan-',delete=False) as f:
                        staged=Path(f.name)
                        f.write(artifact.read_bytes())
                    staged.chmod(0o755)
                    require(digest(staged.read_bytes())==receipt['artifact_sha256'],
                            'staged artifact differs from final native compilation')
                    prepared._assert_current()
                    for path, expected in receipt['dependencies_observed_after_compile'].items():
                        dependency=Path(path)
                        require(dependency.is_file() and digest(dependency.read_bytes())==expected,
                                'observed native dependency changed before publication')
                    budget.checkpoint()
                    os.replace(staged,destination)
                finally:
                    if staged is not None:staged.unlink(missing_ok=True)
                result['artifact']=str(destination)
                result['artifact_sha256']=digest(destination.read_bytes())
            elif request.command=='run':
                execution=budget.capture([artifact],timeout=30,stdout_limit=output_bytes,
                                         stderr_limit=output_bytes)
                result.update(user_program_executed=True,ok=execution.returncode==0,
                              returncode=execution.returncode,stdout=execution.stdout,
                              stderr=execution.stderr)
            result['native_invocations']=len(budget.commands)
            return result
    finally:
        importer.close()
