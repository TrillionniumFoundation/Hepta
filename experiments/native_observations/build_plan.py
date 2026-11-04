"""Opt-in native dependency observation plan. No production/CLI integration."""
from pathlib import Path
import os
import tempfile
import uuid
from experiments.c_char_boundary.build_plan import (Request, admit, Budget, PrivateImporter,
    _protected_inputs, require, digest)
from .context import Context, Limits
from .prepared import Prepared


def execute(request, *, limits=Limits(), seconds=60, output_bytes=2_000_000):
    """One fresh plan per call. No context/receipt is accepted as an input."""
    admit(request)  # Must happen before budget creation, graph loading or probing.
    budget=Budget(seconds,output_bytes)
    context=Context(limits, budget.checkpoint)
    try:
        return _execute(request, budget, context, output_bytes)
    finally:
        context.closed=True


def _execute(request, budget, context, output_bytes):
    request_id=uuid.uuid4().hex
    project=context.load(request.entry,locked=request.locked)
    protected=_protected_inputs(project,request)
    destination=Path(request.output).resolve() if request.output else None
    if destination:
        require(destination not in protected, 'output aliases a qualification input')
    budget.checkpoint()
    importer=PrivateImporter(budget)
    try:
        with Prepared(request.entry,cc=request.cc,char_mode=request.char_mode,
                      _runner=budget.run,_importer=importer.module.import_header,
                      _project=project,_locked=request.locked,_context=context) as prepared:
            require(destination is None or not destination.is_relative_to(prepared.directory),
                    'output aliases private qualification inputs')
            artifact,receipt=prepared.compile(optimize=request.optimize,strict_aliasing=True)
            budget.checkpoint()
            prepared.observer.revalidate()
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
                    prepared.observer.revalidate(output=request.output, destination=destination,
                                                 protected=protected)
                    budget.checkpoint()
                    prepared.observer.check_destination(request.output, destination, protected)
                    os.replace(staged,destination)
                finally:
                    if staged is not None:staged.unlink(missing_ok=True)
                result['artifact']=str(destination)
                result['artifact_sha256']=digest(destination.read_bytes())
            elif request.command=='run':
                prepared.observer.revalidate()
                execution=budget.capture([artifact],timeout=30,stdout_limit=output_bytes,
                                         stderr_limit=output_bytes)
                result.update(user_program_executed=True,ok=execution.returncode==0,
                              returncode=execution.returncode,stdout=execution.stdout,
                              stderr=execution.stderr)
            result['native_invocations']=len(budget.commands)
            return result
    finally:
        importer.close()
        context.closed=True
