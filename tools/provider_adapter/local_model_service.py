#!/usr/bin/env python3
"""Optional CPU causal-model service; inference only, no execution tools.

Weights/tokenizers must already exist as locked regular files. This program
never downloads weights, uses remote model code, or reads evaluator solutions.
"""
from __future__ import annotations

import argparse
import datetime
import importlib.metadata
import json
import math
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import platform
import sys
import time
import uuid

try:
    from .local_model_common import (canonical, digest, file_digest, freeze_model,
                                    model_identity, regular, validate_lock, verify_assets)
except ImportError:
    from local_model_common import (canonical, digest, file_digest, freeze_model,
                                   model_identity, regular, validate_lock, verify_assets)

MAX_BODY = 4 * 1024**2


def render_prompt(tokenizer, messages, prompt_format):
    if prompt_format == 'tokenizer_chat_template':
        return tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
    if prompt_format == 'chatml_v1':
        # Explicit opt-in for base models without a template. Both models can
        # use this identical format; no task evidence is shortened or omitted.
        return ''.join('<|im_start|>' + item['role'] + '\n' + item['content'] + '<|im_end|>\n'
                       for item in messages) + '<|im_start|>assistant\n'
    raise ValueError('E_LOCAL_PROMPT_FORMAT')


def runtime_identity():
    return {'python_version': platform.python_version(),
            'python_executable_sha256': file_digest(Path(sys.executable).resolve()),
            'packages': {name: importlib.metadata.version(name)
                         for name in ('torch', 'transformers', 'tokenizers', 'safetensors')},
            'engine_source_sha256': file_digest(Path(__file__)),
            'common_source_sha256': file_digest(Path(__file__).with_name('local_model_common.py')),
            'scope': 'versions_python_executable_engine_source_not_shared_library_attestation'}


def service_identity(locks, runtime):
    return digest(canonical({'schema': 'hepta.local_service_identity.v1',
                              'models': [model_identity(lock) for lock in locks], 'runtime': runtime}))


def validate_request(request, service_sha256, models):
    if (not isinstance(request, dict)
            or set(request) != {'schema', 'model', 'service_sha256', 'messages', 'remaining_tokens', 'wall_seconds'}
            or request['schema'] != 'hepta.local_generate_request.v1'
            or request['service_sha256'] != service_sha256 or request['model'] not in models):
        raise ValueError('E_LOCAL_REQUEST')
    messages = request['messages']
    if not isinstance(messages, list) or not 1 <= len(messages) <= 1024:
        raise ValueError('E_LOCAL_MESSAGES')
    for item in messages:
        if (not isinstance(item, dict) or set(item) != {'role', 'content'}
                or item['role'] not in {'system', 'user', 'assistant'}
                or not isinstance(item['content'], str)):
            raise ValueError('E_LOCAL_MESSAGES')
    counters = request['remaining_tokens']
    if (not isinstance(counters, dict) or set(counters) != {'input_tokens', 'output_tokens', 'total_tokens'}
            or any(type(value) is not int or not 1 <= value <= 2**53 - 1 for value in counters.values())
            or type(request['wall_seconds']) not in (int, float)
            or not math.isfinite(request['wall_seconds']) or not 0 < request['wall_seconds'] <= 86400):
        raise ValueError('E_LOCAL_BUDGET')
    if len(canonical(request)) > MAX_BODY:
        raise ValueError('E_LOCAL_BUDGET')
    return request


class TransformersEngine:
    """One independently loaded, safe-format, greedy CPU causal model."""
    def __init__(self, lock, directory):
        verify_assets(lock, directory)
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer
        self.torch, self.lock = torch, lock
        generation = lock['generation']
        torch.set_num_threads(generation['threads'])
        torch.manual_seed(0)
        self.tokenizer = AutoTokenizer.from_pretrained(str(directory), local_files_only=True,
                                                       trust_remote_code=False)
        self.model = AutoModelForCausalLM.from_pretrained(str(directory), local_files_only=True,
                         trust_remote_code=False, use_safetensors=True,
                         dtype=getattr(torch, generation['dtype']))
        self.model.to('cpu').eval()
        self.context_limit = int(getattr(self.model.config, 'max_position_embeddings',
                                        generation['max_input_tokens'] + generation['max_new_tokens']))
        # Loading must not have silently obtained an undeclared local artifact.
        verify_assets(lock, directory)

    def generate(self, request):
        import torch
        from transformers import StoppingCriteria, StoppingCriteriaList
        started = time.monotonic_ns()
        deadline = time.monotonic() + request['wall_seconds']
        generation, remaining = self.lock['generation'], request['remaining_tokens']
        rendered = render_prompt(self.tokenizer, request['messages'],
                                 generation.get('prompt_format', 'tokenizer_chat_template'))
        inputs = self.tokenizer(rendered, add_special_tokens=False, return_tensors='pt')
        input_ids = inputs['input_ids'][0].tolist()
        input_count = len(input_ids)
        maximum = min(generation['max_new_tokens'], remaining['output_tokens'],
                      remaining['total_tokens'] - input_count, self.context_limit - input_count)
        if (input_count <= 0 or input_count > min(generation['max_input_tokens'], remaining['input_tokens'])
                or maximum <= 0 or time.monotonic() >= deadline):
            return {'status': 'rejected_pre_inference', 'inference_started': False, 'usage': None}

        class Deadline(StoppingCriteria):
            hit = False
            def __call__(self, input_ids, scores, **kwargs):
                self.hit = time.monotonic() >= deadline
                return self.hit

        stop = Deadline()
        with torch.inference_mode():
            output = self.model.generate(**inputs, do_sample=False, max_new_tokens=maximum,
                        stopping_criteria=StoppingCriteriaList([stop]),
                        pad_token_id=(self.tokenizer.pad_token_id if self.tokenizer.pad_token_id is not None
                                      else self.tokenizer.eos_token_id))
        output_ids = output[0, input_count:].tolist()
        text = self.tokenizer.decode(output_ids, skip_special_tokens=True)
        end_ids = self.model.generation_config.eos_token_id
        if isinstance(end_ids, int): end_ids = [end_ids]
        end_ids = end_ids or [self.tokenizer.eos_token_id]
        reason = 'deadline' if stop.hit else ('eos' if output_ids and output_ids[-1] in end_ids else 'length')
        return {'status': 'completed' if reason == 'eos' else 'incomplete', 'inference_started': True,
                'text': text, 'token_ids': {'input': input_ids, 'output': output_ids},
                'usage': {'input_tokens': input_count, 'output_tokens': len(output_ids),
                          'total_tokens': input_count + len(output_ids),
                          'input_ids_sha256': digest(canonical(input_ids)),
                          'output_ids_sha256': digest(canonical(output_ids)),
                          'text_sha256': digest(text.encode()), 'model_lock_sha256': self.lock['lock_sha256'],
                          'elapsed_ns': time.monotonic_ns() - started, 'finish_reason': reason}}


def write_new(path, value):
    with Path(path).open('xb') as stream:
        stream.write(canonical(value) + b'\n')
        stream.flush()
        import os
        os.fsync(stream.fileno())


class Service:
    def __init__(self, locks, engines, runtime, evidence_dir):
        self.locks, self.models, self.engines = locks, [model_identity(v) for v in locks], engines
        self.runtime, self.sha256 = runtime, service_identity(locks, runtime)
        self.evidence_dir = Path(evidence_dir)
        if self.evidence_dir.exists() or self.evidence_dir.is_symlink():
            raise ValueError('E_LOCAL_EVIDENCE_EXISTS: fresh inference evidence directory required')
        self.evidence_dir.mkdir(parents=True)
        write_new(self.evidence_dir / 'service.json', {
            'schema': 'hepta.local_service.v1', 'service_sha256': self.sha256,
            'models': self.models, 'locks': locks, 'runtime': runtime,
            'claims': {'productivity_advantage_established': False, 'billing_receipt': False,
                       'model_isolation_attested': False, 'runtime_startup_in_task_budget': False},
            'scope': 'trusted_inference_only_service_no_code_execution_tools'})

    def generate(self, request, request_id):
        validate_request(request, self.sha256, self.models)
        prefix = {'schema': 'hepta.local_generation.v1', 'service_sha256': self.sha256,
                  'model': request['model'], 'request_id': request_id,
                  'request_sha256': digest(canonical(request))}
        write_new(self.evidence_dir / (request_id + '.request.json'), {
            **prefix, 'created_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'request': request, 'inference_completed': False})
        try:
            result = self.engines[self.models.index(request['model'])].generate(request)
        except Exception:
            # A failed runtime has unknown completed-token accounting. Never
            # invent zero usage or transform it into a fixture completion.
            result = {'status': 'inference_failed', 'inference_started': True, 'usage': None}
        if result.get('usage') is not None:
            result['usage']['service_sha256'] = self.sha256
            result['usage']['request_sha256'] = prefix['request_sha256']
        full = {**prefix, **result}
        write_new(self.evidence_dir / (request_id + '.response.json'), full)
        return {k: v for k, v in full.items() if k != 'token_ids'}


def serve(service, port):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass

        def do_POST(self):
            request_id = 'local-' + str(uuid.uuid4())
            try:
                length = self.headers.get('Content-Length')
                if (self.path != '/generate' or self.headers.get('Transfer-Encoding') is not None
                        or length is None or not length.isdecimal() or not 0 < int(length) <= MAX_BODY):
                    raise ValueError()
                self.connection.settimeout(10)
                data = self.rfile.read(int(length))
                if len(data) != int(length): raise ValueError()
                request = json.loads(data)
                result = service.generate(request, request_id)
                encoded, status = canonical(result), 200
            except Exception:
                encoded, status = canonical({'error': 'E_LOCAL_SERVICE'}), 400
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(encoded)))
            self.send_header('X-Hepta-Request-Id', request_id)
            self.end_headers()
            try: self.wfile.write(encoded)
            except (BrokenPipeError, ConnectionResetError): pass

    if type(port) is not int or not 1024 <= port <= 65535:
        raise ValueError('E_LOCAL_PORT')
    with HTTPServer(('127.0.0.1', port), Handler) as server:
        server.serve_forever()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='operation', required=True)
    freeze = sub.add_parser('freeze')
    freeze.add_argument('--model-dir', required=True)
    freeze.add_argument('--repository', required=True)
    freeze.add_argument('--revision', required=True)
    freeze.add_argument('--output', required=True)
    freeze.add_argument('--max-input-tokens', type=int, default=16384)
    freeze.add_argument('--max-new-tokens', type=int, default=1024)
    freeze.add_argument('--threads', type=int, default=2)
    freeze.add_argument('--dtype', choices=['float32', 'bfloat16'], default='float32')
    freeze.add_argument('--prompt-format', choices=['tokenizer_chat_template', 'chatml_v1'],
                        default='tokenizer_chat_template')
    run = sub.add_parser('serve')
    run.add_argument('--lock', action='append', required=True)
    run.add_argument('--model-dir', action='append', required=True)
    run.add_argument('--port', type=int, required=True)
    run.add_argument('--evidence-dir', required=True)
    args = parser.parse_args(argv)
    if args.operation == 'freeze':
        value = freeze_model(args.model_dir, args.repository, args.revision, max_new_tokens=args.max_new_tokens,
                              max_input_tokens=args.max_input_tokens, threads=args.threads, dtype=args.dtype,
                              prompt_format=args.prompt_format)
        write_new(args.output, value)
        print(json.dumps({'model': model_identity(value), 'actual_ai_model_runs': 0}))
        return 0
    if len(args.lock) != len(args.model_dir) or not 1 <= len(args.lock) <= 16:
        raise ValueError('E_LOCAL_CONFIG: pair every immutable lock and model directory')
    locks = [validate_lock(json.loads(regular(path).read_bytes())) for path in args.lock]
    if len({v['lock_sha256'] for v in locks}) != len(locks):
        raise ValueError('E_LOCAL_CONFIG: duplicate model lock')
    runtime = runtime_identity()
    engines = [TransformersEngine(lock, directory) for lock, directory in zip(locks, args.model_dir)]
    service = Service(locks, engines, runtime, args.evidence_dir)
    print(json.dumps({'service_sha256': service.sha256, 'models': service.models,
                      'host': '127.0.0.1', 'port': args.port}), flush=True)
    serve(service, args.port)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
