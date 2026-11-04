"""Strict JSON boundary around the isolated frontend adapter, not a sandbox."""
import json
import math
import sys

from hepta.ast import HeptaError
from .adapter import FrontendRequest
from experiments.policy_failures.owner import Cancelled, Failure, Rejected, VERSION

SCHEMA = 'hepta.experimental.frontend-lock-cli.v1'
USAGE = ('python -B -m experiments.frontend_lock_revalidation check --frontend-only '
         '--policy loader-experimental-v1 SOURCE [--locked]')
CATEGORIES = frozenset(('budget', 'unsupported_runtime', 'schema', 'replacement_hook',
    'thread', 'reentrancy', 'cancelled', 'interrupted', 'memory', 'recursion', 'io',
    'diagnostic', 'policy_drift', 'unexpected', 'lifecycle', 'terminal'))


class InvocationError(Exception):
    pass


def parse(argv):
    """No path conversion, abbreviation, response files or exception-message echo."""
    if type(argv) is not list or any(type(x) is not str for x in argv):
        raise InvocationError()
    if argv in (['--help'], ['check', '--help']):
        return None
    if not argv or argv[0] != 'check':
        raise InvocationError()
    flags, sources = {}, []
    index = 1
    while index < len(argv):
        token = argv[index]
        if token == '--':
            sources.extend(argv[index + 1:])
            break
        if token in ('--frontend-only', '--locked', '--policy'):
            if token in flags:
                raise InvocationError()
            if token == '--policy':
                index += 1
                if index == len(argv) or argv[index] != VERSION:
                    raise InvocationError()
                flags[token] = argv[index]
            else:
                flags[token] = True
        elif token.startswith('-') or token.startswith('@'):
            raise InvocationError()
        else:
            sources.append(token)
        index += 1
    if (len(sources) != 1 or not sources[0] or '--frontend-only' not in flags
            or '--policy' not in flags):
        raise InvocationError()
    return sources[0], '--locked' in flags


def envelope(outcome, *, report=None, diagnostics=None, failure=None, error=None, lock_revalidation='not_completed'):
    return {'schema': SCHEMA, 'policy_version': VERSION, 'frontend_only': True,
            'native_qualified': False, 'atomic_snapshot': False,
            'lock_revalidation': lock_revalidation, 'outcome': outcome,
            'ok': outcome in ('success', 'help'), 'report': report,
            'diagnostics': [] if diagnostics is None else diagnostics,
            'first_failure': failure, 'error': error}


def failure_json(failure):
    if failure is None:
        return None
    if type(failure) is not Failure or type(failure.category) is not str or failure.category not in CATEGORIES:
        raise ValueError()
    result = {}
    for name in ('category', 'phase', 'dimension', 'limit', 'admitted', 'attempted',
                 'observed_bytes', 'observed_reads'):
        value = getattr(failure, name)
        if name in ('category', 'phase'):
            if type(value) is not str:
                raise ValueError()
        elif name == 'dimension':
            if value is not None and type(value) is not str:
                raise ValueError()
        elif (name in ('observed_bytes', 'observed_reads') or value is not None) and (type(value) is not int or value < 0):
            raise ValueError()
        result[name] = value
    return result


def classification(failure):
    category = failure_json(failure)['category']
    if category == 'diagnostic':
        return 'diagnostic', 1
    if category in ('cancelled', 'interrupted'):
        return category, 130
    if category in ('unexpected', 'memory', 'recursion'):
        return 'error', 70
    return 'refused', 3


def evaluate(argv):
    request, context, report, failure, diagnostics = None, None, None, None, []
    try:
        parsed = parse(argv)
    except InvocationError:
        return envelope('usage', error='E_ARGUMENTS'), 2
    if parsed is None:
        result = envelope('help')
        result['usage'] = USAGE
        return result, 0
    try:
        entry, locked = parsed
        request = FrontendRequest(config={'locked': locked})
        context = request.owner.context
        analysis = request.check(entry)
        report = analysis.report
        observation = request.lock_revalidation
        failure = context.failure
        if (type(report) is not dict or type(report.get('schema')) is not str
                or report.get('schema') != 'hepta.check.v1'
                or type(report.get('ok')) is not bool
                or type(report.get('diagnostics')) is not list
                or type(report.get('status')) is not str
                or report.get('status') != ('frontend_only' if report['ok'] else 'rejected')
                or (failure is not None and report['ok'])
                or type(observation) is not str
                or observation not in ('not_requested', 'not_completed', 'post_analysis_observed')
                or (failure is not None and observation == 'post_analysis_observed')
                or (locked and observation == 'not_requested')
                or (locked and report['ok'] and observation != 'post_analysis_observed')
                or (not locked and observation != 'not_requested')):
            return envelope('error', failure=failure_json(failure), error='E_RESULT'), 70
        if failure is not None:
            outcome, code = classification(failure)
        else:
            outcome, code = ('success', 0) if report['ok'] else ('diagnostic', 1)
        return envelope(outcome, report=report, failure=failure_json(failure),
                        lock_revalidation=observation), code
    except BaseException as error:
        # A constructor refusal has no assigned request; preserve its own record.
        if context is not None:
            failure = context.failure
        if failure is None and isinstance(error, Rejected):
            failure = error.failure
        if isinstance(error, HeptaError):
            diagnostics = [error.diagnostic.to_dict()]
        if failure is not None:
            outcome, code = classification(failure)
        elif isinstance(error, Cancelled):
            outcome, code = 'cancelled', 130
        elif isinstance(error, KeyboardInterrupt):
            outcome, code = 'interrupted', 130
        else:
            outcome, code = 'error', 70
        return envelope(outcome, diagnostics=diagnostics, failure=failure_json(failure),
                        error='E_INTERNAL' if outcome == 'error' else None,
                        lock_revalidation='not_requested' if request is not None and not locked else 'not_completed'), code


def _plain(value):
    """Copy JSON primitives only, without custom encoders, repr or coercion."""
    kind = type(value)
    if value is None or kind in (bool, str, int):
        return value
    if kind is float and math.isfinite(value):
        return value
    if kind is list:
        return [_plain(item) for item in value]
    if kind is dict and all(type(key) is str for key in value):
        return {key: _plain(item) for key, item in value.items()}
    raise ValueError()


def main(argv=None, *, stdout=None, stderr=None):
    stdout = sys.stdout if stdout is None else stdout
    stderr = sys.stderr if stderr is None else stderr
    response = None
    try:
        response, code = evaluate(sys.argv[1:] if argv is None else argv)
        payload = json.dumps(_plain(response), ensure_ascii=True, allow_nan=False,
                             sort_keys=True, separators=(',', ':')) + '\n'
    except BaseException as error:
        interrupted = isinstance(error, (KeyboardInterrupt, Cancelled))
        outcome = ('cancelled' if isinstance(error, Cancelled) else 'interrupted') if interrupted else 'error'
        code = 130 if interrupted else 70
        error_code = None if interrupted else 'E_SERIALIZATION'
        # Never emit a partial report; preserve a previously materialized first cause.
        first = response.get('first_failure') if type(response) is dict else None
        fallback = envelope(outcome, failure=first, error=error_code)
        try:
            payload = json.dumps(_plain(fallback), ensure_ascii=True, allow_nan=False,
                                 sort_keys=True, separators=(',', ':')) + '\n'
        except BaseException:
            payload = ('{"schema":"' + SCHEMA + '","outcome":"' + outcome + '",'
                       '"ok":false,"report":null,"first_failure":null,'
                       '"policy_version":"loader-experimental-v1","frontend_only":true,'
                       '"native_qualified":false,"atomic_snapshot":false,'
                       '"lock_revalidation":"not_completed","diagnostics":[],'
                       '"error":' + ('null' if interrupted else '"E_SERIALIZATION"') + '}\n')
    try:
        written = stdout.write(payload)
        if type(written) is not int or written != len(payload):
            raise OSError()
        stdout.flush()
    except BaseException:
        try:
            stderr.write('frontend CLI output delivery failed\n')
            stderr.flush()
        except BaseException:
            pass
        return 74
    return code
