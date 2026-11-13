"""Instrumentation only; every observed public operation still executes normally."""
from collections import Counter
from contextlib import contextmanager
from functools import wraps
import time


class Profile:
    def __init__(self):
        self.rows = []
        self.stack = []
        self.counters = Counter()
        self.native = {}
        self.aggregates = {}
        self.extra_observations = []
        self.sequence = Counter()

    @contextmanager
    def span(self, kind, label, metadata=None):
        self.sequence[(kind, label)] += 1
        row = {'id': len(self.rows), 'parent': self.stack[-1]['id'] if self.stack else None,
               'kind': kind, 'label': label, 'occurrence': self.sequence[(kind, label)],
               'metadata': metadata or {}, 'counter_before': dict(self.counters),
               'start_wallclock_ns': time.time_ns(), 'start_ns': time.monotonic_ns(),
               'start_process_cpu_ns': time.process_time_ns(), 'outcome': 'ENTERED'}
        self.rows.append(row)
        self.stack.append(row)
        try:
            yield row
            row['outcome'] = 'RETURNED'
        except BaseException as error:
            row['outcome'] = 'RAISED'
            row['error_type'] = type(error).__module__ + '.' + type(error).__qualname__
            raise
        finally:
            row['end_process_cpu_ns'] = time.process_time_ns()
            row['end_ns'] = time.monotonic_ns()
            row['end_wallclock_ns'] = time.time_ns()
            row['inclusive_wall_ns'] = row['end_ns'] - row['start_ns']
            row['inclusive_process_cpu_ns'] = row['end_process_cpu_ns'] - row['start_process_cpu_ns']
            row['counter_after'] = dict(self.counters)
            assert self.stack.pop() is row

    def wrapper(self, function, kind, label, metadata=None, observed=None, counter=None):
        @wraps(function)
        def measured(*args, **kwargs):
            detail = metadata(args, kwargs) if metadata is not None else None
            with self.span(kind, label, detail) as row:
                if counter is not None:
                    self.counters[counter] += 1
                value = function(*args, **kwargs)
            if observed is not None:
                # Deliberately outside this timer; its real cost remains inside parents.
                observed(row, value, args, kwargs)
            return value
        return measured

    def aggregate_wrapper(self, function, label):
        @wraps(function)
        def measured(*args, **kwargs):
            start, cpu = time.monotonic_ns(), time.process_time_ns()
            row = self.aggregates.setdefault(label, {'calls': 0, 'wall_ns': 0, 'process_cpu_ns': 0, 'raises': 0})
            row['calls'] += 1
            try:
                return function(*args, **kwargs)
            except BaseException:
                row['raises'] += 1
                raise
            finally:
                row['process_cpu_ns'] += time.process_time_ns() - cpu
                row['wall_ns'] += time.monotonic_ns() - start
        return measured

    def native_call(self, label, actual_entry, arguments):
        record = self.native.setdefault(label, {'calls': 0, 'raises': 0, 'sample_every': 64,
                                               'samples': [], 'shapes': Counter()})
        record['calls'] += 1
        self.counters['native:' + label] += 1
        sampled = record['calls'] % 64 == 1
        if sampled:
            started, cpu = time.monotonic_ns(), time.process_time_ns()
        returned = None
        try:
            returned = actual_entry(*arguments)
            return returned
        except BaseException:
            record['raises'] += 1
            raise
        finally:
            if sampled:
                cpu_elapsed = time.process_time_ns() - cpu
                elapsed = time.monotonic_ns() - started
                record['samples'].append({'ordinal': record['calls'], 'wall_ns': elapsed,
                    'process_cpu_ns': cpu_elapsed,
                    'parent': self.stack[-1]['id'] if self.stack else None})
            record['shapes'][(arguments[1], arguments[3], arguments[5], returned)] += 1

    def report(self):
        children = {}
        for row in self.rows:
            children.setdefault(row['parent'], []).append(row)
        for row in self.rows:
            direct = children.get(row['id'], ())
            row['exclusive_timed_children_wall_ns'] = row['inclusive_wall_ns'] - sum(x['inclusive_wall_ns'] for x in direct)
            row['exclusive_timed_children_cpu_ns'] = row['inclusive_process_cpu_ns'] - sum(x['inclusive_process_cpu_ns'] for x in direct)
        native = {}
        for name, row in self.native.items():
            native[name] = {**row, 'shapes': [dict(input_bytes=key[0], output_capacity=key[1],
                state_capacity=key[2], returned=key[3], calls=value)
                for key, value in row['shapes'].items()]}
        return {'rows': self.rows, 'counters': dict(self.counters), 'native': native,
                'aggregates': self.aggregates, 'extra_observations': self.extra_observations,
                'limitations': [
                    'Instrumented diagnostic, never an original deadline qualification.',
                    'All public calls, fresh reads, hashes, original test budgets and production effects execute unchanged.',
                    'Timers and counters add real overhead; no budget or clock is adjusted to remove it.',
                    'Exclusive values subtract only explicitly timed direct child spans; they retain unlabelled work and instrumentation.',
                    'process_time_ns measures this process, not subprocess CPU.',
                    'Native calls are counted completely after constructor admission; one in 64 is timed including ctypes/FFI. No sample multiplication is an exact native CPU total.',
                    'Two context-created SELECT observations execute after the original context function timer; their separately recorded costs remain in enclosing real budgets.',
                    'Binary inputs are exact retained members of the failed original run. No fixture compiler or cold qualification runs here; original business builds execute normally.',
                    'Each selected original method runs in a fresh process, not the original complete 35-method order; first-use costs are separately visible.',
                ]}
