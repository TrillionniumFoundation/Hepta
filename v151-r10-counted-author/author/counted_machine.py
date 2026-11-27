"""Exact original edge diagnostic class; imported only after full guards."""
from hepta.hia_program_runtime import _Machine

class CountedMachine(_Machine):
    def __init__(self, *args):
        super().__init__(*args)
        self.call_costs = {}
        self.frames = []
    def invoke(self, fn, args, depth=0):
        start = self.steps
        frame = [0]
        self.frames.append(frame)
        try:
            return super().invoke(fn, args, depth)
        finally:
            elapsed = self.steps - start
            self.frames.pop()
            record = self.call_costs.setdefault(fn['name'], {'calls': 0, 'exclusive_steps': 0, 'inclusive_steps': 0})
            record['calls'] += 1
            record['exclusive_steps'] += elapsed - frame[0]
            record['inclusive_steps'] += elapsed
            if self.frames:
                self.frames[-1][0] += elapsed
