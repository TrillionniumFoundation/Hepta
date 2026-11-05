"""Raw-token learned discrete events and an explicit binding-validity channel.

No token ID has semantic meaning in forward. The entire controller is trained
from task answers; no reset labels, write masks, key table, or oracle state enter
the model. Hard write/reset decisions use sigmoid straight-through gradients.

A detected reset has priority over writing and erases *all* stored history:
matrix, validity, and the older contextual token. The current observed token is
retained as the new previous token. This is an exact conditional erasure property,
not a guarantee that the learned controller detects the correct semantic event.
Address cross-talk and wrong events remain empirical failure modes.
The numerical contract is FP32/FP64 and fails closed on nonfinite event, output,
or state arithmetic. The Put+linear map is an exact-arithmetic identity; rounding
near a hard threshold can change events and must be checked on actual runs.
"""
from __future__ import annotations

import random
import numpy as np
import torch
from torch import nn
from torch.nn import functional as F
from .p2_associative_memory import (
    RawDeltaMemory, delta_batch, interpret_delta, IGNORE, DELTA_VOCAB_SIZE,
)
from .p2_round2_raw_tokens import (
    TokenBatch, gate_channels, MAP_BEGIN, WRITE, ASK, READ, RESET,
    KEY_BASE, VALUE_BASE, KEY_COUNT, VALUE_COUNT, UNKNOWN, NOISE_BASE,
)

RESET_VALIDITY_MODES = ('ordinary_reset_validity', 'hcsn_reset_validity')
MAPPED_MODE = 'put_linear_reset_validity'


def hard_event(probability):
    """Hard forward values, derivative of the original sigmoid probability."""
    return (probability >= .5).to(probability.dtype) + (probability-probability.detach())


class RawResetValidityMemory(RawDeltaMemory):
    def __init__(self, mode, *, embedding=16, key_width=16, value_width=8, control_width=24):
        lookup = dict(ordinary_reset_validity='ordinary_delta', hcsn_reset_validity='hcsn_delta',
                      put_linear_reset_validity='put_linear_delta')
        if mode not in lookup:
            raise ValueError('invalid reset-validity mode')
        super().__init__(lookup[mode], embedding=embedding, key_width=key_width,
                         value_width=value_width, control_width=control_width)
        self.mode = mode
        # An initially neutral write decision avoids an all-inactive hard gate.
        # This same numeric initialization is applied to both compared modes.
        with torch.no_grad():
            self.channel_bias[0] = 0.
        self.readout[-1] = nn.Linear(control_width, VALUE_COUNT)
        self.validity_logit_scale = 12.

    def forward(self, tokens, duration, initial=None, *, return_state=False, return_trace=False):
        if self.embedding.weight.dtype not in (torch.float32,torch.float64):
            raise ValueError('this numerical contract supports FP32 and FP64 only')
        if tokens.dtype != torch.long or tokens.ndim != 2 or min(tokens.shape) < 1:
            raise ValueError('need nonempty int64 token streams')
        if duration.shape != tokens.shape or not duration.is_floating_point():
            raise ValueError('invalid clocks')
        if not bool(((tokens >= 0) & (tokens < DELTA_VOCAB_SIZE)).all()):
            raise ValueError('unknown token')
        if not bool((torch.isfinite(duration) & (duration > 0)).all()):
            raise ValueError('invalid elapsed time')
        encoded = self.embedding(tokens)
        B = tokens.shape[0]
        if initial is None:
            memory = encoded.new_zeros((B, self.value_width, self.key_width))
            validity = encoded.new_zeros((B, self.key_width))
            previous = encoded.new_zeros((B, self.embedding_width))
            older = previous.clone()
        else:
            shapes = ((B,self.value_width,self.key_width), (B,self.key_width),
                      (B,self.embedding_width), (B,self.embedding_width))
            if not isinstance(initial,tuple) or len(initial) != 4:
                raise ValueError('invalid reset-validity state')
            for x, shape in zip(initial, shapes):
                if x.shape != shape or x.dtype != encoded.dtype or x.device != encoded.device or not bool(torch.isfinite(x).all()):
                    raise ValueError('invalid reset-validity tensors')
            memory, validity, previous, older = initial
        channel = 'ordinary' if self.mode == RESET_VALIDITY_MODES[0] else (
            'put_linear_equivalent' if self.mode == MAPPED_MODE else 'hcsn')
        reads, bounds, soft_controls, events = [], [], [], []
        for t in range(tokens.shape[1]):
            current = encoded[:,t]
            context = torch.cat((older, previous, current,
                                 torch.log1p(duration[:,t,None]).to(encoded.dtype)), dim=-1)
            u = torch.tanh(self.control_logits(torch.tanh(self.control(context))))
            first, second = gate_channels(u, channel)
            a, b = self.channel_weights.unbind(0)
            if self.mode == MAPPED_MODE:
                b = a+b
            soft = torch.sigmoid(a*first+b*second+self.channel_bias)
            if not bool(torch.isfinite(soft).all()):
                raise ArithmeticError('nonfinite learned event probability')
            event = hard_event(soft)
            write, reset = event[:,0:1], event[:,1:2]
            keep = 1-reset
            # Erase BEFORE any products with a potentially huge old state.
            # Masking only after bmm would permit finite state -> Inf -> 0*Inf.
            # This changes the STE surrogate relative to post-update erasure;
            # that ordering is explicitly frozen in the executed protocol.
            memory = keep[:,:,None]*memory
            validity = keep*validity
            address_context = keep*previous
            active_write = keep*write
            key = F.normalize(self.address(address_context), dim=-1, eps=1e-8)
            value = torch.tanh(self.value(current))
            prediction = torch.bmm(memory,key[:,:,None]).squeeze(-1)
            memory = memory+(active_write*(value-prediction))[:,:,None]*key[:,None,:]
            bound_before = (validity*key).sum(-1,keepdim=True)
            validity = validity+active_write*(1-bound_before)*key
            reads.append(torch.bmm(memory,key[:,:,None]).squeeze(-1))
            bounds.append((validity*key).sum(-1))
            if return_trace:
                soft_controls.append(soft)
                events.append(event)
            # After a reset, every component of this state depends only on the
            # current observed token, regardless of the previous hidden state.
            older, previous = address_context, current
        values = self.readout(torch.stack(reads,dim=1))
        binding_logit = self.validity_logit_scale*(torch.stack(bounds,dim=1)-.5)
        scores = torch.cat((F.log_softmax(values,dim=-1)+F.logsigmoid(binding_logit)[...,None],
                            F.logsigmoid(-binding_logit)[...,None]),dim=-1)
        state = (memory,validity,previous,older)
        if not bool(torch.isfinite(scores).all()) or any(not bool(torch.isfinite(x).all()) for x in state):
            raise ArithmeticError('nonfinite output or persistent state; no numerical certificate')
        trace = None
        if return_trace:
            trace = dict(soft_controls=torch.stack(soft_controls,1), events=torch.stack(events,1),
                         binding_logit=binding_logit)
        if return_state and return_trace:
            return scores,state,trace
        if return_state:
            return scores,state
        if return_trace:
            return scores,trace
        return scores


def reset_without_rebinding_batch(seed, *, n=96, cycles=4, queries_per_reset=8,
                                 noise_gap=2, ignore_probability=.6):
    """Independent grammar stress: no valid write ever occurs after first RESET.

    This is evaluator-side generation only. UNKNOWN labels and semantic token
    recognition never enter RawResetValidityMemory.forward.
    """
    if not isinstance(seed,int) or isinstance(seed,bool) or seed < 1:
        raise ValueError('positive integer seed required')
    for value in (n,cycles,queries_per_reset):
        if not isinstance(value,int) or isinstance(value,bool) or value < 1:
            raise ValueError('positive sizes required')
    if n > 256 or cycles > 8 or queries_per_reset > 32 or not 0 <= noise_gap <= 16:
        raise ValueError('stress exceeds bounded budget')
    if not 0 <= ignore_probability <= 1:
        raise ValueError('invalid distractor probability')
    rng = random.Random(seed)
    clock = np.random.default_rng(seed ^ 0x567109)
    records = []
    for _ in range(n):
        tokens, targets, tags, stale = [MAP_BEGIN],[-100],[''],[-100]
        old = {key:rng.randrange(VALUE_COUNT) for key in range(KEY_COUNT)}
        def append(seq, answers=None, names=None, olds=None):
            tokens.extend(seq)
            targets.extend([-100]*len(seq) if answers is None else answers)
            tags.extend(['']*len(seq) if names is None else names)
            stale.extend([-100]*len(seq) if olds is None else olds)
        def distract():
            append([NOISE_BASE+rng.randrange(4) for _ in range(rng.randrange(noise_gap+1))])
            if rng.random() < ignore_probability:
                append([IGNORE,KEY_BASE+rng.randrange(KEY_COUNT),VALUE_BASE+rng.randrange(VALUE_COUNT)])
        keys = list(range(KEY_COUNT))
        rng.shuffle(keys)
        for key in keys:
            append([WRITE,KEY_BASE+key,VALUE_BASE+old[key]])
            distract()
        for key in keys:
            append([ASK,KEY_BASE+key,READ],[-100,-100,old[key]],['','','before_reset'])
            distract()
        for cycle in range(cycles):
            append([RESET]);distract()
            for query in range(queries_per_reset):
                key = keys[query % len(keys)]
                append([ASK,KEY_BASE+key,READ],[-100,-100,UNKNOWN],
                       ['','','reset_no_rebind'],[-100,-100,old[key]])
                distract()
        if interpret_delta(tokens) != targets:
            raise AssertionError('stress generator disagrees with independent interpreter')
        records.append((tokens,targets,tags,stale))
    L = max(len(r[0]) for r in records)
    token_array = torch.full((n,L),NOISE_BASE,dtype=torch.long)
    target_array = torch.full((n,L),-100,dtype=torch.long)
    stale_array = torch.full((n,L),-100,dtype=torch.long)
    durations = torch.from_numpy(np.exp(clock.uniform(np.log(.5),np.log(2.),(n,L))).astype(np.float32))
    lengths, query_kinds = [],[]
    for row,(seq,answers,tags,old) in enumerate(records):
        length = len(seq);lengths.append(length)
        token_array[row,:length] = torch.tensor(seq)
        target_array[row,:length] = torch.tensor(answers)
        stale_array[row,:length] = torch.tensor(old)
        query_kinds.append(tuple(tags+['']*(L-length)))
    return TokenBatch(token_array,durations,target_array,tuple(lengths),
                      tuple('reset_no_rebind' for _ in range(n)),tuple(query_kinds),stale_array)


def make_reset_validity_panel(spec):
    args = dict(spec)
    generator = args.pop('generator','delta')
    if generator == 'delta':
        return delta_batch(**args)
    if generator == 'reset_no_rebind':
        return reset_without_rebinding_batch(**args)
    raise ValueError('unknown panel generator')
