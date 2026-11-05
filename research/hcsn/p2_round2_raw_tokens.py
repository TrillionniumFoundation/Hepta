"""Raw-token P2 task suite and matched learned recurrent controls.

Models receive only token IDs and elapsed times. No key one-hot tensor, parsed
write mask, true state, episode number, query answer, or teacher-forced answer is
an input. A finite-state interpreter exists solely to independently check the
synthetic language and labels. RESET is an observable command, not an unseen
boundary event; passing commanded resets cannot certify autonomous spiking.

The HCSN candidate uses *simplified stopping* Call/Put channels inside a learned
recurrent update. It is not the original He-Xiong system or a solved neural QVI.
Its Put+linear control is an algebraic reparameterization with the same canonical
weights. The ordinary softplus pair has the same learned parameters and initial
signed update-logit slope at the gate origin; global FLOPs/slopes are not equal.
"""
from __future__ import annotations
from dataclasses import dataclass
import hashlib
import math
import random

import numpy as np
import torch
from torch import nn
from torch.nn import functional as F

COPY_BEGIN, RECALL, READ, MAP_BEGIN, WRITE, ASK, RESET = range(7)
NOISE_BASE, KEY_BASE, VALUE_BASE = 7, 11, 15
VOCABULARY = ("COPY", "RECALL", "READ", "MAP", "WRITE", "ASK", "RESET",
              "noise0", "noise1", "noise2", "noise3", "key0", "key1", "key2", "key3",
              "value0", "value1", "value2", "value3")
VOCAB_SIZE = len(VOCABULARY)
VALUE_COUNT, KEY_COUNT, UNKNOWN = 4, 4, 4
TASKS = ("selective_copy", "mqar", "overwrite", "state_tracking", "multi_reset")
MODES = ("hcsn", "ordinary")


@dataclass(frozen=True)
class TokenBatch:
    tokens: torch.Tensor
    duration: torch.Tensor
    targets: torch.Tensor
    lengths: tuple[int, ...]
    task_names: tuple[str, ...]
    query_kinds: tuple[tuple[str, ...], ...]
    stale_answers: torch.Tensor


def interpret(tokens):
    """Independent causal reference interpreter; never called by a model."""
    answers = [-100] * len(tokens)
    mode = pending = None
    key = None
    state = {}
    copied, read_index = [], 0
    recalling = False
    for i, token in enumerate(tokens):
        if isinstance(token, bool) or not isinstance(token, (int, np.integer)) or not 0 <= token < VOCAB_SIZE:
            raise ValueError("invalid language token")
        if token == COPY_BEGIN:
            mode = "copy"; copied = []; recalling = False; read_index = 0; pending = None
        elif token == MAP_BEGIN:
            mode = "map"; state = {}; pending = None
        elif NOISE_BASE <= token < KEY_BASE:
            continue
        elif mode == "copy":
            if VALUE_BASE <= token < VOCAB_SIZE and not recalling:
                copied.append(token-VALUE_BASE)
            elif token == RECALL and not recalling:
                recalling = True
            elif token == READ and recalling and read_index < len(copied):
                answers[i] = copied[read_index]; read_index += 1
            else:
                raise ValueError("malformed selective-copy language")
        elif mode == "map":
            if token == RESET and pending is None:
                state = {}
            elif token in (WRITE, ASK) and pending is None:
                pending = "write_key" if token == WRITE else "ask_key"
            elif KEY_BASE <= token < VALUE_BASE and pending in ("write_key", "ask_key"):
                key = token-KEY_BASE
                pending = "write_value" if pending == "write_key" else "ask_read"
            elif VALUE_BASE <= token < VOCAB_SIZE and pending == "write_value":
                state[key] = token-VALUE_BASE; pending = None
            elif token == READ and pending == "ask_read":
                answers[i] = state.get(key, UNKNOWN); pending = None
            else:
                raise ValueError("malformed map language")
        else:
            raise ValueError("task prefix missing")
    if pending is not None:
        raise ValueError("unfinished map instruction")
    return answers


def _case(kind, rng, *, copy_length, copy_count, noise_gap, overwrites, episodes):
    tokens, targets, tags, stale = [], [], [], []
    state, previous = {}, {}

    def append(token, answer=-100, tag="", old=-100):
        tokens.append(int(token)); targets.append(int(answer)); tags.append(tag); stale.append(int(old))

    def noise():
        for _ in range(rng.randrange(noise_gap+1)):
            append(NOISE_BASE+rng.randrange(4))

    def write(key, value):
        old = state.get(key, UNKNOWN)
        append(WRITE); append(KEY_BASE+key); append(VALUE_BASE+value)
        previous[key] = old; state[key] = value; noise()

    def query(key, tag):
        append(ASK); append(KEY_BASE+key)
        value = state.get(key, UNKNOWN)
        old = previous.get(key, UNKNOWN)
        append(READ, value, tag, old if old != value else -100)
        noise()

    if kind == "selective_copy":
        append(COPY_BEGIN)
        selected = set(rng.sample(range(copy_length), copy_count))
        values = []
        for i in range(copy_length):
            if i in selected:
                value = rng.randrange(VALUE_COUNT); values.append(value); append(VALUE_BASE+value)
            else:
                append(NOISE_BASE+rng.randrange(4))
        append(RECALL)
        for value in values:
            append(READ, value, "copy_ordered")
    else:
        append(MAP_BEGIN)
        keys = list(range(KEY_COUNT)); rng.shuffle(keys)
        for key in keys:
            write(key, rng.randrange(VALUE_COUNT))
        if kind == "mqar":
            rng.shuffle(keys)
            for key in keys: query(key, "mqar")
        elif kind in ("overwrite", "state_tracking"):
            for _ in range(overwrites):
                key = rng.randrange(KEY_COUNT)
                value = (state[key]+1+rng.randrange(VALUE_COUNT-1)) % VALUE_COUNT
                write(key, value)
                if kind == "state_tracking":
                    query(key if rng.random() < .5 else rng.randrange(KEY_COUNT), "tracking")
            rng.shuffle(keys)
            for key in keys: query(key, "overwrite_final")
        elif kind == "multi_reset":
            for key in keys: query(key, "before_reset")
            for _ in range(episodes):
                previous = state.copy(); state = {}
                append(RESET); noise()
                # Immediate read tests whether old binding survives a visible reset.
                query(rng.randrange(KEY_COUNT), "reset_unknown")
                rng.shuffle(keys)
                rebound = rng.randrange(2, KEY_COUNT+1)
                for key in keys[:rebound]: write(key, rng.randrange(VALUE_COUNT))
                rng.shuffle(keys)
                for key in keys: query(key, "after_reset")
        else:
            raise ValueError("unknown token task")
    if interpret(tokens) != targets:
        raise AssertionError("generator and independent causal interpreter disagree")
    return tokens, targets, tags, stale


def make_batch(seed: int, *, n=24, kind=None, copy_length=24, copy_count=3,
               noise_gap=2, overwrites=4, episodes=2, duration_min=.5, duration_max=2.):
    if isinstance(seed, bool) or not isinstance(seed, int) or seed < 1:
        raise ValueError("positive integer seed required")
    if kind is not None and kind not in TASKS:
        raise ValueError("unknown task")
    for x in (n, copy_length, copy_count, overwrites, episodes):
        if isinstance(x, bool) or not isinstance(x, int) or x < 1:
            raise ValueError("positive bounded task size required")
    if n > 512 or copy_length > 512 or not copy_count <= copy_length or copy_count > 8:
        raise ValueError("task exceeds reference budget")
    if isinstance(noise_gap, bool) or not isinstance(noise_gap, int) or not 0 <= noise_gap <= 64:
        raise ValueError("invalid distractor budget")
    if overwrites > 32 or episodes > 8:
        raise ValueError("too many state changes")
    if not math.isfinite(duration_min) or not math.isfinite(duration_max) or not 0 < duration_min <= duration_max <= 1024:
        raise ValueError("invalid independent clock")
    rng = random.Random(seed)
    kinds = [kind or TASKS[i % len(TASKS)] for i in range(n)]
    rng.shuffle(kinds)
    records = [_case(k, rng, copy_length=copy_length, copy_count=copy_count,
                     noise_gap=noise_gap, overwrites=overwrites, episodes=episodes) for k in kinds]
    longest = max(len(r[0]) for r in records)
    tokens = np.full((n,longest), NOISE_BASE, dtype=np.int64)
    targets = np.full((n,longest), -100, dtype=np.int64)
    stale = np.full((n,longest), -100, dtype=np.int64)
    # Timing RNG is independent of task generation and the answer values.
    clock = np.random.default_rng(seed ^ 0x4B183)
    dt = np.exp(clock.uniform(math.log(duration_min),math.log(duration_max),(n,longest))).astype(np.float32)
    tags, lengths = [], []
    for row, (seq, answer, names, old) in enumerate(records):
        length = len(seq); lengths.append(length)
        tokens[row,:length] = seq; targets[row,:length] = answer; stale[row,:length] = old
        tags.append(tuple(names + [""]*(longest-length)))
    return TokenBatch(torch.from_numpy(tokens), torch.from_numpy(dt), torch.from_numpy(targets),
                      tuple(lengths), tuple(kinds), tuple(tags), torch.from_numpy(stale))


def batch_digest(batch):
    h=hashlib.sha256()
    for x in (batch.tokens,batch.duration,batch.targets,batch.stale_answers): h.update(x.numpy().tobytes())
    h.update(repr((batch.lengths,batch.task_names,batch.query_kinds)).encode())
    return h.hexdigest()


def gate_channels(u: torch.Tensor, mode: str):
    if mode == "ordinary":
        return F.softplus(u), F.softplus(-u)
    if mode not in ("hcsn", "put_linear_equivalent"):
        raise ValueError("invalid channel mode")
    # r=.06, delta=.03, sigma=.2, K=1 gives beta=2 and b=2/3.
    v = torch.exp(u)
    margin = u-math.log(2/3)
    continuation = margin.clamp_min(0)
    put = torch.where(margin > 0, torch.exp(-2*continuation)/3, 1-v)
    call = (2/3)*(torch.expm1(continuation)+.5*torch.expm1(-2*continuation))
    if mode == "put_linear_equivalent": return v-1, put
    return call, put


class RawTokenMemory(nn.Module):
    def __init__(self, mode, *, width=48, embedding=16):
        super().__init__()
        if mode not in MODES+('put_linear_equivalent',): raise ValueError("invalid model")
        self.mode, self.width = mode, width
        self.embedding = nn.Embedding(VOCAB_SIZE,embedding)
        self.reset = nn.Linear(embedding+1+width,width)
        self.update = nn.Linear(embedding+1+width,width)
        self.candidate_input = nn.Linear(embedding+1,width)
        self.candidate_state = nn.Linear(width,width,bias=False)
        self.channel_weights = nn.Parameter(torch.stack((torch.ones(width),-torch.ones(width))))
        self.channel_bias = nn.Parameter(torch.zeros(width))
        self.readout = nn.Linear(width,VALUE_COUNT+1)

    def forward(self, tokens, duration, initial=None, *, return_state=False):
        if tokens.dtype != torch.long or tokens.ndim != 2 or min(tokens.shape) < 1:
            raise ValueError("tokens must be nonempty int64 [batch,time]")
        if duration.shape != tokens.shape or not duration.is_floating_point():
            raise ValueError("elapsed time shape/dtype mismatch")
        if not bool(((tokens>=0)&(tokens<VOCAB_SIZE)).all()): raise ValueError("unknown token")
        if not bool((torch.isfinite(duration)&(duration>0)).all()): raise ValueError("invalid elapsed time")
        encoded = self.embedding(tokens)
        dt = torch.log1p(duration).to(encoded.dtype)[...,None]
        if initial is None: h=encoded.new_zeros((tokens.shape[0],self.width))
        else:
            if initial.shape!=(tokens.shape[0],self.width) or initial.dtype!=encoded.dtype or not bool(torch.isfinite(initial).all()):
                raise ValueError("invalid recurrent state")
            h=initial
        outputs=[]
        for t in range(tokens.shape[1]):
            current=torch.cat((encoded[:,t],dt[:,t]),dim=-1)
            merged=torch.cat((current,h),dim=-1)
            reset=torch.sigmoid(self.reset(merged))
            proposal=torch.tanh(self.candidate_input(current)+self.candidate_state(reset*h))
            u=torch.tanh(self.update(merged))
            first,second=gate_channels(u,self.mode)
            a,b=self.channel_weights.unbind(0)
            if self.mode=='put_linear_equivalent': b=a+b
            weight=torch.sigmoid(a*first+b*second+self.channel_bias)
            h=h+weight*(proposal-h)
            outputs.append(self.readout(h))
        logits=torch.stack(outputs,dim=1)
        return (logits,h) if return_state else logits


def train_one(mode, seed, *, steps=600, batch_size=24, width=48, learning_rate=.003, progress=None):
    if mode not in MODES or not isinstance(steps,int) or isinstance(steps,bool) or not 1<=steps<=10000:
        raise ValueError("invalid training mode/budget")
    torch.set_num_threads(1)
    torch.manual_seed(seed)
    model=RawTokenMemory(mode,width=width)
    optimizer=torch.optim.Adam(model.parameters(),lr=learning_rate)
    data_digest=hashlib.sha256(); losses=[]; gradients=[]; total_queries=0; nonfinite=0
    # Fixed development probe is not used for checkpoint selection or early stop.
    development=make_batch(seed+600000,n=batch_size)
    with torch.no_grad():
        initial=float(F.cross_entropy(model(development.tokens,development.duration).flatten(0,1),development.targets.flatten()))
    for step in range(steps):
        data=make_batch(1000000+seed*10000+step,n=batch_size)
        data_digest.update(batch_digest(data).encode())
        total_queries+=int((data.targets!=-100).sum())
        optimizer.zero_grad(set_to_none=True)
        logits=model(data.tokens,data.duration)
        loss=F.cross_entropy(logits.flatten(0,1),data.targets.flatten())
        if not bool(torch.isfinite(loss)): nonfinite+=1; raise ArithmeticError("nonfinite query loss")
        loss.backward()
        if any(p.grad is None or not bool(torch.isfinite(p.grad).all()) for p in model.parameters()):
            raise ArithmeticError("missing/nonfinite BPTT gradient")
        norm=float(torch.nn.utils.clip_grad_norm_(model.parameters(),1.0))
        gradients.append(norm); losses.append(float(loss.detach()))
        optimizer.step()
        if progress is not None and (step+1)%100==0: progress(step+1,losses[-1])
    with torch.no_grad():
        final=float(F.cross_entropy(model(development.tokens,development.duration).flatten(0,1),development.targets.flatten()))
    return model, {'mode':mode,'seed':seed,'updates':steps,'batch_size':batch_size,'width':width,
                   'trainable_parameters':sum(p.numel() for p in model.parameters()),
                   'train_query_count':total_queries,'training_stream_sha256':data_digest.hexdigest(),
                   'development_initial_nll':initial,'development_final_nll':final,
                   'last50_training_loss_mean':float(np.mean(losses[-50:])),
                   'preclip_gradient_norm_max':max(gradients),'preclip_gradient_norm_median':float(np.median(gradients)),
                   'nonfinite_events':nonfinite,'all_update_losses':losses}


def evaluate(model,batch):
    model.eval()
    with torch.inference_mode(): logits=model(batch.tokens,batch.duration)
    prediction=logits.argmax(-1); valid=batch.targets!=-100; correct=prediction==batch.targets
    exact=((correct|~valid).all(-1))
    result={'queries':int(valid.sum()),'correct_queries':int((correct&valid).sum()),
            'query_accuracy':float(correct[valid].float().mean()),
            'sequences':len(batch.lengths),'exact_sequences':int(exact.sum()),
            'sequence_exact_accuracy':float(exact.float().mean()),
            'query_nll':float(F.cross_entropy(logits[valid],batch.targets[valid])),
            'maximum_token_length':max(batch.lengths),'minimum_token_length':min(batch.lengths),
            'dataset_sha256':batch_digest(batch),'by_task':{},'by_query_type':{}}
    for task in sorted(set(batch.task_names)):
        rows=torch.tensor([i for i,k in enumerate(batch.task_names) if k==task])
        v=valid[rows]; c=correct[rows]
        result['by_task'][task]={'queries':int(v.sum()),'accuracy':float(c[v].float().mean()),
                                'sequences':len(rows),'sequence_exact':float(exact[rows].float().mean())}
    alltags=sorted({k for row in batch.query_kinds for k in row if k})
    for tag in alltags:
        mask=torch.tensor([[x==tag for x in row] for row in batch.query_kinds])
        result['by_query_type'][tag]={'queries':int(mask.sum()),'accuracy':float(correct[mask].float().mean())}
    stale_mask=valid&(batch.stale_answers>=0)&(batch.stale_answers!=batch.targets)
    result['stale_answer_opportunities']=int(stale_mask.sum())
    result['stale_answers_emitted']=int(((prediction==batch.stale_answers)&stale_mask).sum())
    unknown=valid&(batch.targets==UNKNOWN)
    result['unknown_queries']=int(unknown.sum())
    result['unknown_false_accepts']=int(((prediction!=UNKNOWN)&unknown).sum())
    return result


def missing_write_panel(model):
    # Four equally likely unobserved values produce the identical observation.
    visible=[MAP_BEGIN,WRITE,KEY_BASE,VALUE_BASE,NOISE_BASE,NOISE_BASE,NOISE_BASE,ASK,KEY_BASE,READ]
    tokens=torch.tensor([visible]*VALUE_COUNT,dtype=torch.long)
    duration=torch.ones_like(tokens,dtype=torch.float32)
    with torch.inference_mode(): logits=model(tokens,duration)[:,-1]; p=logits.softmax(-1)
    if not torch.equal(logits,logits[:1].expand_as(logits)):
        raise AssertionError("identical observations leaked episode/answer identity")
    labels=torch.arange(VALUE_COUNT)
    return {'identical_observed_histories':VALUE_COUNT,'balanced_information_upper_bound':1/VALUE_COUNT,
            'hard_accuracy':float((logits.argmax(-1)==labels).float().mean()),
            'mean_probability_assigned_to_true_missing_value':float(p[torch.arange(VALUE_COUNT),labels].mean()),
            'unknown_prediction_is_allowed_abstention':True}


def previous_flow_operating_domain(*, write_error=.01, blank_error=.01, minimum_write_seconds=.02,
                                   noise_amplitude=.01, retention_seconds=4096.):
    """Necessary conditions for the old rate-scaled CTMC, not this token model.

    For an ideal unidirectional write, error exp(-lambda*d)<=epsilon demands
    lambda>=log(1/epsilon)/d. Under shared symmetric noise, endpoint separation
    exp(-lambda*x^2*D) and balanced accuracy >=1-epsilon demand
    lambda<=-log(1-2epsilon)/(x^2*D). Disjoint bounds close a negative verdict
    for these simultaneous requirements, even before nonzero reverse rates.
    """
    if not 0<write_error<.5 or not 0<blank_error<.5 or min(minimum_write_seconds,noise_amplitude,retention_seconds)<=0:
        raise ValueError("invalid finite operating domain")
    lower=-math.log(write_error)/minimum_write_seconds
    upper=-math.log1p(-2*blank_error)/(noise_amplitude**2*retention_seconds)
    return {'write_error_target':write_error,'retention_error_target':blank_error,
            'minimum_write_seconds':minimum_write_seconds,'noise_amplitude':noise_amplitude,
            'retention_seconds':retention_seconds,'necessary_write_rate_lower_bound':lower,
            'necessary_noise_rate_upper_bound':upper,'simultaneous_rate_interval_nonempty':lower<=upper,
            'scope':'old x^2-supported CTMC with the specified shared rate scale; not a general neural-memory no-go'}
