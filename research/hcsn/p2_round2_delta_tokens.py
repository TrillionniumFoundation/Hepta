"""Learned raw-token associative memory with contextual Delta updates.

A generic one-token-lag learned address and a three-token causal control window
replace an undifferentiated recurrent bottleneck. No model branch recognizes
WRITE, KEY, VALUE, RESET, or IGNORE IDs: only the task generator/interpreter knows
the grammar. An explicit IGNORE/key/value distractor forces context-dependent
writing, so a value-token-only gate cannot solve the task.

This is a bounded adjacent-triple symbolic grammar. It is not arbitrary language
parsing, autonomous first-passage/reset learning, or a full He-Xiong QVI.
"""
from __future__ import annotations
import math
import random
import hashlib
import numpy as np
import torch
from torch import nn
from torch.nn import functional as F
try:
    from .p2_round2_raw_tokens import (TokenBatch, make_batch, interpret, gate_channels, batch_digest,
        NOISE_BASE, KEY_BASE, VALUE_BASE, VALUE_COUNT, KEY_COUNT, VOCAB_SIZE, UNKNOWN, WRITE, ASK,
        MAP_BEGIN, RESET, READ)
except ImportError:
    from p2_round2_raw_tokens import (TokenBatch, make_batch, interpret, gate_channels, batch_digest,
        NOISE_BASE, KEY_BASE, VALUE_BASE, VALUE_COUNT, KEY_COUNT, VOCAB_SIZE, UNKNOWN, WRITE, ASK,
        MAP_BEGIN, RESET, READ)

IGNORE = VOCAB_SIZE
DELTA_VOCAB_SIZE = VOCAB_SIZE+1
DELTA_MODES=('hcsn_delta','ordinary_delta')


def interpret_delta(tokens):
    """Independent grammar verifier. Never called inside a learned model."""
    visible=[];positions=[];i=0
    while i<len(tokens):
        token=tokens[i]
        if token==IGNORE:
            if i+2>=len(tokens) or not KEY_BASE<=tokens[i+1]<VALUE_BASE or not VALUE_BASE<=tokens[i+2]<VOCAB_SIZE:
                raise ValueError('malformed IGNORE/key/value triple')
            i+=3
        else:
            visible.append(token);positions.append(i);i+=1
    core=interpret(visible)
    labels=[-100]*len(tokens)
    for i,label in zip(positions,core):labels[i]=label
    return labels


def delta_batch(seed, *, n=24, kinds=('mqar','overwrite'), noise_gap=2, overwrites=4,
                episodes=2, ignore_probability=.4, duration_min=.5, duration_max=2.):
    if not kinds or any(k not in ('mqar','overwrite','state_tracking','multi_reset') for k in kinds):
        raise ValueError('invalid keyed task mixture')
    if not 0<=ignore_probability<=1 or not math.isfinite(ignore_probability):raise ValueError('invalid distractors')
    if isinstance(n,bool) or not isinstance(n,int) or not 1<=n<=256:raise ValueError('invalid batch size')
    rng=random.Random(seed ^ 0x72139)
    clock=np.random.default_rng(seed ^ 0x98A8)
    records=[]
    for row in range(n):
        kind=kinds[row%len(kinds)]
        base=make_batch(seed+997*row,n=1,kind=kind,noise_gap=noise_gap,overwrites=overwrites,
                        episodes=episodes,duration_min=duration_min,duration_max=duration_max)
        original=base.tokens[0,:base.lengths[0]].tolist()
        target=base.targets[0,:base.lengths[0]].tolist()
        old=base.stale_answers[0,:base.lengths[0]].tolist()
        names=base.query_kinds[0][:base.lengths[0]]
        dt0=base.duration[0,:base.lengths[0]].tolist()
        seq=[];answers=[];tags=[];stale=[];times=[];i=0
        while i<len(original):
            block=3 if original[i] in (WRITE,ASK) else 1
            seq.extend(original[i:i+block]);answers.extend(target[i:i+block]);tags.extend(names[i:i+block])
            stale.extend(old[i:i+block]);times.extend(dt0[i:i+block]);i+=block
            if rng.random()<ignore_probability:
                seq.extend([IGNORE,KEY_BASE+rng.randrange(KEY_COUNT),VALUE_BASE+rng.randrange(VALUE_COUNT)])
                answers.extend([-100]*3);stale.extend([-100]*3);tags.extend(['']*3)
                times.extend(np.exp(clock.uniform(math.log(duration_min),math.log(duration_max),3)).tolist())
        if interpret_delta(seq)!=answers:raise AssertionError('independent contextual grammar disagrees')
        records.append((seq,answers,tags,stale,times,kind))
    rng.shuffle(records)
    length=max(len(r[0]) for r in records)
    tokens=torch.full((n,length),NOISE_BASE,dtype=torch.long)
    targets=torch.full((n,length),-100,dtype=torch.long)
    stale=torch.full((n,length),-100,dtype=torch.long)
    duration=torch.ones((n,length),dtype=torch.float32)
    lengths=[];task_names=[];query_kinds=[]
    for row,(seq,answer,tags,old,dt,kind) in enumerate(records):
        L=len(seq);lengths.append(L);task_names.append(kind)
        tokens[row,:L]=torch.tensor(seq);targets[row,:L]=torch.tensor(answer);stale[row,:L]=torch.tensor(old)
        duration[row,:L]=torch.tensor(dt)
        query_kinds.append(tuple(tags+['']*(length-L)))
    return TokenBatch(tokens,duration,targets,tuple(lengths),tuple(task_names),tuple(query_kinds),stale)


class RawDeltaMemory(nn.Module):
    """Learned matrices and gates; all token IDs use the same computation."""
    def __init__(self, mode, *, embedding=16, key_width=16, value_width=8, control_width=24):
        super().__init__()
        if mode not in DELTA_MODES+('put_linear_delta',):raise ValueError('invalid Delta mode')
        self.mode=mode;self.key_width=key_width;self.value_width=value_width;self.embedding_width=embedding
        self.embedding=nn.Embedding(DELTA_VOCAB_SIZE,embedding)
        self.address=nn.Linear(embedding,key_width,bias=False)
        self.value=nn.Linear(embedding,value_width,bias=False)
        self.control=nn.Linear(3*embedding+1,control_width)
        self.control_logits=nn.Linear(control_width,2)
        self.channel_weights=nn.Parameter(torch.tensor([[6.,6.],[-6.,-6.]]))
        self.channel_bias=nn.Parameter(torch.tensor([-2.,-4.]))
        self.readout=nn.Sequential(nn.Linear(value_width,control_width),nn.Tanh(),nn.Linear(control_width,VALUE_COUNT+1))

    def forward(self,tokens,duration,initial=None,*,return_state=False,return_gates=False):
        if tokens.dtype!=torch.long or tokens.ndim!=2 or min(tokens.shape)<1:raise ValueError('need int64 token streams')
        if duration.shape!=tokens.shape or not duration.is_floating_point():raise ValueError('invalid clocks')
        if not bool(((tokens>=0)&(tokens<DELTA_VOCAB_SIZE)).all()):raise ValueError('unknown token')
        if not bool((torch.isfinite(duration)&(duration>0)).all()):raise ValueError('invalid elapsed time')
        encoded=self.embedding(tokens)
        B=tokens.shape[0]
        if initial is None:
            memory=encoded.new_zeros((B,self.value_width,self.key_width))
            previous=encoded.new_zeros((B,self.embedding_width));older=previous.clone()
        else:
            if not isinstance(initial,tuple) or len(initial)!=3:raise ValueError('invalid memory state')
            memory,previous,older=initial
            shapes=((B,self.value_width,self.key_width),(B,self.embedding_width),(B,self.embedding_width))
            for x,shape in zip(initial,shapes):
                if x.shape!=shape or x.dtype!=encoded.dtype or not bool(torch.isfinite(x).all()):raise ValueError('invalid memory tensors')
        outputs=[];gates=[]
        channel='ordinary' if self.mode=='ordinary_delta' else ('put_linear_equivalent' if self.mode=='put_linear_delta' else 'hcsn')
        for t in range(tokens.shape[1]):
            current=encoded[:,t]
            context=torch.cat((older,previous,current,torch.log1p(duration[:,t,None]).to(encoded.dtype)),dim=-1)
            u=torch.tanh(self.control_logits(torch.tanh(self.control(context))))
            first,second=gate_channels(u,channel)
            a,b=self.channel_weights.unbind(0)
            if self.mode=='put_linear_delta':b=a+b
            controls=torch.sigmoid(a*first+b*second+self.channel_bias)
            write,reset=controls[:,0:1],controls[:,1:2]
            key=F.normalize(self.address(previous),dim=-1,eps=1e-8)
            value=torch.tanh(self.value(current))
            memory=(1-reset[:,:,None])*memory
            prediction=torch.bmm(memory,key[:,:,None]).squeeze(-1)
            delta=write*(value-prediction)
            memory=memory+delta[:,:,None]*key[:,None,:]
            read=torch.bmm(memory,key[:,:,None]).squeeze(-1)
            outputs.append(self.readout(read));gates.append(controls)
            older,previous=previous,current
        scores=torch.stack(outputs,dim=1)
        state=(memory,previous,older)
        if return_state and return_gates:return scores,state,torch.stack(gates,dim=1)
        if return_state:return scores,state
        if return_gates:return scores,torch.stack(gates,dim=1)
        return scores


def train_delta(mode,seed,*,steps=300,batch_size=24,kinds=('mqar','overwrite'),lr=.006,progress=None):
    torch.set_num_threads(1);torch.manual_seed(seed)
    model=RawDeltaMemory(mode)
    optimizer=torch.optim.Adam(model.parameters(),lr=lr)
    stream=hashlib.sha256();losses=[];norms=[];query_count=0
    for step in range(steps):
        batch=delta_batch(2000000+seed*10000+step,n=batch_size,kinds=kinds)
        stream.update(batch_digest(batch).encode())
        query_count+=int((batch.targets!=-100).sum())
        optimizer.zero_grad(set_to_none=True)
        scores=model(batch.tokens,batch.duration)
        loss=F.cross_entropy(scores.flatten(0,1),batch.targets.flatten())
        if not bool(torch.isfinite(loss)):raise ArithmeticError('nonfinite Delta task loss')
        loss.backward()
        if any(p.grad is None or not bool(torch.isfinite(p.grad).all()) for p in model.parameters()):raise ArithmeticError('nonfinite/missing Delta gradient')
        norms.append(float(torch.nn.utils.clip_grad_norm_(model.parameters(),1.0)))
        optimizer.step();losses.append(float(loss.detach()))
        if progress and (step+1)%50==0:progress(step+1,losses[-1])
    return model,{'mode':mode,'seed':seed,'steps':steps,'batch_size':batch_size,'learning_rate':lr,'training_kinds':list(kinds),
                  'trainable_parameters':sum(p.numel() for p in model.parameters()),
                  'persistent_state_values':model.value_width*model.key_width+2*model.embedding_width,
                  'training_stream_sha256':stream.hexdigest(),'training_query_count':query_count,
                  'all_training_losses':losses,'preclip_gradient_max':max(norms),'nonfinite_events':0}


def gate_diagnostics(model,batch):
    with torch.inference_mode():_,gates=model(batch.tokens,batch.duration,return_gates=True)
    kinds={'true_value':[],'ignored_value':[],'reset':[],'read':[],'other':[]}
    for row,L in enumerate(batch.lengths):
        for t in range(L):
            current=int(batch.tokens[row,t])
            if t>=2 and int(batch.tokens[row,t-2])==WRITE and VALUE_BASE<=current<VOCAB_SIZE:tag='true_value'
            elif t>=2 and int(batch.tokens[row,t-2])==IGNORE and VALUE_BASE<=current<VOCAB_SIZE:tag='ignored_value'
            elif current==RESET:tag='reset'
            elif current==READ:tag='read'
            else:tag='other'
            kinds[tag].append(gates[row,t].numpy())
    out={}
    for tag,values in kinds.items():
        if values:
            x=np.stack(values);out[tag]={'tokens':len(values),'mean_write_gate':float(x[:,0].mean()),'mean_reset_gate':float(x[:,1].mean())}
    with torch.inference_mode():
        # Analysis only: model computation does not know which IDs are keys.
        k=F.normalize(model.address(model.embedding(torch.arange(KEY_BASE,VALUE_BASE))),dim=-1)
        gram=k@k.T;off=gram-torch.eye(KEY_COUNT)
    out['learned_key_offdiagonal_gram_max']=float(off.abs().max())
    return out
