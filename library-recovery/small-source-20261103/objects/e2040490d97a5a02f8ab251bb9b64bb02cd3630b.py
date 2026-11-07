"""LOCAL MIRROR of existing Hepta PR #492 model for scoped execution.
The pre-existing source is NOT submitted again by iteration18.
"""
from __future__ import annotations
from typing import NamedTuple
import torch
from torch import nn
from torch.nn import functional as F

NKEYS=6
DIM=NKEYS+5
MODES=('analytic','ordinary','no_reset')

class MemoryState(NamedTuple):
    memory:torch.Tensor
    context:torch.Tensor
    initialized:torch.Tensor

class AutonomousBoundaryMemory(nn.Module):
    def __init__(self,mode='analytic'):
        super().__init__()
        if mode not in MODES: raise ValueError('unrecognized model')
        self.mode=mode
        self.raw_r=nn.Parameter(torch.tensor(-2.97))
        self.raw_delta=nn.Parameter(torch.tensor(-3.50))
        self.raw_sigma=nn.Parameter(torch.tensor(-1.50))
        self.raw_k=nn.Parameter(torch.tensor(.54))
        self.reserve_bias=nn.Parameter(torch.tensor(.08))
        self.novelty_raw=nn.Parameter(torch.tensor(-2.1))
        self.memory_feedback=nn.Parameter(torch.tensor(.03))
        self.context_feedback=nn.Parameter(torch.tensor(.02))
        self.time_feedback=nn.Parameter(torch.tensor(.015))
        self.temperature_raw=nn.Parameter(torch.tensor(-2.5))
        self.write_raw=nn.Parameter(torch.tensor(3.5))
        self.write_features=nn.Parameter(torch.tensor([.08,-.08,.10]))
        self.raw_decay=nn.Parameter(torch.tensor(-8.0))
        self.output_gain=nn.Parameter(torch.tensor(4.0))
        self.output_bias=nn.Parameter(torch.tensor(-.65))

    def initial(self,inputs):
        b=inputs.shape[0]
        return MemoryState(inputs.new_zeros((b,NKEYS)),
            inputs.new_zeros((b,1)),
            torch.zeros((b,1),dtype=torch.bool,device=inputs.device))

    def _step(self,xt,state,hard):
        mem,prev,initialized=state
        key=xt[:,:NKEYS]
        val=xt[:,NKEYS:NKEYS+1]
        write=xt[:,NKEYS+1:NKEYS+2]
        ctx=xt[:,NKEYS+3:NKEYS+4]
        dt=xt[:,NKEYS+4:NKEYS+5]
        novelty=(ctx-torch.where(initialized,prev,ctx)).abs()
        r=F.softplus(self.raw_r)+.005
        delta=F.softplus(self.raw_delta)+.002
        sigma=F.softplus(self.raw_sigma)+.01
        s2=sigma.square()
        a=(r-delta-.5*s2)/s2
        beta=torch.hypot(a,torch.sqrt(2*r/s2))+a
        k=F.softplus(self.raw_k)+.05
        b0=k*beta/(1+beta)
        log_v=self.reserve_bias+self.memory_feedback*mem.abs().mean(-1,keepdim=True)-self.time_feedback*dt
        log_b=torch.log(b0)+F.softplus(self.novelty_raw)*novelty+self.context_feedback*mem.mean(-1,keepdim=True)
        margin=log_v-log_b
        continuation=margin.clamp(min=0)
        boundary=torch.exp(log_b)
        local_k=boundary*(beta+1)/beta
        near=boundary*(.5*(1+beta)*continuation.square()+
                  (1-beta.square())*continuation.pow(3)/6+
                  (1+beta.pow(3))*continuation.pow(4)/24)
        direct=boundary*(torch.expm1(continuation)+torch.expm1(-beta*continuation)/beta)
        call=torch.where(continuation<.002,near,direct)/local_k
        put=torch.where(margin<=0,local_k-torch.exp(log_v),
                              boundary/beta*torch.exp(-beta*continuation))/local_k
        if self.mode in ('analytic','no_reset'):
            features=torch.cat([call,put,torch.tanh(margin)],-1)
        else:
            features=torch.cat([torch.sigmoid(3*margin),
                                torch.sigmoid(-3*margin),torch.tanh(margin)],-1)
        gate_logits=-margin/(F.softplus(self.temperature_raw)+.015)
        q=torch.sigmoid(gate_logits)
        event=margin<=0
        if self.mode=='no_reset':
            renewed=mem
        elif hard:
            renewed=torch.where(event,torch.zeros_like(mem),mem)
        else:
            renewed=(1-q)*mem
        decay=F.softplus(self.raw_decay)*dt
        renewed=renewed*torch.exp(-decay)
        strength=torch.sigmoid(self.write_raw+features @ self.write_features).unsqueeze(-1)
        update=write*key*strength
        renewed=renewed*(1-update)+update*val
        out=MemoryState(renewed,ctx,torch.ones_like(initialized))
        return out,gate_logits,event,margin,call,put
