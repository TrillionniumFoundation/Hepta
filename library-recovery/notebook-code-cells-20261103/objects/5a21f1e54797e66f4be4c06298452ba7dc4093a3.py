plt.rcParams.update({"font.size":10,"axes.spines.top":False,
                     "axes.spines.right":False})
fig, axs = plt.subplots(2,2,figsize=(11,7.2),layout="constrained")
zz = np.linspace(0.7,4,450)
safe = np.maximum(zz,1)
cc,qq = channels(safe,gamma)
axs[0,0].plot(zz,cc,label="Continuation feature C",color="#165dba",lw=2.5)
axs[0,0].plot(zz,qq,label="Discounted hit feature Q",color="#bd4931",lw=2.5)
axs[0,0].axvline(1,color="gray",ls="--",lw=1)
axs[0,0].set(xlabel="State / boundary (z)",ylabel="Dimensionless feature",
             title="Two analytic features, one state variable")
axs[0,0].legend()
dc = np.where(zz>1,1-safe**(-gamma-1),0)
dq = np.where(zz>1,-gamma*safe**(-gamma-1),0)
axs[0,1].plot(zz,dc,label="dC/dz",color="#165dba",lw=2.5)
axs[0,1].plot(zz,dq,label="dQ/dz (piecewise)",color="#bd4931",lw=2.5)
axs[0,1].axvline(1,color="gray",ls="--",lw=1)
axs[0,1].set(xlabel="State / boundary (z)",ylabel="Derivative",
             title="C joins smoothly; Q has a derivative jump")
axs[0,1].legend()
xx = np.linspace(-0.25,2,400)
for horizon,color in [(0.25,"#7595b5"),(1,"#165dba"),(4,"#1a8070")]:
    vals = risk(np.maximum(xx,0),horizon,0,0.6)
    axs[1,0].plot(xx,vals,label=f"T={horizon}",color=color,lw=2)
axs[1,0].axvline(0,color="gray",ls="--",lw=1)
axs[1,0].set(xlabel="Log safety margin x",ylabel="First-hit probability",
             title="A risk forecast depends on its horizon")
axs[1,0].legend()
tt = np.linspace(0.01,4,500)
for xx0,color in [(0.4,"#7595b5"),(0.8,"#165dba"),(1.2,"#1a8070")]:
    axs[1,1].plot(tt,density(xx0,tt,-0.3,0.7),label=f"x0={xx0}",
                  color=color,lw=2)
axs[1,1].set(xlabel="Elapsed time",ylabel="Boundary probability flux",
             title="First-hit density is a flow, not a threshold")
axs[1,1].legend()
fig.suptitle("HCSN mathematical audit — restricted scalar models",fontsize=15)
plt.show()
