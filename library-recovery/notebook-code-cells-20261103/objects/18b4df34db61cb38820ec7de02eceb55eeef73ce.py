r, delta, sigma_e, cost = 0.05, 0.03, 0.4, 0.08
nu_e = r-delta-sigma_e**2/2
gamma = (nu_e+np.sqrt(nu_e**2+2*r*sigma_e**2))/sigma_e**2
boundary = gamma*cost/(r*(1+gamma))
z = np.geomspace(1.0,20.0,100)
V = boundary*z
C, Q = channels(z,gamma)
E = boundary*C
EV = 1-z**(-gamma-1)
EVV = (gamma+1)/boundary*z**(-gamma-2)
residual = ((r-delta)*V*EV+0.5*sigma_e**2*V**2*EVV
            +delta*V-cost-r*E)

x, T, nu, sig = 0.8, 0.9, -0.3, 0.7
pt = float(risk(x,T,nu,sig))
coarse = pde_risk(x,T,nu,sig,0.02,800)
fine = pde_risk(x,T,nu,sig,0.01,1600)
mass = quad(lambda zz:killed(zz,x,T,nu,sig),0,np.inf,
            epsabs=1e-12,epsrel=1e-12)[0]
fint = quad(lambda tt:density(x,tt,nu,sig),0,T,
            epsabs=1e-12,epsrel=1e-12)[0]
t1, t2 = 0.35, 0.55
composition = float(risk(x,t1,nu,sig))+quad(
    lambda zz:killed(zz,x,t1,nu,sig)*risk(zz,t2,nu,sig),
    0,np.inf,epsabs=1e-12,epsrel=1e-12)[0]
eps = 1e-5
flux_numeric = sig**2/2 * (4*killed(eps,x,T,nu,sig)
                           -killed(2*eps,x,T,nu,sig))/(2*eps)
flux_exact = density(x,T,nu,sig)
gradient_errors = []
for xx in [0.05,0.2,0.8,1.6]:
    approx = (risk(xx+eps,T,nu,sig)-risk(xx-eps,T,nu,sig))/(2*eps)
    gradient_errors.append(abs(float(approx-risk_dx(xx,T,nu,sig))))

results = {
    "scope":"Scalar mathematical audit only; no HCSN training or performance claim",
    "simplified_model":{
        "r":r,"delta":delta,"sigma":sigma_e,"cost":cost,
        "gamma":float(gamma),"boundary":float(boundary),
        "max_ode_residual":float(np.max(np.abs(residual))),
        "C_boundary_derivative":0.0,"Q_right_boundary_derivative":-float(gamma)},
    "risk_model":{"x":x,"T":T,"nu":nu,"sigma":sig},
    "risk_analytic":pt,"risk_pde_coarse":coarse,"risk_pde_fine":fine,
    "pde_abs_errors":[abs(coarse-pt),abs(fine-pt)],
    "mass_error":abs(mass+pt-1),
    "cdf_density_integral_error":abs(fint-pt),
    "semigroup_composition_error":abs(composition-pt),
    "boundary_flux_numeric":float(flux_numeric),
    "boundary_flux_exact":float(flux_exact),
    "boundary_flux_abs_error":float(abs(flux_numeric-flux_exact)),
    "max_risk_dx_finite_difference_error":max(gradient_errors),
    "zero_drift_risk_right_derivative_at_boundary_sigma_0_6_T_1":
        -math.sqrt(2/math.pi)/0.6}
assert np.max(np.abs(residual)) < 1e-12
assert abs(fine-pt) < abs(coarse-pt)
assert abs(fine-pt) < 2e-5
assert abs(mass+pt-1) < 1e-10
assert abs(fint-pt) < 1e-10
assert abs(composition-pt) < 1e-10
assert abs(flux_numeric-flux_exact) < 1e-8
assert max(gradient_errors) < 1e-8
import json
print(json.dumps(results,indent=2,ensure_ascii=False))
