"""Round 2: enclosing original HX Eq12 and a sufficient obstacle domain.

This is a CPU research certificate, not an FP32/BF16 implementation of HX.
It uses only mpmath's outward-rounded basic interval operations, exp, sqrt,
and pi.  In particular it DOES NOT call the experimental interval erf/erfc.
Normal probabilities are enclosed by Taylor or integration-by-parts
remainders.  The analytic proposition applies to the exact Eq12 candidate
and the fixed debt-price stopping problem, not equilibrium uniqueness under
arbitrarily repriced deviations, regeneration, or production admission.

The arithmetic trust base is mpmath 1.3.0's interval primitives; this module
is not a proof-assistant or an independent IEEE-1788 library certification.
"""
from __future__ import annotations

from dataclasses import asdict
from fractions import Fraction
import math
import numbers

from mpmath.ctx_iv import MPIntervalContext

try:
    from .hx_original import HXParams
except ImportError:
    from hx_original import HXParams


PARAMETER_BOUNDS = {
    'r': (.005, .30), 'delta': (.001, .20), 'sigma': (.03, .75),
    'alpha': (0., 1.), 'tax': (0., math.nextafter(1., 0.)),
    'xi': (0., 10.), 'k': (0., .25), 'maturity': (.05, 10.),
    'coupon_total': (math.ulp(0.), 500.),
    'face_total': (math.ulp(0.), 1000.),
}


def _finite_scalar(x):
    if isinstance(x, bool) or not isinstance(x, numbers.Real) or not math.isfinite(x):
        raise ValueError('Finite non-boolean real scalar required')
    value = float(x)
    if x != value:
        raise ValueError('Input must be exactly representable as binary64')
    return value


def round_binary(x: float, dtype: str) -> float:
    """Direct round-to-nearest-even from binary64 to FP32/BF16.

    No double rounding through FP32 is used for BF16.  The finite input range
    is deliberately limited to HX parameter/state diagnostics, not arbitrary
    tensor values, infinities, or overflow semantics.
    """
    x = _finite_scalar(x)
    if dtype not in ('fp32', 'bf16') or abs(x) > 1e10:
        raise ValueError('Supported diagnostic format/range required')
    if x == 0:
        return x
    bits = 24 if dtype == 'fp32' else 8
    exponent = max(math.frexp(abs(x))[1] - bits, -126 - bits + 1)
    step = math.ldexp(1., exponent)
    return float(round(x / step) * step)


def rounding_cell(x: float, dtype: str) -> tuple[float, float, float]:
    """Closed over-enclosure of all reals rounding to the encoded number.

    Midpoint ties are included at both ends conservatively.  Exact binary64
    midpoints suffice in this bounded range (at most 25 significant bits).
    """
    q = round_binary(x, dtype)
    bits = 24 if dtype == 'fp32' else 8
    subnormal = math.ldexp(1., -126 - bits + 1)
    if q == 0:
        return q, -subnormal / 2, subnormal / 2
    if q < 0:
        _, lo, hi = rounding_cell(-q, dtype)
        return q, -hi, -lo
    mantissa, power = math.frexp(q)
    up = math.ldexp(1., max(power - bits, -126 - bits + 1))
    down = up / 2 if mantissa == .5 and up > subnormal else up
    return q, q - down / 2, q + up / 2


def parameter_box(p: HXParams, dtype: str | None = None) -> dict:
    """Exact binary64 inputs, or their rounded-input preimage box.

    Quantization cells are intersected with the EXPLICIT prior that original
    inputs passed the existing HX constructor's finite binary64 domain.
    Encoded centers need not themselves satisfy that prior (e.g. BF16 .30).
    The rounding box encloses a continuum, not just selected corner points.
    """
    if not isinstance(p, HXParams):
        raise TypeError('HXParams required')
    if dtype not in (None, 'fp32', 'bf16'):
        raise ValueError('Unsupported quantization format')
    result = {}
    for name, value in asdict(p).items():
        x = _finite_scalar(value)
        allowed_lo, allowed_hi = PARAMETER_BOUNDS[name]
        if not allowed_lo <= x <= allowed_hi:
            raise ValueError('Input outside finite HX prior domain')
        q, lo, hi = (x, x, x) if dtype is None else rounding_cell(x, dtype)
        lo, hi = max(lo, allowed_lo), min(hi, allowed_hi)
        if not lo <= x <= hi:
            raise ArithmeticError('Original input not enclosed by quantization cell')
        result[name] = {'encoded': q, 'lower': lo, 'upper': hi}
    return result


def _raw_fraction(raw) -> Fraction:
    sign, mantissa, exponent, _ = raw
    if not mantissa:
        if exponent != 0:
            raise ArithmeticError('Nonfinite interval endpoint')
        return Fraction(0)
    numerator = -int(mantissa) if sign else int(mantissa)
    return (Fraction(numerator << exponent) if exponent >= 0
            else Fraction(numerator, 1 << -exponent))


def _outward_float(raw, lower: bool) -> float:
    """Conversion verified against exact dyadic rationals, including subnormals."""
    exact = _raw_fraction(raw)
    value = float(exact)
    if not math.isfinite(value):
        raise ArithmeticError('Interval outside finite binary64 export range')
    rounded = Fraction.from_float(value)
    if lower and rounded > exact:
        value = math.nextafter(value, -math.inf)
    elif not lower and rounded < exact:
        value = math.nextafter(value, math.inf)
    return value


def _export(value) -> dict:
    lo = _outward_float(value._mpi_[0], True)
    hi = _outward_float(value._mpi_[1], False)
    return {'lower': lo, 'upper': hi, 'lower_hex': lo.hex(), 'upper_hex': hi.hex()}


class _Enclosure:
    def __init__(self, digits=100):
        if type(digits) is not int or not 90 <= digits <= 180:
            raise ValueError('Interval precision must be 90..180 decimal digits')
        self.c = MPIntervalContext()
        self.c.dps = digits
        self.digits = digits
        self.epsilon = self.c.mpf(10) ** -(digits - 35)
        self.normalizer = self.c.sqrt(2 * self.c.pi)
        self.cache = {}

    def hull(self, a, b):
        return self.c.mpf([min(a.a, b.a), max(a.b, b.b)])

    def _point_tail(self, z):
        """Q(z), z >= 0, with explicit analytic remainder bounds."""
        c = self.c
        if z == 0:
            return c.mpf('.5')
        if z <= 12:
            # Integral_0^z exp(-u^2/2)du =
            # z sum_n (-z^2/2)^n / (n! (2n+1)).  Once decreasing,
            # consecutive partial sums enclose the alternating remainder.
            zz = z*z/2
            total, term = c.mpf(1), c.mpf(1)
            for n in range(1024):
                nxt = -term*zz*(2*n+1)/((n+1)*(2*n+3))
                if n+1 > zz.b and abs(nxt).b < self.epsilon.a:
                    integral = z*self.hull(total, total+nxt)/self.normalizer
                    answer = c.mpf('.5') - integral
                    return c.mpf([max(c.mpf(0), answer.a),
                                  min(c.mpf('.5'), answer.b)])
                total, term = total+nxt, nxt
            raise ArithmeticError('Normal Taylor enclosure failed to converge')
        # Repeated integration by parts gives alternating upper/lower
        # bounds phi(z)/z * [1 - 1/z^2 + 3/z^4 - ...].  The remainder has
        # the next sign and is at most the next term for EVERY truncation;
        # stop before terms grow, rather than asserting convergence.
        total = term = 1/z
        first = term
        for n in range(1024):
            nxt = -term*(2*n+1)/(z*z)
            if (abs(nxt).b < self.epsilon.a*first.a
                    or abs(nxt).a >= abs(term).b or n == 1023):
                return c.exp(-z*z/2)*self.hull(total, total+nxt)/self.normalizer
            total, term = total+nxt, nxt
        raise AssertionError('Unreachable')

    def point_cdf(self, z):
        if z._mpi_[0] != z._mpi_[1]:
            raise ValueError('A point endpoint is required')
        key = z._mpi_[0]
        if key not in self.cache:
            q = self._point_tail(abs(z))
            self.cache[key] = q if z < 0 else 1-q
        return self.cache[key]

    def cdf(self, z):
        # Phi is monotone; do not evaluate a power series on a wide box.
        return self.c.mpf([self.point_cdf(z.a).a, self.point_cdf(z.b).b])

    def _point_laplace(self, s, h):
        """J(s,h)=Integral_0^infty exp(-s*u) Phi(h-u)du."""
        c = self.c
        if s == 0:
            return h*self.point_cdf(h)+c.exp(-h*h/2)/self.normalizer
        tiny = c.mpf(2)**-90  # exact dyadic; no cancellation at tiny rates
        if abs(s).b < tiny.a:
            # J decreases in s.  A narrow interval across zero is safer
            # than replacing a nonzero rate by an unbounded-error limit.
            low = self._point_laplace(tiny, h)
            high = self._point_laplace(-tiny, h)
            return c.mpf([low.a, high.b])
        value = (self.point_cdf(h)-c.exp(s*s/2-h*s)*self.cdf(h-s))/s
        return c.mpf([max(c.mpf(0), value.a), value.b])

    def laplace(self, rate, drift, t):
        # Change variables x=t*u: t*J(rate*t,drift*t).
        # J decreases in its first argument and increases in the second.
        s, h = rate*t, drift*t
        lower = self._point_laplace(s.b, h.a)
        upper = self._point_laplace(s.a, h.b)
        return t*self.c.mpf([lower.a, upper.b])


def normal_cdf_enclosure(lower: float, upper: float, *, digits=100) -> dict:
    """Public scalar interval test surface; absolute arguments <= 1000."""
    lower, upper = _finite_scalar(lower), _finite_scalar(upper)
    if not -1000 <= lower <= upper <= 1000:
        raise ValueError('Normal enclosure supports [-1000,1000]')
    e = _Enclosure(digits)
    return _export(e.cdf(e.c.mpf([lower, upper])))


def _boundary_work(p: HXParams, *, dtype: str | None = None,
                   digits: int = 100):
    """Enclose Eq12 for exact inputs or a full low-precision preimage box.

    A successful sufficient-domain verdict concerns the exact candidate for
    EVERY parameter tuple in the returned input box.  Failure of this
    sufficient condition is UNRESOLVED, not a proof that equity is invalid.
    Positive enclosed local cashflow is a separate valid rejection witness.
    No existing HCSN scientific/production gate is changed by this function.
    """
    box = parameter_box(p, dtype)
    e = _Enclosure(digits)
    c = e.c
    q = {name: c.mpf([v['lower'], v['upper']]) for name, v in box.items()}
    r, delta, sigma, alpha, tax, xi, k, maturity, C, P = (
        q[n] for n in ('r', 'delta', 'sigma', 'alpha', 'tax', 'xi', 'k',
                       'maturity', 'coupon_total', 'face_total'))
    S = sigma*sigma
    a = (r-delta-S/2)/S
    lam = r+xi*k
    z = c.sqrt(a*a+2*r/S)
    zh = c.sqrt(a*a+2*lam/S)
    # Rationalize the subtractive characteristic root, retaining enclosure.
    eta = 2*r/(S*(z+a)) if a.a > 0 else z-a
    gamma = 2*r/(S*(z-a)) if a.b < 0 else z+a
    t = sigma*c.sqrt(maturity)
    IF = e.laplace(eta, -a, t)+e.laplace(gamma, a, t)
    # Algebraic identity avoids subtracting two almost equal square roots.
    z_minus_zh = -2*xi*k/(S*(z+zh))
    IG = e.laplace(z_minus_zh, -zh, t)+e.laplace(z+zh, zh, t)
    # Exact model bounds F<=1, 0<=G<=F; intersections preserve containment.
    IF = c.mpf([max(c.mpf(0), IF.a), min(IF.b, (1/eta).b)])
    IG = c.mpf([max(c.mpf(0), IG.a), min(IG.b, IF.b)])
    c0 = C/(maturity*lam)
    u = P/maturity-c0
    ell = c.exp(-lam*maturity)
    numerator = ((1-tax)*C+(1-ell)*u)/eta+ell*u*IF+c0*IG
    # delta/(eta-1) = sigma^2*(gamma+1)/2, including its delta->0 limit.
    denominator = S*(gamma+1)/2+alpha/maturity*IG
    if denominator.a <= 0:
        raise ArithmeticError('Unresolved positive Eq12 denominator')
    b = numerator/denominator
    net = (delta+alpha/maturity)*b-(1-tax)*C-P/maturity
    face_slack = P-alpha*b
    coupon_slack = C/lam-alpha*b
    if b.b <= 0:
        status = 'NO_POSITIVE_EQ12_CANDIDATE'
    elif b.a <= 0:
        status = 'UNRESOLVED_POSITIVE_CANDIDATE'
    elif net.a > 0:
        status = 'REFUTED_LOCAL_OBSTACLE'
    elif face_slack.a >= 0 and coupon_slack.a >= 0:
        status = 'SUFFICIENT_FIXED_DEBT_OBSTACLE'
    elif net.a <= 0 <= net.b:
        status = 'UNRESOLVED_LOCAL_SIGN'
    else:
        status = 'UNRESOLVED_OUTSIDE_SUFFICIENT_DOMAIN'
    record = {
        'status': status,
        'input_format': dtype or 'exact_binary64',
        'input_contract': ('known legal original binary64 parameters; full closed '
                           'rounding-cell preimage intersected with that prior'
                           if dtype else 'exact original binary64 parameter values'),
        'input_box': box,
        'boundary': _export(b),
        'local_cashflow': _export(net),
        'face_recovery_slack': _export(face_slack),
        'coupon_recovery_slack': _export(coupon_slack),
        'I_F': _export(IF), 'I_G': _export(IG),
        'working_decimal_digits': digits,
        'certificate_kind': 'outward_interval_with_explicit_normal_remainders',
        'arithmetic_trust_base': 'mpmath 1.3.0 basic interval primitives',
        'analytic_scope': ('fixed HX debt-price stopping problem, with absorbing '
                           'recovery extension d(V)=alpha*V/m below b'),
        'equilibrium_uniqueness_proved': False,
        'general_hx_parameter_domain_closed': False,
        'native_low_precision_arithmetic_certified': False,
        'production_activation': False,
    }
    return record, e, q, {
        'b': b, 'a': a, 'eta': eta, 'gamma': gamma, 'lam': lam,
        'zh': zh, 't': t, 'D': S/2, 'nu': r-delta-S/2,
    }


def boundary_domain_enclosure(p: HXParams, *, dtype: str | None = None,
                              digits: int = 100) -> dict:
    """Enclose exact Eq12 and classify its sufficient fixed-debt domain.

    With dtype, the verdict encloses EVERY legal original input in the whole
    rounded-input preimage box, rather than a sampled set of corners.
    """
    return _boundary_work(p, dtype=dtype, digits=digits)[0]


def _forcing_derivatives(e, q, h, x, order):
    """Original Eq8/Eq11 q^(j)(x), j<=3, with interval differentiation."""
    c = e.c
    a, zh, t = h['a'], h['zh'], h['t']

    def component(exponent, drift):
        z = -x/t+drift*t
        pdf = c.exp(-z*z/2)/e.normalizer
        derivatives = [e.cdf(z), -pdf/t, -z*pdf/(t*t),
                       -(z*z-1)*pdf/(t*t*t)]
        return c.exp(exponent*x)*sum(
            math.comb(order, j)*exponent**(order-j)*derivatives[j]
            for j in range(order+1))

    F = component(c.mpf(0), -a)+component(-2*a, a)
    G = component(-a+zh, -zh)+component(-a-zh, zh)
    c0 = q['coupon_total']/(q['maturity']*h['lam'])
    u = q['face_total']/q['maturity']-c0
    result = (q['delta']*h['b']*c.exp(x)
              -c.exp(-h['lam']*q['maturity'])*u*F
              +(q['alpha']*h['b']/q['maturity']-c0)*G)
    if order == 0:
        result += (-(1-q['tax'])*q['coupon_total']+c0
                   +c.exp(-h['lam']*q['maturity'])*u
                   -q['face_total']/q['maturity'])
    return result


def local_equity_enclosure(log_margin: float, p: HXParams, *,
                           digits: int = 100) -> dict:
    """Enclose ORIGINAL HX E(x) for exact 0<=x<=1e-3, including Taylor error.

    Coefficients are obtained from Eq11 with exact smooth fit.  The fifth
    derivative is bounded on [0,x] using the Green initial-value kernel and
    enclosed Eq8 derivatives; the remainder bound is B5*x^5/120.  This is
    not the simplified stopping Call and not a pointwise MP agreement test.
    """
    x = _finite_scalar(log_margin)
    if not 0 <= x <= 1e-3:
        raise ValueError('Enclosed local HX range is [0,1e-3]')
    domain, e, q, h = _boundary_work(p, digits=digits)
    c = e.c
    if h['b'].a <= 0:
        raise ArithmeticError('Positive exact Eq12 candidate unresolved')
    D, nu, r = h['D'], h['nu'], q['r']
    q0 = ((q['delta']+q['alpha']/q['maturity'])*h['b']
          -(1-q['tax'])*q['coupon_total']-q['face_total']/q['maturity'])
    q1 = _forcing_derivatives(e, q, h, c.mpf(0), 1)
    q2 = _forcing_derivatives(e, q, h, c.mpf(0), 2)
    E2 = -q0/D
    E3 = (-q1-nu*E2)/D
    E4 = (r*E2-nu*E3-q2)/D
    xx = c.mpf(x)
    polynomial = xx*xx*(E2/2+xx*(E3/6+xx*E4/24))
    # For K(u)=(exp(eta*u)-exp(-gamma*u))/(D*(eta+gamma)),
    # K'(u)<=exp(eta*x)/D on 0<=u<=x, whence
    # |E|<=Q0*x^2*exp(eta*x)/(2D), |E'|<=Q0*x*exp(eta*x)/D.
    interval_x = c.mpf([0., x])
    Q = [abs(_forcing_derivatives(e, q, h, interval_x, j)).b
         for j in range(4)]
    scale = c.exp(h['eta']*xx)/D
    B0 = Q[0]*xx*xx*scale/2
    B1 = Q[0]*xx*scale
    B2 = (Q[0]+abs(nu)*B1+r*B0)/D
    B3 = (Q[1]+abs(nu)*B2+r*B1)/D
    B4 = (Q[2]+abs(nu)*B3+r*B2)/D
    B5 = (Q[3]+abs(nu)*B4+r*B3)/D
    remainder = (B5*xx**5/120).b
    equity = polynomial+c.mpf([-remainder, remainder])
    return {
        'log_margin': x,
        'domain': domain,
        'equity': _export(equity),
        'polynomial': _export(polynomial),
        'coefficients': [_export(E2/2), _export(E3/6), _export(E4/24)],
        'absolute_taylor_remainder_bound': _export(remainder)['upper'],
        'source': 'original HX Eq8/Eq11 fourth-order series plus proved fifth-derivative bound',
        'production_activation': False,
    }


def evaluate_local_mixed_precision(log_margin: float, p: HXParams, *,
                                   output_dtype: str = 'fp32',
                                   relative_tolerance: float | None = None) -> dict:
    """Actually execute FP32 polynomial arithmetic; optionally store BF16.

    Original binary64 parameters and a directly carried log margin are part
    of the contract.  Boundary, coefficients, and the independent error
    enclosure are computed on the CPU interval reference.  No throughput,
    all-BF16 arithmetic, gradient, or production claim follows.  A failed
    domain/error check exposes only a diagnostic candidate, not a value.
    """
    if output_dtype not in ('fp32', 'bf16'):
        raise ValueError('Output format must be fp32 or bf16')
    if relative_tolerance is None:
        relative_tolerance = 1e-4 if output_dtype == 'fp32' else .01
    tolerance = _finite_scalar(relative_tolerance)
    if not 0 < tolerance <= .1:
        raise ValueError('Relative tolerance must be in (0,.1]')
    certificate = local_equity_enclosure(log_margin, p)
    import torch  # optional numerical backend, imported only for this path
    coefficients = [v['lower']+(v['upper']-v['lower'])/2
                    for v in certificate['coefficients']]
    x = torch.tensor(log_margin, dtype=torch.float32)
    a, b, d = [torch.tensor(v, dtype=torch.float32) for v in coefficients]
    candidate = x*x*(a+x*(b+x*d))
    if output_dtype == 'bf16':
        candidate = candidate.to(torch.bfloat16)
    value = float(candidate)
    lo, hi = (certificate['equity'][side] for side in ('lower', 'upper'))
    if not math.isfinite(value):
        absolute, relative, status = None, None, 'REFUSED_NONFINITE_NATIVE_RESULT'
    else:
        exact_error = max(abs(Fraction.from_float(value)-Fraction.from_float(lo)),
                          abs(Fraction.from_float(value)-Fraction.from_float(hi)))
        absolute = float(exact_error)
        if Fraction.from_float(absolute) < exact_error:
            absolute = math.nextafter(absolute, math.inf)
        if lo > 0:
            # Directed-up rational calculation, including final serialization.
            ratio = Fraction.from_float(absolute)/Fraction.from_float(lo)
            relative = float(ratio)
            if Fraction.from_float(relative) < ratio:
                relative = math.nextafter(relative, math.inf)
        else:
            relative = None
        if certificate['domain']['status'] != 'SUFFICIENT_FIXED_DEBT_OBSTACLE':
            status = 'REFUSED_UNRESOLVED_GLOBAL_DOMAIN'
        elif log_margin == 0 and lo == hi == value == 0:
            status = 'ACCEPTED_WITH_ERROR_ENCLOSURE'
        elif relative is not None and relative <= tolerance:
            status = 'ACCEPTED_WITH_ERROR_ENCLOSURE'
        else:
            status = 'REFUSED_ERROR_TOLERANCE'
    accepted = status == 'ACCEPTED_WITH_ERROR_ENCLOSURE'
    return {
        'status': status, 'value': value if accepted else None,
        'candidate_value': value if math.isfinite(value) else None,
        'absolute_error_bound': absolute, 'relative_error_bound': relative,
        'relative_tolerance': tolerance,
        'state_dtype': 'fp32_direct_log_margin',
        'accumulation_dtype': 'fp32', 'output_dtype': output_dtype,
        'controller_and_reference': 'CPU outward interval arithmetic from original binary64 parameters',
        'certificate': certificate,
        'production_activation': False,
    }
