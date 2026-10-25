"""B.9 toy ECDSA on E_17(3,5), G=(5,3), n=23. INSECURE: for study only."""
from __future__ import annotations

P, A, B, G, N = 17, 3, 5, (5, 3), 23
Point = tuple[int, int] | None


def on_curve(pt: Point) -> bool:
    return pt is None or (0 <= pt[0] < P and 0 <= pt[1] < P and
                          (pt[1] ** 2 - (pt[0] ** 3 + A * pt[0] + B)) % P == 0)


def add(u: Point, v: Point) -> Point:
    if not on_curve(u) or not on_curve(v):
        raise ValueError('Invalid point')
    if u is None: return v
    if v is None: return u
    x1, y1 = u
    x2, y2 = v
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if u == v:
        lam = ((3 * x1 * x1 + A) * pow(2 * y1, -1, P)) % P
    else:
        lam = ((y2 - y1) * pow(x2 - x1, -1, P)) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    pt = (x3, y3)
    assert on_curve(pt)
    return pt


def mul(k: int, pt: Point = G) -> Point:
    if not on_curve(pt) or k < 0:
        raise ValueError('Invalid point or scalar')
    result = None
    while k:
        if k & 1:
            result = add(result, pt)
        pt = add(pt, pt)
        k >>= 1
    return result


def sign(h: int, d: int, k: int) -> tuple[int, int]:
    if not (1 <= d < N and 1 <= k < N):
        raise ValueError('Invalid private scalar / nonce')
    point = mul(k)
    if point is None:
        raise ValueError('kG is the point at infinity')
    r = point[0] % N
    if not r:
        raise ValueError('r = 0, choose another k')
    s = (pow(k, -1, N) * (h + d * r)) % N
    if not s:
        raise ValueError('s = 0, choose another k')
    return r, s


def verify(h: int, signature: tuple[int, int], Q: Point):
    r, s = signature
    if not (1 <= r < N and 1 <= s < N and on_curve(Q)) or Q is None:
        return False, None
    w = pow(s, -1, N)
    u1, u2 = h * w % N, r * w % N
    X = add(mul(u1), mul(u2, Q))
    return X is not None and X[0] % N == r, X


def example() -> dict:
    assert on_curve(G) and mul(N) is None
    d, h, k = 7, 10, 5
    Q = mul(d)
    sig = sign(h, d, k)
    ok, X = verify(h, sig, Q)
    return {'curve': 'y^2 = x^3 + 3x + 5 mod 17', 'G': G, 'n': N,
            'd': d, 'h': h, 'k': k, 'Q': Q, 'signature': sig,
            'verify_point': X, 'valid': ok,
            'changed_message_valid': verify(h + 1, sig, Q)[0]}

if __name__ == '__main__':
    print(example())
