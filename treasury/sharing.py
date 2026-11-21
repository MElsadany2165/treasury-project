"""Milestone 2 Shamir secret sharing and Feldman public commitments."""
import secrets
from typing import Any

from .config import G, P, Q


def evaluate_polynomial(coefficients: list[int], x: int, q: int = Q) -> int:
    """Evaluate f(x) = a0 + a1*x + a2*x^2 + ... modulo q using Horner's method."""
    result = 0
    for coeff in reversed(coefficients):
        result = (result * x + coeff) % q
    return result


def make_shares(secret: int, t: int, n: int, q: int = Q) -> tuple[list[int], list[int]]:
    """Generate random degree-(t-1) polynomial with f(0)=secret; return (coefficients, shares).
    
    Shares are evaluated at x = 1, 2, ..., n.
    """
    if not (1 <= t <= n):
        raise ValueError("Require 1 <= t <= n")
    coefficients = [secret % q] + [secrets.randbelow(q - 1) + 1 for _ in range(t - 1)]
    shares = [evaluate_polynomial(coefficients, i, q) for i in range(1, n + 1)]
    return coefficients, shares


def make_commitments(coefficients: list[int], p: int = P, g: int = G) -> list[int]:
    """C_j = g^(a_j) mod p for j = 0, ..., t-1."""
    return [pow(g, c, p) for c in coefficients]


def compute_verification_key(member_index: int, commitments: list[int], p: int = P, q: int = Q) -> int:
    """Compute member i's verification key h_i = C0 * C1^i * C2^(i^2) ... mod p."""
    val = 1
    for j, c_j in enumerate(commitments):
        exp = pow(member_index, j, q)
        val = (val * pow(c_j, exp, p)) % p
    return val


def verify_share(share: int, member_index: int, commitments: list[int],
                 p: int = P, q: int = Q, g: int = G) -> bool:
    """Check g^share == h_i mod p."""
    h_i = compute_verification_key(member_index, commitments, p, q)
    return pow(g, share, p) == h_i


def lagrange_coefficient(i: int, selected_indices: list[int], q: int = Q) -> int:
    """Lagrange interpolation coefficient lambda_i at zero:
    lambda_i = product over j != i of (j * (j - i)^(-1) mod q).
    """
    numerator = 1
    denominator = 1
    for j in selected_indices:
        if j != i:
            numerator = (numerator * j) % q
            denominator = (denominator * (j - i)) % q
    return (numerator * pow(denominator, -1, q)) % q
