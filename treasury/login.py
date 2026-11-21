"""Milestone 1 proof-of-knowledge login (interactive and non-interactive)."""
import secrets
from typing import Any

from .config import G, P, Q, validate_group_element
from .encoding import H


def register_login_secret(name: str, p: int = P, q: int = Q, g: int = G) -> tuple[int, int]:
    """Choose x_M in Z_q and return (secret x_M, public X_M = g^x_M mod p)."""
    x_M = secrets.randbelow(q - 1) + 1
    X_M = pow(g, x_M, p)
    return x_M, X_M


def make_interactive_commitment(p: int = P, q: int = Q, g: int = G) -> tuple[int, int]:
    """Member picks a fresh k and sends R = g^k mod p."""
    k = secrets.randbelow(q - 1) + 1
    R = pow(g, k, p)
    return k, R


def make_interactive_response(x_M: int, k: int, challenge: int, q: int = Q) -> int:
    """Compute z = k + e * x_M mod q."""
    return (k + challenge * x_M) % q


def verify_interactive_login(R: int, z: int, e: int, X_M: int,
                             p: int = P, q: int = Q, g: int = G) -> bool:
    """Accept if 1 < R, X_M < p, R^q == 1, X_M^q == 1, and g^z == R * X_M^e mod p."""
    if not (validate_group_element(R) and validate_group_element(X_M)):
        return False
    left = pow(g, z, p)
    right = (R * pow(X_M, e, p)) % p
    return left == right


def make_noninteractive_response(name: str, x_M: int, X_M: int, N: int,
                                 p: int = P, q: int = Q, g: int = G) -> tuple[int, int]:
    """Non-interactive login response: R = g^k mod p, e = H("login", name, X_M, R, N), z = k + e * x_M mod q."""
    k = secrets.randbelow(q - 1) + 1
    R = pow(g, k, p)
    e = H("login", name, X_M, R, N, q=q)
    z = (k + e * x_M) % q
    return R, z


def verify_noninteractive_login(name: str, R: int, z: int, N: int, X_M: int,
                                p: int = P, q: int = Q, g: int = G) -> bool:
    """Verify non-interactive login: recompute e and check g^z == R * X_M^e mod p."""
    if not (validate_group_element(R) and validate_group_element(X_M)):
        return False
    e = H("login", name, X_M, R, N, q=q)
    left = pow(g, z, p)
    right = (R * pow(X_M, e, p)) % p
    return left == right
