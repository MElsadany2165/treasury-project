"""Milestone 2 verifiable decryption shares, Chaum-Pedersen proofs, and vault encryption/decryption."""
import secrets
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .config import G, GROUP, P, Q, validate_group_element
from .encoding import H
from .sharing import lagrange_coefficient


def derive_vault_key(m: int) -> bytes:
    """Derive 32-byte AES-256-GCM vault file key from m using HKDF-SHA256."""
    m_bytes = m.to_bytes((m.bit_length() + 7) // 8, "big")
    info = f"ICS505|{GROUP}|vault".encode("utf-8")
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info,
    )
    return hkdf.derive(m_bytes)


def encrypt_vault_file(file_bytes: bytes, h: int,
                       p: int = P, q: int = Q, g: int = G) -> tuple[int, int, bytes]:
    """Encrypt a vault file under the shared vault public key h = C_0.
    
    Picks random u in Z_q, sets m = g^u mod p.
    Picks fresh r in Z_q, computes c1 = g^r mod p, c2 = m * h^r mod p.
    Encrypts file with AES-256-GCM under key derived from m.
    Returns (c1, c2, encrypted_file_with_nonce).
    """
    u = secrets.randbelow(q - 1) + 1
    m = pow(g, u, p)
    r = secrets.randbelow(q - 1) + 1
    c1 = pow(g, r, p)
    c2 = (m * pow(h, r, p)) % p

    vault_key = derive_vault_key(m)
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(vault_key).encrypt(nonce, file_bytes, None)
    return c1, c2, nonce + ciphertext


def make_decryption_share(share: int, member_index: int, c1: int, h_i: int,
                          p: int = P, q: int = Q, g: int = G) -> dict[str, Any]:
    """Compute d_i = c1^s_i mod p and Chaum-Pedersen proof:
    w in Z_q, T1 = g^w mod p, T2 = c1^w mod p,
    e = H("dec", i, c1, h_i, d_i, T1, T2),
    z = w + e * s_i mod q.
    """
    d_i = pow(c1, share, p)
    w = secrets.randbelow(q - 1) + 1
    T_1 = pow(g, w, p)
    T_2 = pow(c1, w, p)
    e = H("dec", member_index, c1, h_i, d_i, T_1, T_2, q=q)
    z = (w + e * share) % q
    return {
        "member_index": member_index,
        "d_i": d_i,
        "T_1": T_1,
        "T_2": T_2,
        "z": z,
    }


def verify_decryption_share(member_index: int, c1: int, h_i: int, d_i: int,
                            T_1: int, T_2: int, z: int,
                            p: int = P, q: int = Q, g: int = G) -> bool:
    """Verify Chaum-Pedersen proof for equality of discrete logs:
    Check group membership for d_i, T_1, T_2.
    Recompute e = H("dec", i, c1, h_i, d_i, T1, T2)
    Check g^z == T1 * h_i^e mod p and c1^z == T2 * d_i^e mod p.
    """
    if not (validate_group_element(d_i) and validate_group_element(T_1) and validate_group_element(T_2)):
        return False
    e = H("dec", member_index, c1, h_i, d_i, T_1, T_2, q=q)
    check1 = pow(g, z, p) == (T_1 * pow(h_i, e, p)) % p
    check2 = pow(c1, z, p) == (T_2 * pow(d_i, e, p)) % p
    return check1 and check2


def combine_decryption_shares(shares_dict: dict[int, int], c2: int,
                              p: int = P, q: int = Q) -> int:
    """Combine at least t accepted decryption shares using Lagrange interpolation:
    D = product of (d_i ^ lambda_i) mod p
    m = c2 * D^(-1) mod p.
    """
    indices = list(shares_dict.keys())
    D = 1
    for i, d_i in shares_dict.items():
        lambda_i = lagrange_coefficient(i, indices, q)
        D = (D * pow(d_i, lambda_i, p)) % p
    m = (c2 * pow(D, -1, p)) % p
    return m


def decrypt_vault_file(c1: int, c2: int, encrypted_file_with_nonce: bytes,
                       shares_dict: dict[int, int],
                       p: int = P, q: int = Q) -> bytes:
    """Combine shares, derive vault key, and AES-256-GCM decrypt the vault file."""
    m = combine_decryption_shares(shares_dict, c2, p, q)
    vault_key = derive_vault_key(m)
    nonce = encrypted_file_with_nonce[:12]
    ciphertext = encrypted_file_with_nonce[12:]
    return AESGCM(vault_key).decrypt(nonce, ciphertext, None)
