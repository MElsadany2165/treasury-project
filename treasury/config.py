"""Shared, non-secret project configuration."""
from pathlib import Path

# Student IDs of the group, sorted numerically and joined with hyphens.
GROUP = "5-12-23"

HOST = "127.0.0.1"
SERVER_PORT = 5050
MALLORY_PORT = 6000
MAX_FRAME_BYTES = 4 * 1024 * 1024
SOCKET_TIMEOUT_SECONDS = 15
LOG_DIR = Path("runtime") / "logs"
DATA_DIR = Path("runtime") / "data"

# Project parameters. Keep these configurable; do not hard-code t=3 or n=5
# inside protocol algorithms.
DEFAULT_T = 3
DEFAULT_N = 5
MEMBER_NAMES = tuple(f"M{i}" for i in range(1, DEFAULT_N + 1))

WEAKNESS_NAMES = {
    "unsigned-handshake", "fixed-nonce", "short-challenge", "no-nonce",
    "no-proof", "no-share-check", "unsigned-ballots",
}

# RFC 3526 Group 14: 2048-bit MODP Group
RFC3526_P_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF"
)
P = int(RFC3526_P_HEX, 16)
Q = (P - 1) // 2
G = 4  # Generates the subgroup of order q in Z_p*


def validate_group_element(u: int) -> bool:
    """A received group element u is accepted only if 1 < u < p and u^q mod p = 1."""
    return 1 < u < P and pow(u, Q, P) == 1


def validate_group() -> None:
    if not GROUP or GROUP.startswith("REPLACE-"):
        raise RuntimeError("Set GROUP in treasury/config.py before running the project")

