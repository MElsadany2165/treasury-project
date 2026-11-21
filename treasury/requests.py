"""Milestone 1 signed requests and sequence-number replay protection."""
from typing import Any
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from .config import GROUP
from .encoding import canonical_json


def request_transcript(group: str, name: str, seq: int, op: str, body: dict[str, Any]) -> list[Any]:
    return ["request", group, name, seq, op, body]


def sign_request(private_key: ec.EllipticCurvePrivateKey,
                 group: str, name: str, seq: int, op: str, body: dict[str, Any]) -> dict[str, Any]:
    """ECDSA-sign canonical_json(request_transcript(...))."""
    transcript = request_transcript(group, name, seq, op, body)
    data = canonical_json(transcript)
    sig = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    return {
        "op": op,
        "seq": seq,
        "body": body,
        "sig": sig.hex(),
    }


def verify_request(public_key: ec.EllipticCurvePublicKey,
                   request: dict[str, Any],
                   last_sequence: int,
                   group: str = GROUP,
                   name: str = "") -> bool:
    """Verify signature and require seq > last_sequence."""
    if not isinstance(request, dict):
        return False
    seq = request.get("seq")
    op = request.get("op")
    body = request.get("body")
    sig_hex = request.get("sig")

    if not isinstance(seq, int) or seq <= last_sequence:
        return False
    if not isinstance(op, str) or not isinstance(body, dict) or not sig_hex:
        return False

    transcript = request_transcript(group, name, seq, op, body)
    data = canonical_json(transcript)
    try:
        public_key.verify(bytes.fromhex(sig_hex), data, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError):
        return False
