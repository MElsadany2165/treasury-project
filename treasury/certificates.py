"""Milestone 1 certificate structure, signing and verification."""
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .config import GROUP
from .encoding import canonical_json


@dataclass
class Certificate:
    group: str
    name: str
    public_key: str
    expires: str
    sig: str = ""

    def unsigned_fields(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if k != "sig"}

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def generate_p256_keypair() -> tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
    """Generate an ECDSA/ECDH-capable P-256 private/public key pair."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key, private_key.public_key()


def public_key_to_pem(public_key: ec.EllipticCurvePublicKey) -> str:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")


def public_key_from_pem(pem_str: str) -> ec.EllipticCurvePublicKey:
    return serialization.load_pem_public_key(pem_str.encode("utf-8"))


def private_key_to_pem(private_key: ec.EllipticCurvePrivateKey) -> str:
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")


def private_key_from_pem(pem_str: str) -> ec.EllipticCurvePrivateKey:
    return serialization.load_pem_private_key(pem_str.encode("utf-8"), password=None)


def create_certificate(founder_private_key: ec.EllipticCurvePrivateKey,
                       name: str,
                       public_key_pem: str,
                       expires: str = "2026-12-31") -> Certificate:
    """Sign canonical_json(unsigned_fields) with founder's ECDSA key."""
    cert = Certificate(group=GROUP, name=name, public_key=public_key_pem, expires=expires)
    data = canonical_json(cert.unsigned_fields())
    signature = founder_private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    cert.sig = signature.hex()
    return cert


def verify_certificate(certificate: dict[str, Any],
                       founder_public_key: ec.EllipticCurvePublicKey,
                       expected_name: str) -> bool:
    """Verify founder signature, GROUP, expected name and expiry date."""
    if not isinstance(certificate, dict):
        return False
    if certificate.get("group") != GROUP:
        return False
    if certificate.get("name") != expected_name:
        return False
    
    expires_str = certificate.get("expires", "")
    try:
        expires_date = datetime.strptime(expires_str, "%Y-%m-%d")
        if datetime.now() > expires_date:
            return False
    except Exception:
        return False

    sig_hex = certificate.get("sig")
    if not sig_hex:
        return False

    unsigned_fields = {k: v for k, v in certificate.items() if k != "sig"}
    data = canonical_json(unsigned_fields)
    try:
        founder_public_key.verify(bytes.fromhex(sig_hex), data, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError):
        return False
