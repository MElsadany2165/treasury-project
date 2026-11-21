"""Milestone 1 secure channel: ECDH handshake, HKDF key derivation, AES-256-GCM framing."""
import hashlib
import struct
from typing import Any

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .config import GROUP
from .encoding import canonical_json
from .framing import ProtocolError, recv_exact


def generate_p256_keypair() -> tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
    """Generate an ECDSA/ECDH-capable P-256 private/public key pair."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key, private_key.public_key()


def public_key_to_point_hex(public_key: ec.EllipticCurvePublicKey) -> str:
    """Uncompressed point hex representation (04 || x || y)."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    ).hex()


def public_key_from_point_hex(point_hex: str) -> ec.EllipticCurvePublicKey:
    """Load uncompressed P-256 public point from hex."""
    return ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(),
        bytes.fromhex(point_hex),
    )


def build_handshake_transcript(member_name: str, X_hex: str, Y_hex: str) -> list[str]:
    """Return the exact transcript list specified in the project handout."""
    return ["hs", GROUP, member_name, X_hex, Y_hex]


def derive_directional_keys(shared_secret: bytes, member_name: str,
                             X_hex: str, Y_hex: str) -> tuple[bytes, bytes]:
    """HKDF-SHA256 to derive 32-byte member->server and server->member keys.
    
    Info = 'ICS505|' + GROUP + '|channel|' followed by SHA-256 of canonical bytes
    of ['hs', GROUP, member name, X, Y].
    Returns (member_to_server_key, server_to_member_key).
    """
    transcript = build_handshake_transcript(member_name, X_hex, Y_hex)
    transcript_hash = hashlib.sha256(canonical_json(transcript)).digest()
    info = f"ICS505|{GROUP}|channel|".encode("utf-8") + transcript_hash
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=None,
        info=info,
    )
    key_material = hkdf.derive(shared_secret)
    return key_material[:32], key_material[32:]


def sign_handshake_step(signer_private_key: ec.EllipticCurvePrivateKey,
                        label: str, member_name: str, X_hex: str, Y_hex: str) -> str:
    """Sign [label, GROUP, member name, X, Y] with ECDSA-SHA256."""
    payload = [label, GROUP, member_name, X_hex, Y_hex]
    sig = signer_private_key.sign(canonical_json(payload), ec.ECDSA(hashes.SHA256()))
    return sig.hex()


def verify_handshake_step(signer_public_key: ec.EllipticCurvePublicKey,
                          sig_hex: str, label: str, member_name: str,
                          X_hex: str, Y_hex: str) -> bool:
    """Verify signature on [label, GROUP, member name, X, Y]."""
    payload = [label, GROUP, member_name, X_hex, Y_hex]
    try:
        signer_public_key.verify(
            bytes.fromhex(sig_hex),
            canonical_json(payload),
            ec.ECDSA(hashes.SHA256()),
        )
        return True
    except (InvalidSignature, ValueError):
        return False


class SecureChannel:
    """AES-256-GCM frames and strict per-direction monotonic counters.

    Required frame: 12-byte nonce || ciphertext+tag. Nonce counter is a
    96-bit big-endian integer starting at zero. Reject skipped/replayed frames.
    """
    def __init__(self, send_key: bytes, receive_key: bytes):
        self.send_key = send_key
        self.receive_key = receive_key
        self.send_counter = 0
        self.receive_counter = 0

    def encrypt(self, plaintext: bytes) -> bytes:
        nonce = self.send_counter.to_bytes(12, "big")
        aesgcm = AESGCM(self.send_key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        self.send_counter += 1
        return nonce + ciphertext

    def decrypt(self, frame: bytes) -> bytes:
        if len(frame) < 12 + 16:
            raise ProtocolError(f"Frame too short: {len(frame)} bytes")
        nonce = frame[:12]
        ciphertext = frame[12:]
        expected_nonce = self.receive_counter.to_bytes(12, "big")
        if nonce != expected_nonce:
            received_int = int.from_bytes(nonce, "big")
            raise ProtocolError(
                f"Nonce mismatch/replay: expected {self.receive_counter}, got {received_int}"
            )
        aesgcm = AESGCM(self.receive_key)
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        except InvalidTag as exc:
            raise ProtocolError("Decryption failed: ciphertext tag verification failed (tampered frame)") from exc
        self.receive_counter += 1
        return plaintext


def send_secure_json(sock, channel: SecureChannel, data: Any) -> None:
    plaintext = canonical_json(data)
    encrypted_frame = channel.encrypt(plaintext)
    header = struct.pack(">I", len(encrypted_frame))
    sock.sendall(header + encrypted_frame)


def recv_secure_json(sock, channel: SecureChannel) -> Any:
    header = recv_exact(sock, 4)
    if not header:
        return None
    (length,) = struct.unpack(">I", header)
    frame = recv_exact(sock, length)
    if not frame:
        raise ProtocolError("Connection closed before frame received")
    plaintext = channel.decrypt(frame)
    import json
    return json.loads(plaintext.decode("utf-8"))
