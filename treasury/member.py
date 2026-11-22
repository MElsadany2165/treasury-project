"""Treasury member client implementation:
- TLS-like authenticated ephemeral ECDH handshake
- HKDF-SHA256 directional key derivation
- AES-256-GCM encrypted framing with monotonic counters
- ZK login (interactive and non-interactive)
- ECDSA signed requests with sequence numbers
- Vault threshold decryption share submission with Chaum-Pedersen proofs
- Private voting: encrypted ballot creation, signing, and tally decryption share submission.
"""
import argparse
import json
import socket
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec

from .certificates import (
    private_key_from_pem,
    public_key_from_pem,
    verify_certificate,
)
from .channel import (
    SecureChannel,
    derive_directional_keys,
    generate_p256_keypair,
    public_key_from_point_hex,
    public_key_to_point_hex,
    recv_secure_json,
    send_secure_json,
    sign_handshake_step,
    verify_handshake_step,
)
from .config import (
    DATA_DIR,
    G,
    GROUP,
    HOST,
    P,
    Q,
    SERVER_PORT,
    SOCKET_TIMEOUT_SECONDS,
    validate_group,
)
from .framing import recv_json, send_json
from .logging_utils import get_logger
from .login import (
    make_interactive_commitment,
    make_interactive_response,
    make_noninteractive_response,
    register_login_secret,
)
from .opening import make_decryption_share
from .requests import sign_request
from .voting import encrypt_vote, sign_ballot


class MemberClient:
    def __init__(self, name: str, host: str = HOST, port: int = SERVER_PORT,
                 weak_mode: str | None = None, logger=None):
        self.name = name
        self.host = host
        self.port = port
        self.weak_mode = weak_mode
        self.logger = logger or get_logger(name)
        self.seq = 0

        # Load member credentials from its private directory
        m_dir = DATA_DIR / name
        with open(m_dir / f"{name}_priv.pem", "r", encoding="utf-8") as f:
            self.priv_key = private_key_from_pem(f.read())
        with open(m_dir / f"{name}_cert.json", "r", encoding="utf-8") as f:
            self.cert = json.load(f)
        with open(m_dir / "founder.pub", "r", encoding="utf-8") as f:
            self.founder_pub = public_key_from_pem(f.read())

        # Load share and verification key
        with open(m_dir / f"{name}_share.json", "r", encoding="utf-8") as f:
            share_data = json.load(f)
        self.index = share_data["index"]
        self.share = int(share_data["share"], 16)
        self.vkey = int(share_data["verification_key"], 16)

        # Load commitments and vault public key
        with open(m_dir / "commitments.json", "r", encoding="utf-8") as f:
            commitments_data = json.load(f)
        self.commitments = [int(c, 16) for c in commitments_data["commitments"]]
        self.vault_pub_key = int(commitments_data["vault_public_key"], 16)

        # Generate or load login secret x_M
        self.login_secret_file = m_dir / f"{name}_login_secret.json"
        if self.login_secret_file.exists():
            with open(self.login_secret_file, "r", encoding="utf-8") as f:
                login_data = json.load(f)
            self.x_M = int(login_data["x_M"], 16)
            self.X_M = int(login_data["X_M"], 16)
        else:
            self.x_M, self.X_M = register_login_secret(self.name, P, Q, G)
            with open(self.login_secret_file, "w", encoding="utf-8") as f:
                json.dump({"x_M": format(self.x_M, "x"), "X_M": format(self.X_M, "x")}, f, indent=2)

        self.sock = None
        self.channel = None

    def connect_and_handshake(self) -> None:
        self.logger.info("Connecting to %s:%d as %s", self.host, self.port, self.name)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(SOCKET_TIMEOUT_SECONDS)
        self.sock.connect((self.host, self.port))

        # Generate ephemeral keypair
        m_eph_priv, m_eph_pub = generate_p256_keypair()
        X_hex = public_key_to_point_hex(m_eph_pub)

        # Step 1: Send cert and X
        msg1 = {"cert": self.cert, "X": X_hex}
        send_json(self.sock, msg1)

        # Step 2: Receive server cert, Y, sig
        msg2 = recv_json(self.sock)
        if not msg2:
            raise ConnectionError("Server closed connection during handshake")

        server_cert = msg2["cert"]
        Y_hex = msg2["Y"]
        srv_sig = msg2.get("sig", "")

        # Verify server certificate
        if not verify_certificate(server_cert, self.founder_pub, "server"):
            raise ValueError("Server certificate verification failed!")

        server_pub = public_key_from_pem(server_cert["public_key"])

        # Verify server signature on ["hs-server", GROUP, member_name, X, Y]
        if self.weak_mode == "unsigned-handshake":
            self.logger.warning("WEAK MODE: skipping handshake signature verification")
        else:
            if not srv_sig or not verify_handshake_step(server_pub, srv_sig, "hs-server", self.name, X_hex, Y_hex):
                self.logger.error("M1 rejects the handshake: the server's signature is missing or invalid")
                raise ValueError("Server handshake signature verification failed!")

        # Step 3: Member signs ["hs-member", GROUP, member_name, X, Y]
        if self.weak_mode == "unsigned-handshake":
            m_sig_hex = ""
        else:
            m_sig_hex = sign_handshake_step(self.priv_key, "hs-member", self.name, X_hex, Y_hex)
        send_json(self.sock, {"sig": m_sig_hex})

        # Derive keys
        srv_eph_pub = public_key_from_point_hex(Y_hex)
        shared_secret = m_eph_priv.exchange(ec.ECDH(), srv_eph_pub)
        m2s_key, s2m_key = derive_directional_keys(shared_secret, self.name, X_hex, Y_hex)

        # Member sends with m2s_key, receives with s2m_key
        self.channel = SecureChannel(send_key=m2s_key, receive_key=s2m_key)
        self.logger.info("Secure channel established with server (AES-256-GCM)")

    def register_login(self) -> None:
        send_secure_json(self.sock, self.channel, {
            "op": "register",
            "name": self.name,
            "X_M": format(self.X_M, "x"),
        })
        resp = recv_secure_json(self.sock, self.channel)
        if not resp or not resp.get("ok"):
            raise RuntimeError(f"Registration failed: {resp}")

    def login_interactive(self) -> None:
        # Step 1: send R
        k, R = make_interactive_commitment(P, Q, G)
        send_secure_json(self.sock, self.channel, {
            "op": "login-init",
            "R": format(R, "x"),
        })
        resp1 = recv_secure_json(self.sock, self.channel)
        if not resp1 or not resp1.get("ok"):
            raise RuntimeError(f"Login init failed: {resp1}")
        challenge = resp1["challenge"]

        # Step 2: send z
        z = make_interactive_response(self.x_M, k, challenge, Q)
        send_secure_json(self.sock, self.channel, {
            "op": "login-finish",
            "z": format(z, "x"),
        })
        resp2 = recv_secure_json(self.sock, self.channel)
        if not resp2 or not resp2.get("ok"):
            raise RuntimeError(f"Login failed: {resp2}")
        self.logger.info("Interactive zero-knowledge login successful")

    def login_noninteractive(self) -> None:
        import secrets
        nonce_N = secrets.randbits(128)
        R, z = make_noninteractive_response(self.name, self.x_M, self.X_M, nonce_N, P, Q, G)
        send_secure_json(self.sock, self.channel, {
            "op": "login-noninteractive",
            "R": format(R, "x"),
            "z": format(z, "x"),
            "N": nonce_N,
        })
        resp = recv_secure_json(self.sock, self.channel)
        if not resp or not resp.get("ok"):
            raise RuntimeError(f"Non-interactive login failed: {resp}")
        self.logger.info("Non-interactive zero-knowledge login successful")

    def send_signed_request(self, op: str, body: dict[str, Any]) -> dict[str, Any]:
        self.seq += 1
        req_signed = sign_request(self.priv_key, GROUP, self.name, self.seq, op, body)
        send_secure_json(self.sock, self.channel, {
            "op": "request",
            "request": req_signed,
        })
        resp = recv_secure_json(self.sock, self.channel)
        return resp

    def submit_vault_share(self, c1: int, cheat_mult_g: bool = False) -> dict[str, Any]:
        d_obj = make_decryption_share(self.share, self.index, c1, self.vkey, P, Q, G)
        d_i = d_obj["d_i"]
        if cheat_mult_g:
            # Cheat: send d_i * g mod p (A5)
            d_i = (d_i * G) % P
            self.logger.warning("CHEATING: Sending tampered share d_%d * g mod p", self.index)

        payload = {
            "op": "vault-share",
            "member_index": self.index,
            "d_i": format(d_i, "x"),
            "T_1": format(d_obj["T_1"], "x"),
            "T_2": format(d_obj["T_2"], "x"),
            "z": format(d_obj["z"], "x"),
        }
        send_secure_json(self.sock, self.channel, payload)
        return recv_secure_json(self.sock, self.channel)

    def submit_ballot(self, vote_number: int, vote: int, unsigned: bool = False, tamper_c2_mult_g: bool = False) -> dict[str, Any]:
        c1, c2 = encrypt_vote(vote, self.vault_pub_key, P, Q, G)
        if unsigned:
            sig = ""
        else:
            sig = sign_ballot(self.priv_key, GROUP, self.name, vote_number, c1, c2)

        if tamper_c2_mult_g:
            c2 = (c2 * G) % P
            self.logger.warning("ATTACK A7: Tampered c2 multiplied by g mod p")

        payload = {
            "op": "ballot",
            "member_name": self.name,
            "vote_number": vote_number,
            "c1": format(c1, "x"),
            "c2": format(c2, "x"),
            "sig": sig,
        }
        send_secure_json(self.sock, self.channel, payload)
        return recv_secure_json(self.sock, self.channel)

    def submit_tally_share(self, vote_number: int, C1: int) -> dict[str, Any]:
        d_obj = make_decryption_share(self.share, self.index, C1, self.vkey, P, Q, G)
        payload = {
            "op": "tally-share",
            "vote_number": vote_number,
            "member_index": self.index,
            "d_i": format(d_obj["d_i"], "x"),
            "T_1": format(d_obj["T_1"], "x"),
            "T_2": format(d_obj["T_2"], "x"),
            "z": format(d_obj["z"], "x"),
        }
        send_secure_json(self.sock, self.channel, payload)
        return recv_secure_json(self.sock, self.channel)

    def close(self):
        if self.sock:
            self.sock.close()
            self.sock = None


def main():
    parser = argparse.ArgumentParser(description="Treasury Member Client")
    parser.add_argument("--name", default="M1")
    parser.add_argument("--host", default=HOST)
    parser.add_argument("--port", type=int, default=SERVER_PORT)
    parser.add_argument("--weak", default=None)
    parser.add_argument("--action", default="login", choices=["login", "spend", "propose", "vault", "vote"])
    parser.add_argument("--amount", type=int, default=50)
    parser.add_argument("--reason", default="pizza")
    parser.add_argument("--vote", type=int, default=1)
    parser.add_argument("--vote-number", type=int, default=1)
    args = parser.parse_args()

    validate_group()
    client = MemberClient(args.name, host=args.host, port=args.port, weak_mode=args.weak)
    try:
        client.connect_and_handshake()
        client.register_login()
        client.login_interactive()

        if args.action == "spend":
            resp = client.send_signed_request("spend", {"amount": args.amount, "reason": args.reason})
            client.logger.info("Spend response: %s", resp)
        elif args.action == "propose":
            resp = client.send_signed_request("propose_spending", {"amount": args.amount, "reason": args.reason})
            client.logger.info("Proposal response: %s", resp)
        elif args.action == "vote":
            resp = client.submit_ballot(args.vote_number, args.vote)
            client.logger.info("Ballot response: %s", resp)
    finally:
        client.close()


if __name__ == "__main__":
    main()
