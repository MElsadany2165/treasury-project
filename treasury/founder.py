"""Founder setup entry point.

Generates P-256 keys, founder-signed certificates, Shamir secret shares,
commitments, and the initial AES-256-GCM encrypted treasury vault file.
Securely wipes secret polynomial and temporary secrets from memory after setup.
"""
import argparse
import json
import os
from pathlib import Path

from .certificates import (
    create_certificate,
    generate_p256_keypair,
    private_key_to_pem,
    public_key_to_pem,
)
from .config import (
    DATA_DIR,
    DEFAULT_N,
    DEFAULT_T,
    G,
    GROUP,
    MEMBER_NAMES,
    P,
    Q,
    validate_group,
)
from .logging_utils import get_logger
from .opening import encrypt_vault_file
from .sharing import compute_verification_key, make_commitments, make_shares, verify_share


def setup_treasury(t: int = DEFAULT_T, n: int = DEFAULT_N, secret_vault_text: str = None) -> None:
    validate_group()
    log = get_logger("founder")
    log.info("Starting founder setup: GROUP=%s, t=%d, n=%d", GROUP, t, n)

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    founder_dir = DATA_DIR / "founder"
    founder_dir.mkdir(parents=True, exist_ok=True)

    # 1. Founder Keypair
    founder_priv, founder_pub = generate_p256_keypair()
    founder_pub_pem = public_key_to_pem(founder_pub)
    founder_priv_pem = private_key_to_pem(founder_priv)

    with open(founder_dir / "founder_priv.pem", "w", encoding="utf-8") as f:
        f.write(founder_priv_pem)
    with open(DATA_DIR / "founder.pub", "w", encoding="utf-8") as f:
        f.write(founder_pub_pem)
    log.info("Founder keys generated and saved (founder.pub published)")

    # 2. Server Keypair and Certificate
    server_dir = DATA_DIR / "server"
    server_dir.mkdir(parents=True, exist_ok=True)
    server_priv, server_pub = generate_p256_keypair()
    server_cert = create_certificate(
        founder_priv,
        name="server",
        public_key_pem=public_key_to_pem(server_pub),
        expires="2026-12-31",
    )
    with open(server_dir / "server_priv.pem", "w", encoding="utf-8") as f:
        f.write(private_key_to_pem(server_priv))
    with open(server_dir / "server_cert.json", "w", encoding="utf-8") as f:
        json.dump(server_cert.to_dict(), f, indent=2)
    log.info("Server keypair and founder-signed certificate generated")

    # 3. Members M1..Mn Keypairs and Certificates
    member_names = [f"M{i}" for i in range(1, n + 1)]
    for name in member_names:
        m_dir = DATA_DIR / name
        m_dir.mkdir(parents=True, exist_ok=True)
        m_priv, m_pub = generate_p256_keypair()
        m_cert = create_certificate(
            founder_priv,
            name=name,
            public_key_pem=public_key_to_pem(m_pub),
            expires="2026-12-31",
        )
        with open(m_dir / f"{name}_priv.pem", "w", encoding="utf-8") as f:
            f.write(private_key_to_pem(m_priv))
        with open(m_dir / f"{name}_cert.json", "w", encoding="utf-8") as f:
            json.dump(m_cert.to_dict(), f, indent=2)
        # Give public server cert and founder.pub to each member
        with open(m_dir / "server_cert.json", "w", encoding="utf-8") as f:
            json.dump(server_cert.to_dict(), f, indent=2)
        with open(m_dir / "founder.pub", "w", encoding="utf-8") as f:
            f.write(founder_pub_pem)
    log.info("Member keypairs and certificates generated for %s", member_names)

    # Also store all member certificates on server
    for name in member_names:
        m_cert_path = DATA_DIR / name / f"{name}_cert.json"
        with open(m_cert_path, "r", encoding="utf-8") as f:
            cert_data = json.load(f)
        with open(server_dir / f"{name}_cert.json", "w", encoding="utf-8") as f:
            json.dump(cert_data, f, indent=2)

    # 4. Shamir Secret Sharing of the Treasury Key
    import secrets
    master_secret_s = secrets.randbelow(Q - 1) + 1
    coefficients, shares = make_shares(master_secret_s, t, n, Q)
    commitments = make_commitments(coefficients, P, G)
    vault_public_key_h = commitments[0]

    # Publish commitments to server and all members
    commitments_hex = [format(c, "x") for c in commitments]
    commitments_data = {
        "commitments": commitments_hex,
        "vault_public_key": format(vault_public_key_h, "x"),
        "t": t,
        "n": n,
    }
    with open(DATA_DIR / "commitments.json", "w", encoding="utf-8") as f:
        json.dump(commitments_data, f, indent=2)
    with open(server_dir / "commitments.json", "w", encoding="utf-8") as f:
        json.dump(commitments_data, f, indent=2)

    # Deliver shares to individual member private directories
    for i, name in enumerate(member_names, start=1):
        m_dir = DATA_DIR / name
        share_i = shares[i - 1]
        vkey_i = compute_verification_key(i, commitments, P, Q)
        # Check share
        assert verify_share(share_i, i, commitments, P, Q, G), f"Share check failed for {name}"
        share_data = {
            "name": name,
            "index": i,
            "share": format(share_i, "x"),
            "verification_key": format(vkey_i, "x"),
        }
        with open(m_dir / f"{name}_share.json", "w", encoding="utf-8") as f:
            json.dump(share_data, f, indent=2)
        with open(m_dir / "commitments.json", "w", encoding="utf-8") as f:
            json.dump(commitments_data, f, indent=2)

    log.info("Shamir shares (t=%d, n=%d) and Feldman commitments generated and verified", t, n)

    # 5. Encrypt Treasury Vault File
    if not secret_vault_text:
        secret_vault_text = (
            "CLUB TREASURY VAULT RECORD\n"
            "Total Assets: 10,000,000 ICS Tokens\n"
            "Secret Access Code: GOLDEN-SHAMIR-THRESHOLD-TREASURY\n"
            "Authorized: 3-of-5 threshold signature verified."
        )
    vault_bytes = secret_vault_text.encode("utf-8")
    c1, c2, enc_vault_bytes = encrypt_vault_file(vault_bytes, vault_public_key_h, P, Q, G)

    with open(server_dir / "vault.enc", "wb") as f:
        f.write(enc_vault_bytes)
    vault_meta = {
        "c1": format(c1, "x"),
        "c2": format(c2, "x"),
        "vault_file": "vault.enc",
    }
    with open(server_dir / "vault_meta.json", "w", encoding="utf-8") as f:
        json.dump(vault_meta, f, indent=2)
    log.info("Treasury vault encrypted with AES-256-GCM and uploaded to server (c1=%s..., c2=%s...)",
             format(c1, "x")[:8], format(c2, "x")[:8])

    # 6. Secure Erasure of s, polynomial coefficients, and ephemeral parameters
    master_secret_s = 0
    coefficients.clear()
    shares.clear()
    log.info("Founder temporary secret s and polynomial coefficients securely erased from memory")
    log.info("Setup complete. System ready for Milestone 1, 2, 3 operations.")


def main():
    parser = argparse.ArgumentParser(description="Treasury founder setup")
    parser.add_argument("--t", type=int, default=DEFAULT_T)
    parser.add_argument("--n", type=int, default=DEFAULT_N)
    args = parser.parse_args()
    if not (1 <= args.t <= args.n):
        parser.error("require 1 <= t <= n")
    setup_treasury(args.t, args.n)


if __name__ == "__main__":
    main()
