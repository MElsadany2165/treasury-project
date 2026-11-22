"""Attack harness entry point.
Implements:
- Mandatory Attack A1: Man-In-The-Middle Proxy (--weak unsigned-handshake)
- Mandatory Attack A5: Cheating Member with missing/invalid proof (--weak no-proof)
- Bonus Attack A7: Changed ballot (--weak unsigned-ballots)
"""
import argparse
import json
import socket
import threading
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec

from .certificates import generate_p256_keypair, public_key_from_pem, verify_certificate
from .channel import (
    SecureChannel,
    derive_directional_keys,
    public_key_from_point_hex,
    public_key_to_point_hex,
    recv_secure_json,
    send_secure_json,
)
from .config import (
    DATA_DIR,
    G,
    GROUP,
    HOST,
    MALLORY_PORT,
    P,
    Q,
    SERVER_PORT,
    SOCKET_TIMEOUT_SECONDS,
    WEAKNESS_NAMES,
    validate_group,
)
from .framing import recv_json, send_json
from .logging_utils import get_logger
from .opening import (
    decrypt_vault_file,
    encrypt_vault_file,
    make_decryption_share,
    verify_decryption_share,
)
from .sharing import compute_verification_key, make_commitments, make_shares
from .voting import (
    aggregate_ballots,
    decrypt_tally,
    encrypt_vote,
    sign_ballot,
    tamper_ballot_a7,
    verify_ballot,
)


def run_a1_mitm_proxy(weak: bool = True):
    """Run A1 MITM TCP proxy on MALLORY_PORT (6000), forwarding to SERVER_PORT (5050)."""
    log = get_logger("mallory")
    log.info("Starting A1 MITM Proxy on %s:%d forwarding to %s:%d (weak=%s)",
             HOST, MALLORY_PORT, HOST, SERVER_PORT, weak)

    proxy_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    proxy_sock.bind((HOST, MALLORY_PORT))
    proxy_sock.listen()

    log.info("Mallory proxy listening on port %d...", MALLORY_PORT)

    while True:
        try:
            client_conn, client_addr = proxy_sock.accept()
            log.info("Mallory intercepted connection from M1 at %s", client_addr)

            # Connect to actual server on 5050
            server_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_conn.connect((HOST, SERVER_PORT))

            # Intercept Msg 1 from M1: {"cert": cert_M1, "X": X_m1}
            msg1 = recv_json(client_conn)
            log.info("Mallory intercepted Msg 1 from M1: cert name=%s, X=%s...",
                     msg1["cert"]["name"], msg1["X"][:8])

            # Mallory generates her own ephemeral keys
            mal_eph_priv_to_srv, mal_eph_pub_to_srv = generate_p256_keypair()
            mal_X_to_srv = public_key_to_point_hex(mal_eph_pub_to_srv)

            # Forward modified Msg 1 to Server with Mallory's ephemeral key
            msg1_to_srv = {"cert": msg1["cert"], "X": mal_X_to_srv}
            send_json(server_conn, msg1_to_srv)

            # Receive Msg 2 from Server: {"cert": server_cert, "Y": Y_srv, "sig": srv_sig}
            msg2 = recv_json(server_conn)
            log.info("Mallory intercepted Msg 2 from Server: Y=%s..., sig=%s...",
                     msg2["Y"][:8], (msg2.get("sig") or "")[:8])

            # Mallory generates ephemeral keys for M1
            mal_eph_priv_to_m1, mal_eph_pub_to_m1 = generate_p256_keypair()
            mal_Y_to_m1 = public_key_to_point_hex(mal_eph_pub_to_m1)

            # Forward Msg 2 to M1
            if weak:
                # In weak mode: handshake signatures are omitted
                msg2_to_m1 = {"cert": msg2["cert"], "Y": mal_Y_to_m1, "sig": ""}
            else:
                # In secure mode: Mallory cannot forge server signature on (X_m1, mal_Y)
                # Forward server's signature on (mal_X, Y_srv) which M1 will reject!
                msg2_to_m1 = {"cert": msg2["cert"], "Y": mal_Y_to_m1, "sig": msg2.get("sig", "")}

            send_json(client_conn, msg2_to_m1)

            # Receive Msg 3 from M1
            msg3 = recv_json(client_conn)
            if not msg3:
                log.info("M1 rejected the handshake! Connection closed.")
                client_conn.close()
                server_conn.close()
                break

            log.info("Mallory intercepted Msg 3 from M1: sig=%s...", msg3.get("sig", "")[:8])

            # Forward Msg 3 to Server
            send_json(server_conn, msg3)

            # Mallory establishes independent SecureChannel with M1 and with Server
            m1_pub = public_key_from_point_hex(msg1["X"])
            srv_pub = public_key_from_point_hex(msg2["Y"])

            ss_m1 = mal_eph_priv_to_m1.exchange(ec.ECDH(), m1_pub)
            ss_srv = mal_eph_priv_to_srv.exchange(ec.ECDH(), srv_pub)

            m1_to_mal, mal_to_m1 = derive_directional_keys(ss_m1, msg1["cert"]["name"], msg1["X"], mal_Y_to_m1)
            mal_to_srv, srv_to_mal = derive_directional_keys(ss_srv, msg1["cert"]["name"], mal_X_to_srv, msg2["Y"])

            chan_m1 = SecureChannel(send_key=mal_to_m1, receive_key=m1_to_mal)
            chan_srv = SecureChannel(send_key=mal_to_srv, receive_key=srv_to_mal)

            log.info("Mallory successfully MITMed the secure channel! Now eavesdropping plaintext frames...")

            # Forward traffic between M1 and Server, decrypting and logging in clear
            while True:
                plain_from_m1 = recv_secure_json(client_conn, chan_m1)
                if plain_from_m1 is None:
                    break
                log.info("Mallory eavesdropped from M1 (IN CLEAR): %s", plain_from_m1)

                # Try to modify request
                if plain_from_m1.get("op") == "request":
                    log.info("Mallory attempting to tamper with M1's signed request...")
                    # Forward as is or show that modifying invalidates signature
                send_secure_json(server_conn, chan_srv, plain_from_m1)

                plain_from_srv = recv_secure_json(server_conn, chan_srv)
                if plain_from_srv is None:
                    break
                log.info("Mallory eavesdropped from Server (IN CLEAR): %s", plain_from_srv)
                send_secure_json(client_conn, chan_m1, plain_from_srv)

            client_conn.close()
            server_conn.close()
            break
        except Exception as exc:
            log.error("Mallory proxy exception: %s", exc)
            break
    proxy_sock.close()


def run_a5_cheating_member_demo():
    """Demonstrate A5: Cheating member M3 sending d_3 * g mod p in weak vs secure mode."""
    log = get_logger("mallory")
    log.info("=== Running Mandatory Attack A5: Cheating Member Demo ===")

    # Setup simulated environment
    import secrets
    secret = secrets.randbelow(Q - 1) + 1
    t, n = 3, 5
    coeffs, shares = make_shares(secret, t, n, Q)
    commitments = make_commitments(coeffs, P, G)
    h = commitments[0]
    vkeys = [compute_verification_key(i, commitments, P, Q) for i in range(1, n + 1)]

    vault_text = b"CONFIDENTIAL TREASURY RESERVES: 10,000,000 GOLD COINS"
    c1, c2, enc_vault = encrypt_vault_file(vault_text, h, P, Q, G)

    log.info("Step 1: Mallory's goal: M3 cheats by submitting d_3 * g mod p to corrupt vault opening.")

    # 1. Weak Mode Demonstration (--weak no-proof)
    log.info("Step 2: Weak Mode (--weak no-proof) demonstration:")
    d1 = make_decryption_share(shares[0], 1, c1, vkeys[0], P, Q, G)
    d2 = make_decryption_share(shares[1], 2, c1, vkeys[1], P, Q, G)

    # Cheated share
    honest_d3 = pow(c1, shares[2], P)
    cheated_d3 = (honest_d3 * G) % P
    log.info("M3 computes honest d_3=%s, but sends cheated d_3 * g mod p=%s",
             format(honest_d3, "x")[:8], format(cheated_d3, "x")[:8])

    weak_shares = {1: d1["d_i"], 2: d2["d_i"], 3: cheated_d3}
    try:
        decrypt_vault_file(c1, c2, enc_vault, weak_shares, P, Q)
        log.error("Unexpected success")
    except Exception as exc:
        log.info("DAMAGE IN WEAK MODE: The vault does not open (AES-GCM decryption failed), and nobody can tell who cheated!")

    # 2. Secure Mode Demonstration
    log.info("Step 3: Secure Mode demonstration:")
    d3_obj = make_decryption_share(shares[2], 3, c1, vkeys[2], P, Q, G)
    proof_check = verify_decryption_share(3, c1, vkeys[2], cheated_d3, d3_obj["T_1"], d3_obj["T_2"], d3_obj["z"], P, Q, G)
    log.info("Server checks Chaum-Pedersen proof for M3's share: result=%s", proof_check)
    if not proof_check:
        log.info("Server log: decryption share from M3: d=%s proof FAILED, rejected", format(cheated_d3, "x")[:8])
        log.info("WHAT STOPS MALLORY: Server rejects M3's corrupted share and opens the vault with another member (M4)!")
        d4_obj = make_decryption_share(shares[3], 4, c1, vkeys[3], P, Q, G)
        secure_shares = {1: d1["d_i"], 2: d2["d_i"], 4: d4_obj["d_i"]}
        recovered = decrypt_vault_file(c1, c2, enc_vault, secure_shares, P, Q)
        log.info("Vault successfully opened: %s", recovered.decode("utf-8"))


def run_a7_tampered_ballot_demo():
    """Demonstrate Bonus Attack A7: Changing an unsigned encrypted ballot in weak vs secure mode."""
    log = get_logger("mallory")
    log.info("=== Running Bonus Attack A7: Tampered Ballot Demo ===")

    import secrets
    secret = secrets.randbelow(Q - 1) + 1
    t, n = 3, 5
    coeffs, shares = make_shares(secret, t, n, Q)
    commitments = make_commitments(coeffs, P, G)
    h = commitments[0]
    vkeys = [compute_verification_key(i, commitments, P, Q) for i in range(1, n + 1)]

    # M3 votes NO (0)
    m3_priv, m3_pub = generate_p256_keypair()
    c1, c2 = encrypt_vote(0, h, P, Q, G)
    sig = sign_ballot(m3_priv, GROUP, "M3", 1, c1, c2)
    ballot = {"member_name": "M3", "vote_number": 1, "c1": format(c1, "x"), "c2": format(c2, "x"), "sig": sig}

    log.info("M3 cast NO ballot: c1=%s..., c2=%s...", ballot["c1"][:8], ballot["c2"][:8])

    # Mallory intercepts and multiplies c2 by g mod p
    tampered = tamper_ballot_a7(ballot, P, G)
    log.info("Mallory tampered ballot: c2' = c2 * g mod p -> %s...", tampered["c2"][:8])

    # 1. Weak mode (--weak unsigned-ballots)
    log.info("WEAK MODE (--weak unsigned-ballots): Ballots are not signed/verified.")
    C1, C2 = aggregate_ballots([tampered], P)
    shares_dict = {}
    for i in [1, 2, 3]:
        d = make_decryption_share(shares[i - 1], i, C1, vkeys[i - 1], P, Q, G)
        shares_dict[i] = d["d_i"]
    tally = decrypt_tally(C1, C2, shares_dict, max_votes=1, p=P, q=Q, g=G)
    log.info("DAMAGE IN WEAK MODE: Total YES votes decrypted = %d (NO was flipped to YES without decrypting!)", tally)

    # 2. Secure mode
    log.info("SECURE MODE: Server verifies member's ECDSA signature over ballot transcript.")
    verified = verify_ballot(m3_pub, tampered, GROUP)
    log.info("Server signature check on tampered ballot: %s", verified)
    if not verified:
        log.info("WHAT STOPS MALLORY: Server log: ballot from M3 signature FAILED, rejected! Attack stopped.")


def main():
    parser = argparse.ArgumentParser(description="Treasury Attack Harness")
    parser.add_argument("--attack", required=True, choices=["A1", "A2", "A3", "A4", "A5", "A6", "A7"])
    parser.add_argument("--weak", default=None)
    args = parser.parse_args()
    validate_group()

    if args.attack == "A1":
        run_a1_mitm_proxy(weak=(args.weak == "unsigned-handshake"))
    elif args.attack == "A5":
        run_a5_cheating_member_demo()
    elif args.attack == "A7":
        run_a7_tampered_ballot_demo()
    else:
        log = get_logger("mallory")
        log.info("Attack %s runner", args.attack)


if __name__ == "__main__":
    main()
