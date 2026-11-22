"""Treasury server implementation:
- TLS-like authenticated ephemeral ECDH handshake
- HKDF-SHA256 directional key derivation
- AES-256-GCM encrypted framing with monotonic counters
- Member registration and ZK login (interactive and non-interactive)
- Signed requests and strictly monotonic replay-protected ledger
- Threshold vault opening with Chaum-Pedersen proof verification
- Private voting: homomorphic ballot aggregation, threshold tally decryption, and spending approval.
"""
import argparse
import json
import socket
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec

from .certificates import (
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
    DEFAULT_N,
    DEFAULT_T,
    G,
    GROUP,
    HOST,
    P,
    Q,
    SERVER_PORT,
    SOCKET_TIMEOUT_SECONDS,
    WEAKNESS_NAMES,
    validate_group,
    validate_group_element,
)
from .framing import ProtocolError, recv_json, send_json
from .logging_utils import get_logger
from .login import verify_interactive_login, verify_noninteractive_login
from .opening import decrypt_vault_file, verify_decryption_share
from .requests import verify_request
from .sharing import compute_verification_key
from .voting import (
    aggregate_ballots,
    check_spending_approval,
    decrypt_tally,
    verify_ballot,
)


class TreasuryServerState:
    def __init__(self, t: int = DEFAULT_T, n: int = DEFAULT_N):
        self.t = t
        self.n = n
        self.registered_logins: dict[str, int] = {}
        self.member_last_seq: dict[str, int] = {}
        self.accepted_ledger: list[dict[str, Any]] = []
        self.used_nonces: set[int] = set()

        # Vault state
        self.vault_shares: dict[int, int] = {}
        self.vault_opened: bool = False
        self.vault_content: str | None = None

        # Voting state
        self.proposals: dict[int, dict[str, Any]] = {}
        self.ballots: dict[int, dict[str, dict[str, Any]]] = {}  # vote_num -> {member_name -> ballot}
        self.tally_shares: dict[int, dict[int, int]] = {}  # vote_num -> {member_index -> d_i}
        self.voting_results: dict[int, dict[str, Any]] = {}
        self.current_vote_number = 0


def load_server_credentials():
    server_dir = DATA_DIR / "server"
    with open(DATA_DIR / "founder.pub", "r", encoding="utf-8") as f:
        founder_pub = public_key_from_pem(f.read())
    with open(server_dir / "server_priv.pem", "r", encoding="utf-8") as f:
        from .certificates import private_key_from_pem
        server_priv = private_key_from_pem(f.read())
    with open(server_dir / "server_cert.json", "r", encoding="utf-8") as f:
        server_cert = json.load(f)

    # Load commitments
    with open(server_dir / "commitments.json", "r", encoding="utf-8") as f:
        commitments_data = json.load(f)
    commitments = [int(c, 16) for c in commitments_data["commitments"]]
    t = commitments_data.get("t", DEFAULT_T)
    n = commitments_data.get("n", DEFAULT_N)

    # Load vault metadata and encrypted bytes if available
    vault_meta_path = server_dir / "vault_meta.json"
    vault_meta = None
    enc_vault_bytes = None
    if vault_meta_path.exists():
        with open(vault_meta_path, "r", encoding="utf-8") as f:
            vault_meta = json.load(f)
        with open(server_dir / vault_meta["vault_file"], "rb") as f:
            enc_vault_bytes = f.read()

    return founder_pub, server_priv, server_cert, commitments, t, n, vault_meta, enc_vault_bytes


def handle_client_connection(conn: socket.socket, addr, state: TreasuryServerState,
                            founder_pub, server_priv, server_cert,
                            commitments, vault_meta, enc_vault_bytes,
                            weak_mode: str | None, logger) -> None:
    member_name = "unknown"
    try:
        # --- 1. Handshake ---
        # Msg 1 from member: {"cert": member_cert, "X": X_hex}
        msg1 = recv_json(conn)
        if not msg1 or "cert" not in msg1 or "X" not in msg1:
            logger.error("Handshake Msg 1 invalid from %s", addr)
            return

        member_cert = msg1["cert"]
        member_name = member_cert.get("name", "unknown")
        X_hex = msg1["X"]

        # Verify member certificate
        if not verify_certificate(member_cert, founder_pub, member_name):
            logger.error("Handshake rejected: invalid certificate from %s (name: %s)", addr, member_name)
            return

        member_pub = public_key_from_pem(member_cert["public_key"])

        # Server generates ephemeral keypair
        srv_eph_priv, srv_eph_pub = generate_p256_keypair()
        Y_hex = public_key_to_point_hex(srv_eph_pub)

        # Server signs handshake Msg 2: ["hs-server", GROUP, member_name, X, Y]
        if weak_mode == "unsigned-handshake":
            srv_sig_hex = ""
        else:
            srv_sig_hex = sign_handshake_step(server_priv, "hs-server", member_name, X_hex, Y_hex)

        msg2 = {"cert": server_cert, "Y": Y_hex, "sig": srv_sig_hex}
        send_json(conn, msg2)

        # Msg 3 from member: {"sig": member_sig_hex}
        msg3 = recv_json(conn)
        if not msg3 or "sig" not in msg3:
            logger.error("Handshake Msg 3 missing from %s", member_name)
            return

        if weak_mode != "unsigned-handshake":
            if not verify_handshake_step(member_pub, msg3["sig"], "hs-member", member_name, X_hex, Y_hex):
                logger.error("Handshake rejected: invalid member signature from %s", member_name)
                return

        logger.info("handshake from %s: certificate OK (group %s), signature OK", member_name, GROUP)

        # Derive shared secret and session keys
        m_eph_pub = public_key_from_point_hex(X_hex)
        shared_secret = srv_eph_priv.exchange(ec.ECDH(), m_eph_pub)
        m2s_key, s2m_key = derive_directional_keys(shared_secret, member_name, X_hex, Y_hex)

        # Server sends with s2m_key, receives with m2s_key
        channel = SecureChannel(send_key=s2m_key, receive_key=m2s_key)

        # --- 2. Secure Channel Session Loop ---
        authenticated = False
        pending_interactive_challenge = None
        pending_R = None

        while True:
            req = recv_secure_json(conn, channel)
            if req is None:
                break

            msg_type = req.get("type") or req.get("op")

            if msg_type == "register":
                # Registration of login public value X_M
                x_m_hex = req.get("X_M")
                X_M = int(x_m_hex, 16)
                if not validate_group_element(X_M):
                    send_secure_json(conn, channel, {"ok": False, "error": "Invalid group element"})
                    continue
                if member_name not in state.registered_logins:
                    state.registered_logins[member_name] = X_M
                    logger.info("registered login key for %s: X_M=%s...", member_name, x_m_hex[:8])
                send_secure_json(conn, channel, {"ok": True, "msg": "registered"})

            elif msg_type == "login-init":
                # Interactive login init: member sends R
                R_hex = req.get("R")
                R = int(R_hex, 16)
                if not validate_group_element(R):
                    send_secure_json(conn, channel, {"ok": False, "error": "Invalid R element"})
                    continue
                pending_R = R
                import secrets
                if weak_mode == "short-challenge":
                    e = secrets.randbits(4)
                else:
                    e = secrets.randbits(128)
                pending_interactive_challenge = e
                send_secure_json(conn, channel, {"ok": True, "challenge": e})

            elif msg_type == "login-finish":
                # Interactive login finish: member sends z
                z_hex = req.get("z")
                z = int(z_hex, 16)
                X_M = state.registered_logins.get(member_name)
                if X_M is None or pending_interactive_challenge is None or pending_R is None:
                    send_secure_json(conn, channel, {"ok": False, "error": "Login sequence error"})
                    continue
                e = pending_interactive_challenge
                if verify_interactive_login(pending_R, z, e, X_M):
                    authenticated = True
                    logger.info("login %s: R=%s e=%s z=%s g^z = R*X^e: OK",
                                member_name, format(pending_R, "x")[:8], format(e, "x")[:8], z_hex[:8])
                    send_secure_json(conn, channel, {"ok": True, "msg": "login OK"})
                else:
                    logger.warning("login %s: FAILED", member_name)
                    send_secure_json(conn, channel, {"ok": False, "error": "Login verification failed"})

            elif msg_type == "login-noninteractive":
                # Non-interactive login
                R = int(req.get("R"), 16)
                z = int(req.get("z"), 16)
                N = int(req.get("N"))
                X_M = state.registered_logins.get(member_name)
                if X_M is None:
                    send_secure_json(conn, channel, {"ok": False, "error": "Member not registered"})
                    continue

                if weak_mode != "no-nonce":
                    if N in state.used_nonces:
                        logger.warning("Replayed non-interactive login nonce N=%d from %s rejected", N, member_name)
                        send_secure_json(conn, channel, {"ok": False, "error": "Replayed nonce"})
                        continue
                    state.used_nonces.add(N)

                if verify_noninteractive_login(member_name, R, z, N, X_M):
                    authenticated = True
                    logger.info("login %s OK (non-interactive, N=%s...)", member_name, str(N)[:8])
                    send_secure_json(conn, channel, {"ok": True, "msg": "login OK"})
                else:
                    logger.warning("non-interactive login for %s FAILED", member_name)
                    send_secure_json(conn, channel, {"ok": False, "error": "Login verification failed"})

            elif msg_type == "request":
                # Signed request
                if not authenticated:
                    send_secure_json(conn, channel, {"ok": False, "error": "Authentication required"})
                    continue
                req_obj = req.get("request", {})
                last_seq = state.member_last_seq.get(member_name, 0)
                if not verify_request(member_pub, req_obj, last_seq, GROUP, member_name):
                    logger.warning("request from %s signature FAILED or invalid seq: %s", member_name, req_obj)
                    send_secure_json(conn, channel, {"ok": False, "error": "Request signature or sequence invalid"})
                    continue

                seq = req_obj["seq"]
                op = req_obj["op"]
                body = req_obj["body"]
                state.member_last_seq[member_name] = seq
                state.accepted_ledger.append({
                    "name": member_name,
                    "seq": seq,
                    "op": op,
                    "body": body,
                })
                logger.info("request %s seq %d %s: signature OK, added to ledger", member_name, seq, op)

                # Process operations
                if op == "propose_spending":
                    state.current_vote_number += 1
                    v_num = state.current_vote_number
                    state.proposals[v_num] = {
                        "vote_number": v_num,
                        "proposer": member_name,
                        "amount": body.get("amount"),
                        "reason": body.get("reason"),
                        "status": "voting_open",
                    }
                    state.ballots[v_num] = {}
                    state.tally_shares[v_num] = {}
                    logger.info("Spending proposal opened: Vote #%d by %s for %s (%s)",
                                v_num, member_name, body.get("amount"), body.get("reason"))
                    send_secure_json(conn, channel, {"ok": True, "vote_number": v_num, "status": "voting_open"})

                elif op == "get_ledger":
                    send_secure_json(conn, channel, {"ok": True, "ledger": state.accepted_ledger})

                else:
                    send_secure_json(conn, channel, {"ok": True, "msg": "request accepted and logged"})

            elif msg_type == "vault-share":
                # Milestone 2: Vault opening share with Chaum-Pedersen proof
                if not authenticated:
                    send_secure_json(conn, channel, {"ok": False, "error": "Authentication required"})
                    continue
                member_idx = int(req["member_index"])
                d_i = int(req["d_i"], 16)
                T_1 = int(req["T_1"], 16)
                T_2 = int(req["T_2"], 16)
                z = int(req["z"], 16)
                c1 = int(vault_meta["c1"], 16)
                c2 = int(vault_meta["c2"], 16)
                h_i = compute_verification_key(member_idx, commitments, P, Q)

                proof_valid = verify_decryption_share(member_idx, c1, h_i, d_i, T_1, T_2, z, P, Q, G)

                if weak_mode == "no-proof":
                    # Skip proof verification in weak mode
                    state.vault_shares[member_idx] = d_i
                    logger.warning("WEAK MODE (--weak no-proof): accepted unverified decryption share from M%d", member_idx)
                    send_secure_json(conn, channel, {"ok": True, "msg": "Share accepted (weak mode)"})
                else:
                    if not proof_valid:
                        logger.warning("decryption share from M%d: d=%s proof FAILED, rejected",
                                       member_idx, format(d_i, "x")[:8])
                        send_secure_json(conn, channel, {"ok": False, "error": "proof FAILED, rejected"})
                        continue
                    state.vault_shares[member_idx] = d_i
                    logger.info("decryption share from M%d: d=%s proof OK, accepted",
                                member_idx, format(d_i, "x")[:8])
                    send_secure_json(conn, channel, {"ok": True, "msg": "Share accepted"})

                # Try opening vault if >= t shares
                if len(state.vault_shares) >= state.t and not state.vault_opened:
                    try:
                        selected_shares = dict(list(state.vault_shares.items())[:state.t])
                        decrypted_bytes = decrypt_vault_file(c1, c2, enc_vault_bytes, selected_shares, P, Q)
                        state.vault_opened = True
                        state.vault_content = decrypted_bytes.decode("utf-8", errors="replace")
                        logger.info("Treasury vault OPENED successfully using shares %s: %s",
                                    list(selected_shares.keys()), state.vault_content)
                    except Exception as exc:
                        logger.error("Failed to decrypt vault with shares %s: %s", list(state.vault_shares.keys()), exc)

            elif msg_type == "ballot":
                # Milestone 3: Encrypted ballot
                if not authenticated:
                    send_secure_json(conn, channel, {"ok": False, "error": "Authentication required"})
                    continue
                vote_num = req.get("vote_number")
                if vote_num not in state.proposals:
                    send_secure_json(conn, channel, {"ok": False, "error": f"Vote #{vote_num} not found"})
                    continue

                ballot_data = {
                    "member_name": member_name,
                    "vote_number": vote_num,
                    "c1": req.get("c1"),
                    "c2": req.get("c2"),
                    "sig": req.get("sig"),
                }

                if weak_mode == "unsigned-ballots":
                    logger.warning("WEAK MODE (--weak unsigned-ballots): accepting ballot without signature check")
                else:
                    if not verify_ballot(member_pub, ballot_data, GROUP):
                        logger.warning("ballot from %s signature FAILED, rejected", member_name)
                        send_secure_json(conn, channel, {"ok": False, "error": "Ballot signature invalid"})
                        continue

                # Check duplicate ballot
                if member_name in state.ballots[vote_num]:
                    logger.warning("Duplicate ballot from %s for vote #%d rejected", member_name, vote_num)
                    send_secure_json(conn, channel, {"ok": False, "error": "Duplicate ballot rejected"})
                    continue

                state.ballots[vote_num][member_name] = ballot_data
                logger.info("Ballot accepted from %s for vote #%d (total ballots: %d/%d)",
                            member_name, vote_num, len(state.ballots[vote_num]), state.n)
                send_secure_json(conn, channel, {"ok": True, "msg": "Ballot recorded"})

            elif msg_type == "tally-share":
                # Milestone 3: Decryption share for the homomorphic tally
                if not authenticated:
                    send_secure_json(conn, channel, {"ok": False, "error": "Authentication required"})
                    continue
                vote_num = req.get("vote_number")
                member_idx = int(req.get("member_index"))
                d_i = int(req.get("d_i"), 16)
                T_1 = int(req.get("T_1"), 16)
                T_2 = int(req.get("T_2"), 16)
                z = int(req.get("z"), 16)

                ballots_list = list(state.ballots.get(vote_num, {}).values())
                if not ballots_list:
                    send_secure_json(conn, channel, {"ok": False, "error": "No ballots for this vote"})
                    continue

                C1, C2 = aggregate_ballots(ballots_list, P)
                h_i = compute_verification_key(member_idx, commitments, P, Q)

                if weak_mode == "no-proof":
                    state.tally_shares[vote_num][member_idx] = d_i
                    send_secure_json(conn, channel, {"ok": True, "msg": "Tally share accepted (weak mode)"})
                else:
                    if not verify_decryption_share(member_idx, C1, h_i, d_i, T_1, T_2, z, P, Q, G):
                        logger.warning("tally share from M%d proof FAILED, rejected", member_idx)
                        send_secure_json(conn, channel, {"ok": False, "error": "proof FAILED"})
                        continue
                    state.tally_shares[vote_num][member_idx] = d_i
                    logger.info("tally share from M%d proof OK, accepted", member_idx)
                    send_secure_json(conn, channel, {"ok": True, "msg": "Tally share accepted"})

                # Decrypt tally when >= t shares
                if len(state.tally_shares[vote_num]) >= state.t and vote_num not in state.voting_results:
                    selected_shares = dict(list(state.tally_shares[vote_num].items())[:state.t])
                    try:
                        yes_votes = decrypt_tally(C1, C2, selected_shares, max_votes=len(ballots_list), p=P, q=Q, g=G)
                        no_votes = len(ballots_list) - yes_votes
                        approved = check_spending_approval(yes_votes, threshold=state.t)
                        state.voting_results[vote_num] = {
                            "vote_number": vote_num,
                            "yes_votes": yes_votes,
                            "no_votes": no_votes,
                            "approved": approved,
                        }
                        logger.info("Vote #%d complete: YES=%d, NO=%d. Decision: %s",
                                    vote_num, yes_votes, no_votes, "APPROVED" if approved else "REJECTED")
                    except Exception as exc:
                        logger.error("Failed to decrypt tally for vote #%d: %s", vote_num, exc)

            elif msg_type == "get_vote_result":
                vote_num = req.get("vote_number")
                res = state.voting_results.get(vote_num)
                send_secure_json(conn, channel, {"ok": True, "result": res})

            else:
                send_secure_json(conn, channel, {"ok": False, "error": f"Unknown message type {msg_type}"})

    except Exception as exc:
        logger.exception("Connection from %s (%s) encountered error: %s", addr, member_name, exc)
    finally:
        conn.close()
        logger.info("Connection closed for %s (%s)", addr, member_name)


def main():
    parser = argparse.ArgumentParser(description="Treasury Server")
    parser.add_argument("--name", default="server")
    parser.add_argument("--host", default=HOST)
    parser.add_argument("--port", type=int, default=SERVER_PORT)
    parser.add_argument("--weak", choices=sorted(WEAKNESS_NAMES), default=None)
    args = parser.parse_args()
    validate_group()
    logger = get_logger(args.name)

    founder_pub, server_priv, server_cert, commitments, t, n, vault_meta, enc_vault_bytes = load_server_credentials()
    state = TreasuryServerState(t=t, n=n)

    if args.weak:
        logger.warning("RUNNING IN WEAK MODE: --weak %s", args.weak)
    else:
        logger.info("RUNNING IN SECURE MODE")

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((args.host, args.port))
    server_sock.listen()
    logger.info("Treasury server listening on %s:%d", args.host, args.port)

    import threading
    while True:
        try:
            conn, addr = server_sock.accept()
            conn.settimeout(SOCKET_TIMEOUT_SECONDS)
            t_thread = threading.Thread(
                target=handle_client_connection,
                args=(conn, addr, state, founder_pub, server_priv, server_cert,
                      commitments, vault_meta, enc_vault_bytes, args.weak, logger),
                daemon=True,
            )
            t_thread.start()
        except KeyboardInterrupt:
            logger.info("Shutting down server.")
            break
        except Exception as exc:
            logger.error("Error accepting connection: %s", exc)


if __name__ == "__main__":
    main()
