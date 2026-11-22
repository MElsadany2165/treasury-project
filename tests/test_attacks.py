"""Automated attack tests for mandatory A1, A5, and bonus A7."""
import secrets
import unittest
from cryptography.hazmat.primitives.asymmetric import ec
from treasury.certificates import generate_p256_keypair, create_certificate, verify_certificate
from treasury.channel import (
    public_key_to_point_hex,
    public_key_from_point_hex,
    derive_directional_keys,
    sign_handshake_step,
    verify_handshake_step,
    SecureChannel,
)
from treasury.config import G, GROUP, P, Q
from treasury.opening import (
    encrypt_vault_file,
    make_decryption_share,
    verify_decryption_share,
    decrypt_vault_file,
)
from treasury.requests import sign_request, verify_request
from treasury.sharing import (
    make_shares,
    make_commitments,
    compute_verification_key,
)
from treasury.voting import (
    encrypt_vote,
    sign_ballot,
    verify_ballot,
    aggregate_ballots,
    decrypt_tally,
    tamper_ballot_a7,
)


class AttacksTestSuite(unittest.TestCase):
    def test_a1_mitm_attack_weak_vs_secure(self):
        # Long-term keys
        founder_priv, founder_pub = generate_p256_keypair()
        server_priv, server_pub = generate_p256_keypair()
        m1_priv, m1_pub = generate_p256_keypair()
        mallory_priv, mallory_pub = generate_p256_keypair()

        # Ephemeral keys
        m1_eph_priv, m1_eph_pub = generate_p256_keypair()
        mal_eph1_priv, mal_eph1_pub = generate_p256_keypair()
        mal_eph2_priv, mal_eph2_pub = generate_p256_keypair()
        srv_eph_priv, srv_eph_pub = generate_p256_keypair()

        X_m1 = public_key_to_point_hex(m1_eph_pub)
        X_mal = public_key_to_point_hex(mal_eph2_pub)
        Y_srv = public_key_to_point_hex(srv_eph_pub)
        Y_mal = public_key_to_point_hex(mal_eph1_pub)

        # 1. SECURE MODE: Mallory cannot forge server's signature on (X_m1, Y_mal)
        # Server only signs (X_mal, Y_srv)
        server_sig_on_server_side = sign_handshake_step(server_priv, "hs-server", "M1", X_mal, Y_srv)
        # When M1 checks server signature for M1's session (X_m1, Y_mal), it must fail!
        self.assertFalse(verify_handshake_step(server_pub, server_sig_on_server_side, "hs-server", "M1", X_m1, Y_mal))

        # 2. WEAK MODE (--weak unsigned-handshake):
        # Handshake signatures are omitted. Mallory intercepts and completes 2 separate handshakes:
        # Handshake 1: M1 <-> Mallory
        ss_m1_mal = m1_eph_priv.exchange(ec.ECDH(), mal_eph1_pub)
        m1_to_mal_key, mal_to_m1_key = derive_directional_keys(ss_m1_mal, "M1", X_m1, Y_mal)

        # Handshake 2: Mallory <-> Server
        ss_mal_srv = mal_eph2_priv.exchange(ec.ECDH(), srv_eph_pub)
        mal_to_srv_key, srv_to_mal_key = derive_directional_keys(ss_mal_srv, "M1", X_mal, Y_srv)

        m1_channel = SecureChannel(m1_to_mal_key, mal_to_m1_key)
        mal_channel_m1 = SecureChannel(mal_to_m1_key, m1_to_mal_key)

        # M1 sends an encrypted request
        plain_req = sign_request(m1_priv, GROUP, "M1", 1, "spend", {"amount": 100, "reason": "supplies"})
        frame_from_m1 = m1_channel.encrypt(b"M1_LOGIN_SECRET_DATA")

        # Mallory can decrypt and read everything in clear!
        intercepted_cleartext = mal_channel_m1.decrypt(frame_from_m1)
        self.assertEqual(intercepted_cleartext, b"M1_LOGIN_SECRET_DATA")

        # But if Mallory tries to modify the signed request body, the server rejects it
        tampered_req = dict(plain_req)
        tampered_req["body"] = {"amount": 1000000, "reason": "mallory heist"}
        self.assertFalse(verify_request(m1_pub, tampered_req, last_sequence=0, name="M1"))

    def test_a5_cheating_member_weak_vs_secure(self):
        secret = secrets.randbelow(Q - 1) + 1
        t = 3
        n = 5
        coeffs, shares = make_shares(secret, t, n, Q)
        commitments = make_commitments(coeffs, P, G)
        h = commitments[0]
        vkeys = [compute_verification_key(i, commitments, P, Q) for i in range(1, n + 1)]

        secret_vault = b"Treasury reserves: 50,000 USD"
        c1, c2, enc_vault = encrypt_vault_file(secret_vault, h, P, Q, G)

        # M1, M2 provide honest shares
        d1_obj = make_decryption_share(shares[0], 1, c1, vkeys[0], P, Q, G)
        d2_obj = make_decryption_share(shares[1], 2, c1, vkeys[1], P, Q, G)

        # M3 cheats: sends d_3 * g mod p
        honest_d3 = pow(c1, shares[2], P)
        cheated_d3 = (honest_d3 * G) % P
        d3_obj = make_decryption_share(shares[2], 3, c1, vkeys[2], P, Q, G)

        # 1. SECURE MODE: Server verifies Chaum-Pedersen proof for M3's cheated share
        # Cheated share cannot pass the proof check with M3's verification key!
        is_m3_proof_valid = verify_decryption_share(
            3, c1, vkeys[2], cheated_d3, d3_obj["T_1"], d3_obj["T_2"], d3_obj["z"], P, Q, G
        )
        self.assertFalse(is_m3_proof_valid)

        # Server rejects M3 and opens the vault with another member (e.g. M4)
        d4_obj = make_decryption_share(shares[3], 4, c1, vkeys[3], P, Q, G)
        self.assertTrue(verify_decryption_share(
            4, c1, vkeys[3], d4_obj["d_i"], d4_obj["T_1"], d4_obj["T_2"], d4_obj["z"], P, Q, G
        ))
        shares_dict = {1: d1_obj["d_i"], 2: d2_obj["d_i"], 4: d4_obj["d_i"]}
        decrypted = decrypt_vault_file(c1, c2, enc_vault, shares_dict, P, Q)
        self.assertEqual(decrypted, secret_vault)

        # 2. WEAK MODE (--weak no-proof): Proof is skipped.
        # Server includes cheated d3. Decryption yields corrupted plaintext / fails AES-GCM tag!
        weak_shares_dict = {1: d1_obj["d_i"], 2: d2_obj["d_i"], 3: cheated_d3}
        with self.assertRaises(Exception):
            decrypt_vault_file(c1, c2, enc_vault, weak_shares_dict, P, Q)

    def test_a7_tampered_ballot_weak_vs_secure(self):
        secret = secrets.randbelow(Q - 1) + 1
        coeffs, shares = make_shares(secret, 3, 5, Q)
        commitments = make_commitments(coeffs, P, G)
        h = commitments[0]
        vkeys = [compute_verification_key(i, commitments, P, Q) for i in range(1, 6)]

        m_priv, m_pub = generate_p256_keypair()
        # Member votes NO (0)
        c1, c2 = encrypt_vote(0, h, P, Q, G)
        sig = sign_ballot(m_priv, GROUP, "M1", 1, c1, c2)
        ballot = {"member_name": "M1", "vote_number": 1, "c1": format(c1, "x"), "c2": format(c2, "x"), "sig": sig}

        # Mallory modifies c2 by multiplying by g
        tampered = tamper_ballot_a7(ballot, P, G)

        # SECURE MODE: Server rejects tampered ballot
        self.assertFalse(verify_ballot(m_pub, tampered, GROUP))

        # WEAK MODE (--weak unsigned-ballots): Unsigned ballots accepted
        # Decrypting tally of the tampered ballot recovers 1 instead of 0
        C1, C2 = aggregate_ballots([tampered], P)
        shares_dict = {}
        for i in [1, 2, 3]:
            d_obj = make_decryption_share(shares[i - 1], i, C1, vkeys[i - 1], P, Q, G)
            shares_dict[i] = d_obj["d_i"]
        tally = decrypt_tally(C1, C2, shares_dict, max_votes=1, p=P, q=Q, g=G)
        self.assertEqual(tally, 1)


if __name__ == "__main__":
    unittest.main()
