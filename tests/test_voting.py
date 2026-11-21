"""Essam's automated tests for Milestone 3: Private Voting and Bonus Attack A7."""
import secrets
import unittest
from treasury.certificates import generate_p256_keypair
from treasury.config import G, GROUP, P, Q
from treasury.sharing import (
    make_shares,
    make_commitments,
    compute_verification_key,
)
from treasury.opening import make_decryption_share
from treasury.voting import (
    create_proposal,
    encrypt_vote,
    sign_ballot,
    verify_ballot,
    aggregate_ballots,
    decrypt_tally,
    check_spending_approval,
    tamper_ballot_a7,
)


class VotingTests(unittest.TestCase):
    def setUp(self):
        self.t = 3
        self.n = 5
        self.s = secrets.randbelow(Q - 1) + 1
        self.coeffs, self.shares = make_shares(self.s, self.t, self.n, Q)
        self.commitments = make_commitments(self.coeffs, P, G)
        self.h = self.commitments[0]
        self.vkeys = [compute_verification_key(i, self.commitments, P, Q) for i in range(1, self.n + 1)]

        # Generate keys for 5 members
        self.members = {}
        for i in range(1, self.n + 1):
            name = f"M{i}"
            priv, pub = generate_p256_keypair()
            self.members[name] = {
                "index": i,
                "priv": priv,
                "pub": pub,
                "share": self.shares[i - 1],
                "vkey": self.vkeys[i - 1],
            }

    def test_signed_proposal_and_unique_vote_identifier(self):
        proposal = create_proposal(vote_number=1, proposer="M1", amount=500, reason="Treasury security audit")
        self.assertEqual(proposal.vote_number, 1)
        self.assertEqual(proposal.amount, 500)
        self.assertEqual(proposal.proposer, "M1")

    def test_encrypted_ballot_and_signature_verification(self):
        m1 = self.members["M1"]
        vote = 1  # YES
        c1, c2 = encrypt_vote(vote, self.h, P, Q, G)
        sig = sign_ballot(m1["priv"], GROUP, "M1", 1, c1, c2)

        ballot = {
            "member_name": "M1",
            "vote_number": 1,
            "c1": format(c1, "x"),
            "c2": format(c2, "x"),
            "sig": sig,
        }

        self.assertTrue(verify_ballot(m1["pub"], ballot, GROUP))

        # Tampered vote c2 must fail signature verification
        bad_ballot = dict(ballot)
        bad_ballot["c2"] = format((c2 * 2) % P, "x")
        self.assertFalse(verify_ballot(m1["pub"], bad_ballot, GROUP))

    def test_homomorphic_tally_and_spending_approval(self):
        # Votes: M1=1, M2=1, M3=0, M4=1, M5=0 -> Total YES = 3 (passes!)
        raw_votes = {"M1": 1, "M2": 1, "M3": 0, "M4": 1, "M5": 0}
        ballots = []
        for name, vote in raw_votes.items():
            m = self.members[name]
            c1, c2 = encrypt_vote(vote, self.h, P, Q, G)
            sig = sign_ballot(m["priv"], GROUP, name, 1, c1, c2)
            ballots.append({
                "member_name": name,
                "vote_number": 1,
                "c1": format(c1, "x"),
                "c2": format(c2, "x"),
                "sig": sig,
            })

        # Server aggregates ballots homomorphically without opening individual votes
        C1, C2 = aggregate_ballots(ballots, P)

        # 3 members (e.g. M1, M3, M5) open the tally with threshold decryption
        participants = ["M1", "M3", "M5"]
        shares_dict = {}
        for name in participants:
            m = self.members[name]
            d_obj = make_decryption_share(m["share"], m["index"], C1, m["vkey"], P, Q, G)
            shares_dict[m["index"]] = d_obj["d_i"]

        recovered_yes = decrypt_tally(C1, C2, shares_dict, max_votes=self.n, p=P, q=Q, g=G)
        self.assertEqual(recovered_yes, 3)
        self.assertTrue(check_spending_approval(recovered_yes, threshold=3))

    def test_spending_rejection_when_under_threshold(self):
        # Votes: M1=1, M2=0, M3=0, M4=1, M5=0 -> Total YES = 2 (< 3, rejected)
        raw_votes = {"M1": 1, "M2": 0, "M3": 0, "M4": 1, "M5": 0}
        ballots = []
        for name, vote in raw_votes.items():
            m = self.members[name]
            c1, c2 = encrypt_vote(vote, self.h, P, Q, G)
            sig = sign_ballot(m["priv"], GROUP, name, 2, c1, c2)
            ballots.append({
                "member_name": name,
                "vote_number": 2,
                "c1": format(c1, "x"),
                "c2": format(c2, "x"),
                "sig": sig,
            })

        C1, C2 = aggregate_ballots(ballots, P)
        shares_dict = {}
        for name in ["M2", "M4", "M5"]:
            m = self.members[name]
            d_obj = make_decryption_share(m["share"], m["index"], C1, m["vkey"], P, Q, G)
            shares_dict[m["index"]] = d_obj["d_i"]

        recovered_yes = decrypt_tally(C1, C2, shares_dict, max_votes=self.n, p=P, q=Q, g=G)
        self.assertEqual(recovered_yes, 2)
        self.assertFalse(check_spending_approval(recovered_yes, threshold=3))

    def test_bonus_attack_a7_demonstration(self):
        # Member M3 votes NO (0)
        m3 = self.members["M3"]
        c1, c2 = encrypt_vote(0, self.h, P, Q, G)
        sig = sign_ballot(m3["priv"], GROUP, "M3", 3, c1, c2)
        ballot = {
            "member_name": "M3",
            "vote_number": 3,
            "c1": format(c1, "x"),
            "c2": format(c2, "x"),
            "sig": sig,
        }

        # Mallory performs attack A7: multiplies c2 by g mod p
        tampered_ballot = tamper_ballot_a7(ballot, P, G)

        # 1. In secure mode: signature check catches the tampering and rejects it!
        self.assertFalse(verify_ballot(m3["pub"], tampered_ballot, GROUP))

        # 2. In weak mode (--weak unsigned-ballots): signatures are not enforced.
        # Mallory's tampered ballot changes a NO vote into a YES vote!
        ballots = [tampered_ballot]
        C1, C2 = aggregate_ballots(ballots, P)

        shares_dict = {}
        for name in ["M1", "M2", "M3"]:
            m = self.members[name]
            d_obj = make_decryption_share(m["share"], m["index"], C1, m["vkey"], P, Q, G)
            shares_dict[m["index"]] = d_obj["d_i"]

        tally_result = decrypt_tally(C1, C2, shares_dict, max_votes=1, p=P, q=Q, g=G)
        # Because Mallory multiplied by g, the tally is 1 (YES) instead of 0 (NO)!
        self.assertEqual(tally_result, 1)


if __name__ == "__main__":
    unittest.main()
