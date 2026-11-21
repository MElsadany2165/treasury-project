"""Milestone 3 private encrypted voting system and bonus attack A7.

Owner: Essam — Private Voting and Bonus Attack
Milestone 3:
- Implement signed spending proposals.
- Create unique vote identifiers.
- Implement encrypted yes/no ballots with fresh randomness.
- Implement ballot ECDSA signatures and verification.
- Prevent duplicate ballots.
- Implement homomorphic ciphertext aggregation.
- Integrate the tally with Divan's threshold-decryption functionality.
- Recover the total number of yes votes without exposing individual votes.
- Implement spending approval when at least three members vote yes.
- Implement bonus attack A7: changing an unsigned encrypted ballot.
- Demonstrate the changed tally in weak mode and signature rejection in secure mode.
"""
import secrets
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from .config import G, GROUP, P, Q, validate_group_element
from .encoding import canonical_json
from .opening import combine_decryption_shares


@dataclass
class Proposal:
    vote_number: int
    proposer: str
    amount: int
    reason: str
    passed: bool | None = None
    yes_votes: int | None = None
    no_votes: int | None = None


def create_proposal(vote_number: int, proposer: str, amount: int, reason: str) -> Proposal:
    """Create a new spending proposal with unique vote identifier."""
    return Proposal(
        vote_number=vote_number,
        proposer=proposer,
        amount=amount,
        reason=reason,
    )


def encrypt_vote(vote: int, vault_public_key: int,
                 p: int = P, q: int = Q, g: int = G) -> tuple[int, int]:
    """ElGamal-style additive homomorphic encryption of vote v in {0, 1} under vault key h.
    
    Picks fresh randomness r in Z_q, computes:
    c1 = g^r mod p
    c2 = g^v * h^r mod p
    Returns (c1, c2).
    """
    if vote not in (0, 1):
        raise ValueError(f"Vote must be 0 (no) or 1 (yes), got {vote}")
    r = secrets.randbelow(q - 1) + 1
    c1 = pow(g, r, p)
    c2 = (pow(g, vote, p) * pow(vault_public_key, r, p)) % p
    return c1, c2


def ballot_transcript(group: str, member_name: str, vote_number: int,
                      c1: int, c2: int) -> list[Any]:
    """Canonical ballot transcript: ["ballot", group, member_name, vote_number, c1_hex, c2_hex]."""
    return ["ballot", group, member_name, vote_number, format(c1, "x"), format(c2, "x")]


def sign_ballot(member_private_key: ec.EllipticCurvePrivateKey,
                group: str, member_name: str, vote_number: int,
                c1: int, c2: int) -> str:
    """Sign ballot transcript using member's ECDSA key."""
    transcript = ballot_transcript(group, member_name, vote_number, c1, c2)
    sig = member_private_key.sign(canonical_json(transcript), ec.ECDSA(hashes.SHA256()))
    return sig.hex()


def verify_ballot(member_public_key: ec.EllipticCurvePublicKey,
                  ballot: dict[str, Any],
                  group: str = GROUP) -> bool:
    """Verify ballot structure, group membership of c1, c2, and member ECDSA signature."""
    if not isinstance(ballot, dict):
        return False
    member_name = ballot.get("member_name")
    vote_number = ballot.get("vote_number")
    c1_val = ballot.get("c1")
    c2_val = ballot.get("c2")
    sig_hex = ballot.get("sig")

    if not member_name or vote_number is None or c1_val is None or c2_val is None or not sig_hex:
        return False

    try:
        c1 = int(c1_val, 16) if isinstance(c1_val, str) else int(c1_val)
        c2 = int(c2_val, 16) if isinstance(c2_val, str) else int(c2_val)
    except (ValueError, TypeError):
        return False

    if not (validate_group_element(c1) and validate_group_element(c2)):
        return False

    transcript = ballot_transcript(group, member_name, vote_number, c1, c2)
    data = canonical_json(transcript)
    try:
        member_public_key.verify(bytes.fromhex(sig_hex), data, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError):
        return False


def aggregate_ballots(ballots: list[dict[str, Any]], p: int = P) -> tuple[int, int]:
    """Homomorphically combine encrypted ballots by modular multiplication:
    C_1 = product of c_1,k mod p
    C_2 = product of c_2,k mod p.
    Notice: C_1 = g^(sum r_k) and C_2 = g^(sum v_k) * h^(sum r_k).
    """
    if not ballots:
        raise ValueError("Cannot aggregate empty ballots list")
    
    C1 = 1
    C2 = 1
    for b in ballots:
        c1 = int(b["c1"], 16) if isinstance(b["c1"], str) else int(b["c1"])
        c2 = int(b["c2"], 16) if isinstance(b["c2"], str) else int(b["c2"])
        C1 = (C1 * c1) % p
        C2 = (C2 * c2) % p
    return C1, C2


def decrypt_tally(C1: int, C2: int,
                  decryption_shares: dict[int, int],
                  max_votes: int,
                  p: int = P, q: int = Q, g: int = G) -> int:
    """Threshold-decrypt aggregate ciphertext (C1, C2) and recover total yes votes T.
    
    Using Divan's threshold combination:
    D = product of (d_i ^ lambda_i) mod p = C1^s mod p = h^(sum r_k) mod p.
    m_tally = C2 * D^(-1) mod p = g^T mod p where T = sum(v_k).
    Recover T by discrete log search over 0, 1, ..., max_votes.
    """
    m_tally = combine_decryption_shares(decryption_shares, C2, p, q)
    for T in range(max_votes + 1):
        if pow(g, T, p) == m_tally:
            return T
    raise ValueError(f"Could not find discrete logarithm for tally (tested 0 to {max_votes})")


def check_spending_approval(yes_votes: int, threshold: int = 3) -> bool:
    """Spending proposal passes if at least threshold members vote yes."""
    return yes_votes >= threshold


def tamper_ballot_a7(ballot: dict[str, Any], p: int = P, g: int = G) -> dict[str, Any]:
    """Bonus Attack A7 (changed ballot):
    Mallory multiplies c2 by g mod p, flipping a 'no' ballot (g^0 * h^r = h^r)
    into a 'yes' ballot (g^1 * h^r).
    In weak mode (--weak unsigned-ballots), signature is absent/ignored and the
    attack succeeds, adding a fake yes vote.
    In secure mode, signature verification fails and the server rejects the ballot.
    """
    tampered = dict(ballot)
    orig_c2 = int(ballot["c2"], 16) if isinstance(ballot["c2"], str) else int(ballot["c2"])
    new_c2 = (orig_c2 * g) % p
    tampered["c2"] = format(new_c2, "x")
    return tampered
