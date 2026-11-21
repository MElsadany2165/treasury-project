import secrets
import unittest
from treasury.config import G, P, Q
from treasury.sharing import (
    evaluate_polynomial,
    make_shares,
    make_commitments,
    compute_verification_key,
    verify_share,
    lagrange_coefficient,
)


class SharingTests(unittest.TestCase):
    def test_polynomial_evaluation(self):
        # f(x) = 5 + 3x + 2x^2 mod 17
        coeffs = [5, 3, 2]
        q = 17
        # f(1) = 5 + 3 + 2 = 10
        self.assertEqual(evaluate_polynomial(coeffs, 1, q), 10)
        # f(2) = 5 + 6 + 8 = 19 = 2 mod 17
        self.assertEqual(evaluate_polynomial(coeffs, 2, q), 2)

    def test_sharing_and_commitment_verification(self):
        secret = secrets.randbelow(Q - 1) + 1
        t = 3
        n = 5
        coeffs, shares = make_shares(secret, t, n, Q)
        commitments = make_commitments(coeffs, P, G)

        for i, share in enumerate(shares, start=1):
            self.assertTrue(verify_share(share, i, commitments, P, Q, G))

        # Tampered share fails verification
        self.assertFalse(verify_share((shares[0] + 1) % Q, 1, commitments, P, Q, G))

    def test_lagrange_reconstruction_at_zero(self):
        secret = secrets.randbelow(Q - 1) + 1
        t = 3
        n = 5
        coeffs, shares = make_shares(secret, t, n, Q)

        # Reconstruct secret with any 3 shares: e.g. indices 1, 3, 5
        selected = [1, 3, 5]
        recovered = 0
        for idx in selected:
            lam = lagrange_coefficient(idx, selected, Q)
            recovered = (recovered + shares[idx - 1] * lam) % Q

        self.assertEqual(recovered, secret % Q)


if __name__ == "__main__":
    unittest.main()
