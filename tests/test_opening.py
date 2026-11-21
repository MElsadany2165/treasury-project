import secrets
import unittest
from treasury.config import G, P, Q
from treasury.sharing import (
    make_shares,
    make_commitments,
    compute_verification_key,
)
from treasury.opening import (
    encrypt_vault_file,
    make_decryption_share,
    verify_decryption_share,
    combine_decryption_shares,
    decrypt_vault_file,
)


class OpeningTests(unittest.TestCase):
    def setUp(self):
        self.t = 3
        self.n = 5
        self.s = secrets.randbelow(Q - 1) + 1
        self.coeffs, self.shares = make_shares(self.s, self.t, self.n, Q)
        self.commitments = make_commitments(self.coeffs, P, G)
        self.h = self.commitments[0]
        self.vkeys = [compute_verification_key(i, self.commitments, P, Q) for i in range(1, self.n + 1)]

    def test_vault_file_encryption_and_threshold_opening(self):
        secret_file = b"Top secret treasury treasure: 1,000,000 gold coins!"
        c1, c2, enc_vault = encrypt_vault_file(secret_file, self.h, P, Q, G)

        # Members M1, M3, M5 produce decryption shares
        participants = [1, 3, 5]
        shares_dict = {}
        for i in participants:
            share = self.shares[i - 1]
            h_i = self.vkeys[i - 1]
            d_obj = make_decryption_share(share, i, c1, h_i, P, Q, G)
            self.assertTrue(verify_decryption_share(
                i, c1, h_i, d_obj["d_i"], d_obj["T_1"], d_obj["T_2"], d_obj["z"], P, Q, G
            ))
            shares_dict[i] = d_obj["d_i"]

        decrypted = decrypt_vault_file(c1, c2, enc_vault, shares_dict, P, Q)
        self.assertEqual(decrypted, secret_file)

    def test_vault_alternative_threshold_combination(self):
        # Members M2, M4, M5 should also successfully decrypt the exact same file
        secret_file = b"Top secret treasury treasure: 1,000,000 gold coins!"
        c1, c2, enc_vault = encrypt_vault_file(secret_file, self.h, P, Q, G)

        participants = [2, 4, 5]
        shares_dict = {}
        for i in participants:
            share = self.shares[i - 1]
            h_i = self.vkeys[i - 1]
            d_obj = make_decryption_share(share, i, c1, h_i, P, Q, G)
            shares_dict[i] = d_obj["d_i"]

        decrypted = decrypt_vault_file(c1, c2, enc_vault, shares_dict, P, Q)
        self.assertEqual(decrypted, secret_file)

    def test_invalid_proof_rejected(self):
        c1, c2, enc_vault = encrypt_vault_file(b"test", self.h, P, Q, G)
        share = self.shares[0]
        h_1 = self.vkeys[0]
        d_obj = make_decryption_share(share, 1, c1, h_1, P, Q, G)
        # Corrupt z
        bad_z = (d_obj["z"] + 1) % Q
        self.assertFalse(verify_decryption_share(
            1, c1, h_1, d_obj["d_i"], d_obj["T_1"], d_obj["T_2"], bad_z, P, Q, G
        ))


if __name__ == "__main__":
    unittest.main()
