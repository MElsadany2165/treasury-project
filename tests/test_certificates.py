import unittest
from treasury.certificates import (
    generate_p256_keypair,
    public_key_to_pem,
    public_key_from_pem,
    create_certificate,
    verify_certificate,
)
from treasury.config import GROUP


class CertificateTests(unittest.TestCase):
    def setUp(self):
        self.founder_priv, self.founder_pub = generate_p256_keypair()
        self.m1_priv, self.m1_pub = generate_p256_keypair()
        self.m1_pem = public_key_to_pem(self.m1_pub)

    def test_valid_certificate(self):
        cert = create_certificate(self.founder_priv, "M1", self.m1_pem, "2026-12-31")
        self.assertTrue(verify_certificate(cert.to_dict(), self.founder_pub, "M1"))

    def test_invalid_founder_signature(self):
        other_founder_priv, _ = generate_p256_keypair()
        cert = create_certificate(other_founder_priv, "M1", self.m1_pem, "2026-12-31")
        self.assertFalse(verify_certificate(cert.to_dict(), self.founder_pub, "M1"))

    def test_wrong_name(self):
        cert = create_certificate(self.founder_priv, "M1", self.m1_pem, "2026-12-31")
        self.assertFalse(verify_certificate(cert.to_dict(), self.founder_pub, "M2"))

    def test_wrong_group(self):
        cert = create_certificate(self.founder_priv, "M1", self.m1_pem, "2026-12-31")
        cert_dict = cert.to_dict()
        cert_dict["group"] = "wrong-group"
        self.assertFalse(verify_certificate(cert_dict, self.founder_pub, "M1"))

    def test_expired_certificate(self):
        cert = create_certificate(self.founder_priv, "M1", self.m1_pem, "2020-01-01")
        self.assertFalse(verify_certificate(cert.to_dict(), self.founder_pub, "M1"))


if __name__ == "__main__":
    unittest.main()
