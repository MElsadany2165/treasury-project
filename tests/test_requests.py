import unittest
from treasury.certificates import generate_p256_keypair
from treasury.config import GROUP
from treasury.requests import sign_request, verify_request


class RequestTests(unittest.TestCase):
    def setUp(self):
        self.priv, self.pub = generate_p256_keypair()

    def test_valid_signed_request(self):
        req = sign_request(self.priv, GROUP, "M1", 1, "spend", {"amount": 50, "reason": "pizza"})
        self.assertTrue(verify_request(self.pub, req, last_sequence=0, name="M1"))

    def test_reject_lower_or_equal_sequence(self):
        req = sign_request(self.priv, GROUP, "M1", 1, "spend", {"amount": 50, "reason": "pizza"})
        self.assertFalse(verify_request(self.pub, req, last_sequence=1, name="M1"))
        self.assertFalse(verify_request(self.pub, req, last_sequence=2, name="M1"))

    def test_reject_tampered_request(self):
        req = sign_request(self.priv, GROUP, "M1", 1, "spend", {"amount": 50, "reason": "pizza"})
        req["body"]["amount"] = 500  # Attacker changes amount
        self.assertFalse(verify_request(self.pub, req, last_sequence=0, name="M1"))


if __name__ == "__main__":
    unittest.main()
