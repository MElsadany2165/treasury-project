import secrets
import unittest
from treasury.config import G, P, Q
from treasury.login import (
    register_login_secret,
    make_interactive_commitment,
    make_interactive_response,
    verify_interactive_login,
    make_noninteractive_response,
    verify_noninteractive_login,
)


class LoginTests(unittest.TestCase):
    def test_interactive_login_success(self):
        x_M, X_M = register_login_secret("M1")
        k, R = make_interactive_commitment()
        challenge = secrets.randbits(128)
        z = make_interactive_response(x_M, k, challenge)
        self.assertTrue(verify_interactive_login(R, z, challenge, X_M))

    def test_interactive_login_wrong_secret(self):
        x_M, X_M = register_login_secret("M1")
        wrong_x, _ = register_login_secret("M2")
        k, R = make_interactive_commitment()
        challenge = secrets.randbits(128)
        z = make_interactive_response(wrong_x, k, challenge)
        self.assertFalse(verify_interactive_login(R, z, challenge, X_M))

    def test_noninteractive_login_success(self):
        x_M, X_M = register_login_secret("M1")
        nonce_N = secrets.randbits(128)
        R, z = make_noninteractive_response("M1", x_M, X_M, nonce_N)
        self.assertTrue(verify_noninteractive_login("M1", R, z, nonce_N, X_M))

    def test_noninteractive_login_tampered_name_or_nonce(self):
        x_M, X_M = register_login_secret("M1")
        nonce_N = secrets.randbits(128)
        R, z = make_noninteractive_response("M1", x_M, X_M, nonce_N)
        self.assertFalse(verify_noninteractive_login("M2", R, z, nonce_N, X_M))
        self.assertFalse(verify_noninteractive_login("M1", R, z, nonce_N + 1, X_M))


if __name__ == "__main__":
    unittest.main()
