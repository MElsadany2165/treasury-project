import unittest
from cryptography.hazmat.primitives.asymmetric import ec
from treasury.channel import (
    generate_p256_keypair,
    public_key_to_point_hex,
    public_key_from_point_hex,
    derive_directional_keys,
    sign_handshake_step,
    verify_handshake_step,
    SecureChannel,
)
from treasury.framing import ProtocolError


class ChannelTests(unittest.TestCase):
    def test_ecdh_key_derivation_agreement(self):
        m_priv, m_pub = generate_p256_keypair()
        s_priv, s_pub = generate_p256_keypair()

        X_hex = public_key_to_point_hex(m_pub)
        Y_hex = public_key_to_point_hex(s_pub)

        s_pub_from_m = public_key_from_point_hex(Y_hex)
        m_pub_from_s = public_key_from_point_hex(X_hex)

        ss_member = m_priv.exchange(ec.ECDH(), s_pub_from_m)
        ss_server = s_priv.exchange(ec.ECDH(), m_pub_from_s)

        self.assertEqual(ss_member, ss_server)

        m2s_1, s2m_1 = derive_directional_keys(ss_member, "M1", X_hex, Y_hex)
        m2s_2, s2m_2 = derive_directional_keys(ss_server, "M1", X_hex, Y_hex)

        self.assertEqual(m2s_1, m2s_2)
        self.assertEqual(s2m_1, s2m_2)
        self.assertNotEqual(m2s_1, s2m_1)

    def test_handshake_signatures(self):
        s_priv, s_pub = generate_p256_keypair()
        m_priv, m_pub = generate_p256_keypair()
        X_hex = public_key_to_point_hex(m_pub)
        Y_hex = public_key_to_point_hex(s_pub)

        sig_server = sign_handshake_step(s_priv, "hs-server", "M1", X_hex, Y_hex)
        self.assertTrue(verify_handshake_step(s_pub, sig_server, "hs-server", "M1", X_hex, Y_hex))
        self.assertFalse(verify_handshake_step(s_pub, sig_server, "hs-server", "M2", X_hex, Y_hex))

        sig_member = sign_handshake_step(m_priv, "hs-member", "M1", X_hex, Y_hex)
        self.assertTrue(verify_handshake_step(m_pub, sig_member, "hs-member", "M1", X_hex, Y_hex))

    def test_secure_channel_encryption_and_counter(self):
        k1 = b"A" * 32
        k2 = b"B" * 32
        sender_channel = SecureChannel(k1, k2)
        receiver_channel = SecureChannel(k2, k1)

        msg1 = b"First message"
        frame1 = sender_channel.encrypt(msg1)
        self.assertEqual(receiver_channel.decrypt(frame1), msg1)

        msg2 = b"Second message"
        frame2 = sender_channel.encrypt(msg2)
        self.assertEqual(receiver_channel.decrypt(frame2), msg2)

    def test_secure_channel_detects_replay(self):
        k1 = b"A" * 32
        k2 = b"B" * 32
        sender_channel = SecureChannel(k1, k2)
        receiver_channel = SecureChannel(k2, k1)

        frame1 = sender_channel.encrypt(b"Hello")
        receiver_channel.decrypt(frame1)

        # Replaying frame1 should fail due to counter check
        with self.assertRaises(ProtocolError):
            receiver_channel.decrypt(frame1)

    def test_secure_channel_detects_tamper(self):
        k1 = b"A" * 32
        k2 = b"B" * 32
        sender_channel = SecureChannel(k1, k2)
        receiver_channel = SecureChannel(k2, k1)

        frame = sender_channel.encrypt(b"Secret data")
        tampered = bytearray(frame)
        tampered[-1] ^= 0x01  # Flip one bit in AES-GCM tag/ciphertext
        with self.assertRaises(ProtocolError):
            receiver_channel.decrypt(bytes(tampered))


if __name__ == "__main__":
    unittest.main()
