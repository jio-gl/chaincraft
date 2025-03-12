# tests/test_crypto_primitives.py

import unittest
import time
import hashlib

from crypto_primitives.pow import ProofOfWorkPrimitive
from crypto_primitives.vdf import VDFPrimitive
from crypto_primitives.ecdsa_sign import ECDSASignaturePrimitive
from crypto_primitives.vrf import ECDSAVRFPrimitive

class TestCryptoPrimitives(unittest.TestCase):

    def test_pow(self):
        pow_primitive = ProofOfWorkPrimitive(difficulty_bits=12)  # smaller difficulty for test
        challenge = "HelloWorld"
        nonce = pow_primitive.create_proof(challenge)
        # Check proof
        self.assertTrue(pow_primitive.verify_proof(challenge, nonce))

    def test_vdf(self):
        # Use fewer iterations for testing speed
        vdf_primitive = VDFPrimitive(iterations=1000)
        input_data = "TestVDF"
        
        # Measure time for proof generation
        start_time = time.time()
        proof = vdf_primitive.create_proof(input_data)
        proof_time = time.time() - start_time
        
        # Measure time for verification
        start_time = time.time()
        verification_result = vdf_primitive.verify_proof(input_data, proof)
        verify_time = time.time() - start_time
        
        # Verification should be successful
        self.assertTrue(verification_result)
        
        # Verification should be significantly faster than proof generation
        # Typically at least 10x faster, but we'll use 2x as a conservative test bound
        print(f"VDF proof generation time: {proof_time:.4f}s")
        print(f"VDF verification time: {verify_time:.4f}s")
        print(f"Speedup factor: {proof_time/verify_time:.2f}x")
        self.assertGreater(proof_time / verify_time, 2)
        
        # Test with incorrect proof
        incorrect_proof = proof + 1
        self.assertFalse(vdf_primitive.verify_proof(input_data, incorrect_proof))

    def test_ecdsa_sign(self):
        ecdsa_primitive = ECDSASignaturePrimitive()
        ecdsa_primitive.generate_key()

        message = b"Hello ECDSA"
        sig = ecdsa_primitive.sign(message)
        self.assertTrue(ecdsa_primitive.verify(message, sig))

        # Negative check
        wrong_message = b"Goodbye ECDSA"
        self.assertFalse(ecdsa_primitive.verify(wrong_message, sig))

    def test_ecdsa_vrf(self):
        vrf_primitive = ECDSAVRFPrimitive()
        vrf_primitive.generate_key()

        message = b"Hello VRF"
        proof = vrf_primitive.sign(message)

        # Verify proof
        self.assertTrue(vrf_primitive.verify(message, proof))
        
        # Get VRF output
        vrf_out = vrf_primitive.vrf_output(message, proof)
        self.assertEqual(len(vrf_out), 32)  # 32 bytes = 256-bit hash

        # Negative check
        wrong_message = b"Attack VRF"
        self.assertFalse(vrf_primitive.verify(wrong_message, proof))

if __name__ == "__main__":
    unittest.main()