import hashlib
import time
import random
from typing import Optional, Callable
from .abstract import KeylessCryptoPrimitive

class ProofOfWorkPrimitive(KeylessCryptoPrimitive):
    """
    Simple Proof-of-Work that searches for a nonce such that:
    SHA256(challenge + nonce) has at least difficulty_bits leading zeros in binary.
    """

    def __init__(self, difficulty_bits=28):
        """
        difficulty_bits defines how many leading zero bits are required.
        For example, difficulty_bits=28 => requires ~1 in 2^(28) solution.
        """
        self.difficulty_bits = difficulty_bits

    def create_proof(self, challenge: str, interrupt_callback: Optional[Callable[[], bool]] = None, debug: bool = False) -> int:
        """
        Create a proof (nonce) by brute-forcing a hash with required leading zeros (in bits).
        
        Args:
            challenge: The challenge string to hash with the nonce
            interrupt_callback: Optional callback that returns True if mining should be interrupted
        
        Returns:
            int: The nonce that satisfies the proof of work, or -1 if interrupted
        """
        if debug:
            print(f"Mining with difficulty_bits: {self.difficulty_bits}")
        target = 2**(256 - self.difficulty_bits)

        nonce = 0
        while True:
            # Check if we should interrupt mining
            if interrupt_callback and nonce % 10000 == 0 and interrupt_callback():
                return -1  # Signal interrupted mining
                
            test_str = challenge + str(nonce)
            hash_bytes = hashlib.sha256(test_str.encode()).digest()
            # Convert hash bytes to integer
            hash_int = int.from_bytes(hash_bytes, byteorder='big')
            
            # Check if hash_int is less than target (equivalent to having required leading zeros)
            if hash_int < target:
                return nonce
                
            nonce += 1

    def verify_proof(self, challenge: str, nonce: int) -> bool:
        """
        Verify if hashing challenge + nonce meets the difficulty requirement.
        
        Args:
            challenge: The challenge string
            nonce: The nonce to verify
            
        Returns:
            bool: True if the nonce is valid, False otherwise
        """
        # Check for interrupt signal
        if nonce == -1:
            return False
        
        # Calculate hash    
        hash_bytes = hashlib.sha256((challenge + str(nonce)).encode()).digest()
        # Convert hash to integer
        hash_int = int.from_bytes(hash_bytes, byteorder='big')
        
        # Calculate target based on difficulty
        target = 2**(256 - self.difficulty_bits)
        
        # Check if hash is less than target
        return hash_int < target