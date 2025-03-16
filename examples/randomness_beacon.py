# examples/randomness_beacon.py

import json
import time
import hashlib
import random
from typing import List, Dict, Optional, Tuple, Any, Callable
import os
import secrets
import threading

from shared_object import SharedObject, SharedObjectException
from shared_message import SharedMessage
from chaincraft import ChaincraftNode
from crypto_primitives.pow import ProofOfWorkPrimitive


# Generate a random Ethereum-like address (20 bytes)
def generate_eth_address() -> str:
    address_bytes = secrets.token_bytes(20)
    return "0x" + address_bytes.hex()


class Block:
    """Represents a block in the randomness beacon chain"""
    
    def __init__(
        self,
        coinbase_address: str,
        prev_block_hash: str,
        block_height: int,
        timestamp: float,
        nonce: int
    ):
        self.coinbase_address = coinbase_address
        self.prev_block_hash = prev_block_hash
        self.block_height = block_height
        self.timestamp = timestamp
        self.nonce = nonce
        # Fixed difficulty of 13 bits
        self.difficulty_bits = RandomnessBeacon.DIFFICULTY_BITS
        # Calculate the hash after all attributes are set
        self.block_hash = self._calculate_hash()
    
    def _calculate_hash(self) -> str:
        """Calculate the hash of this block"""
        block_data = self.to_dict()
        # Remove the hash field itself before hashing
        if 'block_hash' in block_data:
            del block_data['block_hash']
        block_str = json.dumps(block_data, sort_keys=True)
        return hashlib.sha256(block_str.encode()).hexdigest()
    
    def to_dict(self) -> Dict:
        """Convert the block to a dictionary"""
        return {
            'message_type': 'BlockMessage',
            'coinbase_address': self.coinbase_address,
            'prev_block_hash': self.prev_block_hash,
            'block_height': self.block_height,
            'timestamp': self.timestamp,
            'nonce': self.nonce,
            'difficulty_bits': self.difficulty_bits
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'Block':
        """Create a Block instance from a dictionary"""
        block = cls(
            coinbase_address=data['coinbase_address'],
            prev_block_hash=data['prev_block_hash'],
            block_height=data['block_height'],
            timestamp=data['timestamp'],
            nonce=data['nonce']
        )
        # Verify the hash if provided
        if 'block_hash' in data and data['block_hash'] != block.block_hash:
            raise ValueError(f"Block hash mismatch: {data['block_hash']} != {block.block_hash}")
        return block


class RandomnessBeacon(SharedObject):
    """
    A randomness beacon implemented as a blockchain without transactions.
    Each block is linked to the previous block and contains a random value
    derived from the block hash.
    """
    
    # Genesis block hash - known to everyone and hardcoded
    GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"
    
    # Fixed difficulty of 26 bits
    DIFFICULTY_BITS = 23
    
    def __init__(self, coinbase_address: Optional[str] = None):
        """
        Initialize the randomness beacon.
        
        Args:
            coinbase_address: The address of the node that will mine blocks. If None,
                              a new random address will be generated.
        """
        # Generate a random coinbase address if none provided
        self.coinbase_address = coinbase_address or generate_eth_address()
        
        # Initialize the blockchain with a genesis block
        self.chain: List[Block] = []
        
        # Ledger to track block rewards per address
        self.ledger: Dict[str, int] = {}
        
        # For merklelized sync
        self.chain_hashes: List[str] = []
        
        # Dictionary to map block hashes to their heights for quick lookup
        self.hash_to_height: Dict[str, int] = {}
        
        # Add genesis block
        self._add_genesis_block()
    
    def _add_genesis_block(self) -> None:
        """Add the genesis block to the chain"""
        genesis_block = Block(
            coinbase_address="0x0000000000000000000000000000000000000000",
            prev_block_hash=self.GENESIS_HASH,
            block_height=0,
            timestamp=0.0,
            nonce=0
        )
        self.chain.append(genesis_block)
        self.chain_hashes.append(genesis_block.block_hash)
        self.hash_to_height[genesis_block.block_hash] = genesis_block.block_height
    
    def add_message(self, message: SharedMessage) -> None:
        """
        Add a new block to the chain from a message.
        
        Args:
            message: The SharedMessage containing a block proposal.
        """
        try:
            block_data = message.data
            
            # Skip if not a BlockMessage type
            if not isinstance(block_data, dict) or block_data.get("message_type") != "BlockMessage":
                return
            
            # First, check if we already have this exact block by its hash
            if "block_hash" in block_data and self.has_digest(block_data["block_hash"]):
                # We already have this exact block
                print(f"Already have block with hash {block_data['block_hash'][:8]}")
                return
            
            # Create block instance from the data
            proposed_block = Block.from_dict(block_data)
            
            # Verify that the calculated hash matches the provided hash
            if "block_hash" in block_data and block_data["block_hash"] != proposed_block.block_hash:
                print(f"Block hash mismatch: {block_data['block_hash'][:8]} != {proposed_block.block_hash[:8]}")
                return
            
            # Get the current latest block
            latest_block = self.get_latest_block()
            
            # Check if any block in our chain has the same hash but different height (which would be invalid)
            # Using the hash_to_height dictionary for fast lookup
            if proposed_block.block_hash in self.hash_to_height:
                existing_height = self.hash_to_height[proposed_block.block_hash]
                if existing_height != proposed_block.block_height:
                    print(f"INVALID: Block with hash {proposed_block.block_hash[:8]} already exists at height {existing_height}, " +
                            f"but is being proposed for height {proposed_block.block_height}")
                    return
            
            # Print more debug info
            print(f"Processing block: height={proposed_block.block_height}, hash={proposed_block.block_hash[:8]}, current height={latest_block.block_height}")
            
            # If the proposed block is for a height that's already finalized (below current height),
            # we just print a warning and don't update our chain
            if proposed_block.block_height < latest_block.block_height:
                # We check if this block conflicts with our block at the same height
                if proposed_block.block_height < len(self.chain):
                    existing_block_at_height = self.chain[proposed_block.block_height]
                    
                    # If the hashes are different, we have a conflict but we DON'T resolve it
                    if existing_block_at_height.block_hash != proposed_block.block_hash:
                        # Use the collision resolution logic just to see which one would have won
                        winner_block = self._resolve_collision(existing_block_at_height, proposed_block)
                        
                        # Print a warning with the information
                        if winner_block.block_hash == proposed_block.block_hash:
                            print(f"WARNING: Historical block conflict at height {proposed_block.block_height}: " +
                                f"Received block {proposed_block.block_hash[:8]} would have won over our block {existing_block_at_height.block_hash[:8]}")
                        else:
                            print(f"WARNING: Historical block conflict at height {proposed_block.block_height}: " +
                                f"Our block {existing_block_at_height.block_hash[:8]} would have won over received block {proposed_block.block_hash[:8]}")
                        
                        print(f"Ignoring historical block conflict as the height is already finalized")
                
                # Just ensure we have the hash in our chain_hashes for merkle sync
                if proposed_block.block_hash not in self.chain_hashes:
                    # For historical records only
                    print(f"Adding historical block digest: height={proposed_block.block_height}, hash={proposed_block.block_hash[:8]}")
                    self.add_digest(proposed_block.block_hash)
                    # Also add to hash_to_height dictionary if not already present
                    if proposed_block.block_hash not in self.hash_to_height:
                        self.hash_to_height[proposed_block.block_hash] = proposed_block.block_height
                return
            
            # If the proposed block is for the same height as the latest block,
            # we have a collision to resolve
            if proposed_block.block_height == latest_block.block_height:
                # Special case: if the block has the exact same hash as our current block at this height,
                # it's the same block so we can ignore it
                if proposed_block.block_hash == latest_block.block_hash:
                    print(f"Received duplicate of current block at height {proposed_block.block_height}")
                    return
                
                # Resolve the collision
                winner_block = self._resolve_collision(latest_block, proposed_block)
                
                # If the new block won, replace the last block
                if winner_block.block_hash == proposed_block.block_hash:
                    print(f"Collision at height {proposed_block.block_height}: New block {proposed_block.block_hash[:8]} won over {latest_block.block_hash[:8]}")
                    
                    # Rollback the ledger increase for the previous block miner
                    old_count = self.ledger.get(latest_block.coinbase_address, 0)
                    if old_count > 0:
                        self.ledger[latest_block.coinbase_address] = old_count - 1
                    
                    # Remove the old block's hash from our hash_to_height dictionary
                    if latest_block.block_hash in self.hash_to_height:
                        del self.hash_to_height[latest_block.block_hash]
                    
                    # Replace the last block
                    self.chain[-1] = proposed_block
                    self.chain_hashes[-1] = proposed_block.block_hash
                    
                    # Add the new block's hash to our hash_to_height dictionary
                    self.hash_to_height[proposed_block.block_hash] = proposed_block.block_height
                    
                    # Update the ledger for the new block miner
                    self.ledger[proposed_block.coinbase_address] = self.ledger.get(proposed_block.coinbase_address, 0) + 1
                    
                    print(f"Updated chain: height={latest_block.block_height}, tip={proposed_block.block_hash[:8]}")
                    print(f"Updated ledger: {self.ledger}")
                else:
                    print(f"Collision at height {proposed_block.block_height}: Existing block {latest_block.block_hash[:8]} won over {proposed_block.block_hash[:8]}")
            
            # If the proposed block is for the next height, add it to the chain
            elif proposed_block.block_height == latest_block.block_height + 1:
                print(f"Adding new block: height={proposed_block.block_height}, hash={proposed_block.block_hash[:8]}")
                
                # Add the block to the chain
                self.chain.append(proposed_block)
                self.chain_hashes.append(proposed_block.block_hash)
                
                # Add to hash_to_height dictionary
                self.hash_to_height[proposed_block.block_hash] = proposed_block.block_height
                
                # Update the ledger
                self.ledger[proposed_block.coinbase_address] = self.ledger.get(proposed_block.coinbase_address, 0) + 1
                
                print(f"Updated chain: height={proposed_block.block_height}, tip={proposed_block.block_hash[:8]}")
                print(f"Updated ledger: {self.ledger}")
            
            # Otherwise, ignore the block
            else:
                print(f"Ignoring block with invalid height: {proposed_block.block_height}, current height: {latest_block.block_height}")
        except Exception as e:
            print(f"Error adding block from message: {e}")
            import traceback
            traceback.print_exc()
    
    def add_digest(self, hash_digest: str) -> bool:
        """
        Add a digest to the chain.
        
        Args:
            hash_digest: The digest to add.
            
        Returns:
            bool: True if the digest was added, False otherwise.
        """
        if hash_digest not in self.chain_hashes:
            # This is just for merklelized sync - actual blocks are added via add_message
            self.chain_hashes.append(hash_digest)
            
            # We don't have the height information, so we can't add it to hash_to_height here
            # It will be added properly when the actual block is received
            
            return True
        return False
        
    def is_valid(self, message: SharedMessage) -> bool:
        """
        Check if a message contains a valid block proposal.
        
        Args:
            message: The SharedMessage potentially containing a block proposal.
            
        Returns:
            bool: True if the message contains a valid block proposal, False otherwise.
        """
        try:
            # Try to parse as a block proposal
            block_data = message.data
            if not isinstance(block_data, dict):
                return False
            
            # Check if it's a BlockMessage type
            if block_data.get("message_type") != "BlockMessage":
                # This is not a block message, so it's valid for other purposes
                return True
            
            # If block height is specified and is below current height (already finalized),
            # consider it valid to avoid strikes
            if 'block_height' in block_data:
                latest_block = self.get_latest_block()
                if block_data['block_height'] < latest_block.block_height:
                    # This is a block we've already passed, so consider it valid
                    # but we can check if it matches a block we already have
                    if self.has_digest(block_data.get('block_hash', '')):
                        # We already have this exact block
                        return True
                    
                    # If we have a block at this height, we could check if our block at this height 
                    # matches the proposed one, but for simplicity we'll consider it valid anyway
                    return True
            
            # For new blocks or blocks at current height, check if they're valid proposals
            return self._is_valid_block_proposal(block_data)
        except Exception as e:
            print(f"Error validating block proposal: {e}")
            return False

    def _is_valid_block_proposal(self, block_data: Dict) -> bool:
        """
        Check if a block proposal is valid.
        
        Args:
            block_data: The block data to validate.
            
        Returns:
            bool: True if the block proposal is valid, False otherwise.
        """
        try:
            # Check if the block data contains all required fields
            required_fields = [
                'coinbase_address', 'prev_block_hash', 'block_height',
                'timestamp', 'nonce', 'difficulty_bits'
            ]
            if not all(field in block_data for field in required_fields):
                print(f"Missing required fields: {required_fields}")
                return False
            
            # Create a Block object to validate it
            block = Block.from_dict(block_data)
            
            # Check if the block height is valid (should be 1 higher than the latest block or same for collisions)
            latest_block = self.get_latest_block()
            if block.block_height != latest_block.block_height + 1 and block.block_height != latest_block.block_height:
                print(f"Invalid block height: {block.block_height}, expected {latest_block.block_height + 1} or {latest_block.block_height}")
                return False
            
            # For height+1 blocks, check if the previous block hash matches the latest block hash
            if block.block_height == latest_block.block_height + 1 and block.prev_block_hash != latest_block.block_hash:
                print(f"Invalid previous block hash: {block.prev_block_hash} != {latest_block.block_hash}")
                return False
            
            # For same-height blocks (collisions), validate against the same previous block
            if block.block_height == latest_block.block_height and block.prev_block_hash != latest_block.prev_block_hash:
                print(f"Invalid previous block hash for collision block: {block.prev_block_hash} != {latest_block.prev_block_hash}")
                return False
            
            # Check if the timestamp is not too far in the future (< 5 seconds)
            current_time = time.time() * 1000  # Convert to milliseconds
            if block.timestamp > current_time + 5000:
                print(f"Block timestamp too far in the future: {block.timestamp} > {current_time + 5000}")
                return False
            
            # Check that the difficulty is fixed at 28 bits
            if block.difficulty_bits != 23:
                print(f"Invalid difficulty bits: {block.difficulty_bits}, expected 23")
                return False
            
            # Verify the PoW
            challenge = block.coinbase_address + block.prev_block_hash
            pow_primitive = ProofOfWorkPrimitive(difficulty_bits=self.DIFFICULTY_BITS)
            if not pow_primitive.verify_proof(challenge, block.nonce):
                print(f"Invalid PoW for block: {block.block_hash}")
                return False
            
            # All checks passed
            return True
        except Exception as e:
            print(f"Error validating block proposal: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def _resolve_collision(self, existing_block: Block, new_block: Block) -> Block:
        """
        Resolve a collision between two blocks at the same height.
        
        Args:
            existing_block: The existing block in the chain.
            new_block: The new block being proposed. 
            
        Returns:
            Block: The block that should be used.
        """
        # Compare lexicographically the block hashes
        if new_block.block_hash < existing_block.block_hash:
            # New block wins
            return new_block
        else:
            # Existing block wins
            return existing_block
        
    def get_latest_block(self) -> Block:
        """Get the latest block in the chain"""
        return self.chain[-1]
    
    def mine_block(self, interrupt_callback: Optional[Callable[[], bool]] = None) -> Optional[Block]:
        """
        Mine a new block for this beacon.
        
        Args:
            interrupt_callback: Optional callback that returns True if mining should be interrupted
            
        Returns:
            Optional[Block]: The newly mined block, or None if mining was interrupted
        """
        latest_block = self.get_latest_block()
        block_height = latest_block.block_height + 1
        prev_block_hash = latest_block.block_hash
        start_timestamp = time.time() * 1000  # milliseconds when mining started
        
        # Create the challenge for mining
        challenge = self.coinbase_address + prev_block_hash
        
        # Create a PoW instance with fixed difficulty
        pow_primitive = ProofOfWorkPrimitive(difficulty_bits=self.DIFFICULTY_BITS)
        
        # Mine a new block - this will give us a nonce that produces a hash with the required number of leading zeros
        nonce = pow_primitive.create_proof(challenge, interrupt_callback)
        
        # If mining was interrupted
        if nonce == -1:
            return None
        
        # Get current timestamp after mining is complete
        end_timestamp = time.time() * 1000
        
        # Create a new block with the found nonce
        new_block = Block(
            coinbase_address=self.coinbase_address,
            prev_block_hash=prev_block_hash,
            block_height=block_height,
            timestamp=end_timestamp,  # Use timestamp after mining
            nonce=nonce
        )
        
        return new_block
    
    def get_randomness(self, block_height: Optional[int] = None) -> str:
        """
        Get the randomness for a specific block height.
        If block_height is None, the latest block is used.
        
        Args:
            block_height: The block height to get the randomness for.
            
        Returns:
            str: The randomness value (a hex string).
        """
        if block_height is None:
            block = self.get_latest_block()
        elif 0 <= block_height < len(self.chain):
            block = self.chain[block_height]
        else:
            raise ValueError(f"Invalid block height: {block_height}")
        
        # The randomness is the block hash, which is already a hex string
        return block.block_hash
    
    def get_binary_randomness(self, block_height: Optional[int] = None, length: int = 256) -> str:
        """
        Get a binary string of randomness from a block.
        
        Args:
            block_height: The block height to get the randomness for.
            length: The length of the binary string to return (default: 256 bits).
            
        Returns:
            str: A binary string of random bits.
        """
        hex_randomness = self.get_randomness(block_height)
        # Convert hex to binary
        binary = bin(int(hex_randomness, 16))[2:]
        # Pad to full length
        padded_binary = binary.zfill(256)
        # Return the requested length
        return padded_binary[:length]
    
    # Methods required for merklelized storage
    
    def is_merkelized(self) -> bool:
        """
        Check if this shared object is merklelized.
        
        Returns:
            bool: True, as this object is merklelized.
        """
        return True
    
    def get_latest_digest(self) -> str:
        """
        Get the latest digest for this shared object.
        
        Returns:
            str: The hash of the latest block.
        """
        return self.get_latest_block().block_hash
    
    def has_digest(self, hash_digest: str) -> bool:
        """
        Check if this shared object has a specific digest.
        
        Args:
            hash_digest: The digest to check for.
            
        Returns:
            bool: True if the digest exists in the chain, False otherwise.
        """
        # Handle empty hash or None values
        if not hash_digest:
            return False
            
        return hash_digest in self.chain_hashes
    
    def is_valid_digest(self, hash_digest: str) -> bool:
        """
        Check if a digest is valid for this shared object.
        
        Args:
            hash_digest: The digest to check.
            
        Returns:
            bool: True if the digest is valid, False otherwise.
        """
        return self.has_digest(hash_digest)
    
    def gossip_object(self, digest: str) -> List[SharedMessage]:
        """
        Get all block messages since a specific digest for gossiping.
        
        Args:
            digest: The digest to start from.
            
        Returns:
            List[SharedMessage]: The messages to gossip.
        """
        # Handle case when digest is empty or not found
        if not digest or not self.has_digest(digest):
            # Return only the first 10 blocks if no valid digest is provided - this helps with initial sync
            # while keeping message size manageable
            blocks_to_gossip = self.chain[:10]  # Limit to first 10 blocks
            print(f"Gossiping first 10 blocks out of {len(self.chain)} total blocks")
            messages = []
            for block in blocks_to_gossip:
                block_data = block.to_dict()
                block_data["block_hash"] = block.block_hash  # Include the hash explicitly
                messages.append(SharedMessage(data=block_data))
            return messages
        
        try:
            # Find the index of the digest
            index = self.chain_hashes.index(digest)
            
            # Get all blocks after the digest
            blocks_to_gossip = self.chain[index+1:]
            
            if blocks_to_gossip:
                print(f"Gossiping {len(blocks_to_gossip)} blocks after digest {digest[:8]}...")
            
            # Convert blocks to messages
            messages = []
            for block in blocks_to_gossip:
                block_data = block.to_dict()
                block_data["block_hash"] = block.block_hash  # Include the hash explicitly
                messages.append(SharedMessage(data=block_data))
            
            return messages
        except ValueError:
            print(f"Error: Digest {digest[:8]} not found in chain_hashes")
            # Return the first 10 blocks as a fallback
            blocks_to_gossip = self.chain[:10]  # Limit to first 10 blocks
            print(f"Fallback: Gossiping first 10 blocks")
            messages = []
            for block in blocks_to_gossip:
                block_data = block.to_dict()
                block_data["block_hash"] = block.block_hash  # Include the hash explicitly
                messages.append(SharedMessage(data=block_data))
            return messages
        except Exception as e:
            print(f"Error in gossip_object: {e}")
            import traceback
            traceback.print_exc()
            return []
        
    def get_messages_since_digest(self, digest: str) -> List[SharedMessage]:
        """
        Get all block messages since a specific digest.
        
        Args:
            digest: The digest to start from.
            
        Returns:
            List[SharedMessage]: The messages since the digest.
        """
        return self.gossip_object(digest)