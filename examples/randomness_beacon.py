from typing import List, Dict, Any
import json
import hashlib
import time
import os
import threading

from shared_object import SharedObject, SharedObjectException
from shared_message import SharedMessage
from crypto_primitives.pow import ProofOfWorkPrimitive

class RandomnessBeacon(SharedObject):
    # Genesis block hash - known to everyone
    GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"
    
    def __init__(self, coinbase_address=None, difficulty_bits=12):
        self.blocks = []  # List of block headers
        self.block_by_hash = {}  # Quick lookup by hash
        self.ledger = {}  # Tracks blocks mined by each address
        self.coinbase_address = coinbase_address  # This node's mining address
        self.pow_primitive = ProofOfWorkPrimitive(difficulty_bits=difficulty_bits)
        self.block_replacement_event = threading.Event()  # Event to signal block replacements
        self.block_change_lock = threading.Lock()  # Lock for thread safety
        
        # Initialize with genesis block
        genesis_block = {
            "message_type": "BEACON_BLOCK",
            "blockHeight": 0,
            "prevBlockHash": self.GENESIS_HASH,
            "timestamp": int(time.time()),
            "coinbaseAddress": "0x0000000000000000000000000000000000000000",
            "nonce": 0,
        }
        genesis_hash = self._calculate_block_hash(genesis_block)
        genesis_block["blockHash"] = genesis_hash
        
        self.blocks.append(genesis_block)
        self.block_by_hash[genesis_hash] = genesis_block
    
    def is_valid(self, message: SharedMessage) -> bool:
        """Validate a new block message"""
        try:
            block = message.data
            
            # Basic structure check
            if not isinstance(block, dict):
                return False
                
            # Check message type
            if block.get("message_type") != "BEACON_BLOCK":
                return False
                
            # Check required fields
            required_fields = ["blockHeight", "prevBlockHash", "timestamp", "coinbaseAddress", "nonce"]
            if not all(field in block for field in required_fields):
                return False
                
            # Time validation: within ±15 seconds
            current_time = int(time.time())
            if abs(block["timestamp"] - current_time) > 15:
                return False
                
            # Verify block height is valid (next in sequence or replacing last)
            if block["blockHeight"] != len(self.blocks) and block["blockHeight"] != len(self.blocks) - 1:
                return False
                
            # For replacement case, verify this is not replacing genesis
            if block["blockHeight"] == 0:
                return False
                
            # Get previous block based on height
            if block["blockHeight"] == 0:  # Genesis block case
                prev_block_hash = self.GENESIS_HASH
            elif block["blockHeight"] > 0 and block["blockHeight"] <= len(self.blocks):
                # Find previous block hash based on the height
                prev_height = block["blockHeight"] - 1
                if prev_height < len(self.blocks):
                    prev_block_hash = self.blocks[prev_height]["blockHash"]
                else:
                    return False
            else:
                return False
                
            # Check prev block hash matches expected
            if block["prevBlockHash"] != prev_block_hash:
                return False
                
            # Calculate block hash if not provided
            if "blockHash" not in block:
                block["blockHash"] = self._calculate_block_hash(block)
                
            # Verify PoW
            challenge = block["coinbaseAddress"] + block["prevBlockHash"]
            if not self.pow_primitive.verify_proof(challenge, block["nonce"], block["blockHash"]):
                return False
                
            # All checks passed
            return True
        except Exception as e:
            print(f"Block validation error: {str(e)}")
            return False

    def add_message(self, message: SharedMessage) -> None:
        """Add a valid block to the chain"""
        block = message.data
        
        # Calculate and add block hash if not already provided
        if "blockHash" not in block:
            block["blockHash"] = self._calculate_block_hash(block)

        # Check if we're already seen this block
        if block["blockHash"] in self.block_by_hash:
            return
        
        # Acquire lock for thread safety
        with self.block_change_lock:
            # Check if we're replacing the last block
            if block["blockHeight"] == len(self.blocks) - 1:
                self._handle_replacement(block)
            else:
                # Add new block
                self.blocks.append(block)
                self.block_by_hash[block["blockHash"]] = block
                
                # Update ledger for miner
                addr = block["coinbaseAddress"]
                self.ledger[addr] = self.ledger.get(addr, 0) + 1
                
                # Signal that a new block was added
                if block["blockHeight"] > 0:  # Don't signal for genesis
                    self.block_replacement_event.set()

    def _handle_replacement(self, new_block):
        """Handle potential replacement of the last block"""
        current_last = self.blocks[-1]
        
        # Skip if trying to replace genesis
        if current_last["blockHeight"] == 0:
            return
            
        # Only replace if both blocks are at exactly the same height
        if current_last["blockHeight"] != new_block["blockHeight"]:
            print(f"Height mismatch: current={current_last['blockHeight']}, new={new_block['blockHeight']} - not replacing")
            return
            
        # Only replace if both blocks have the same previous block hash
        if current_last["prevBlockHash"] != new_block["prevBlockHash"]:
            print(f"Previous hash mismatch: current={current_last['prevBlockHash'][:8]}..., new={new_block['prevBlockHash'][:8]}... - not replacing")
            return
            
        # Compare lexicographical ordering of block hashes
        # Lower hash value wins (lexicographically smaller)
        current_hash = current_last["blockHash"]
        new_hash = new_block["blockHash"]
        
        is_own_block = current_last["coinbaseAddress"] == self.coinbase_address
        
        print(f"Collision detected at height {current_last['blockHeight']}")
        print(f"Current hash: {current_hash}")
        print(f"New hash: {new_hash}")
        print(f"Common prevBlockHash: {current_last['prevBlockHash'][:8]}...")
        print(f"Is new < current? {new_hash < current_hash}")
        print(f"Is replacing our own block? {is_own_block}")
        
        if new_hash < current_hash:  # Lower lexicographical hash value wins
            print("New block is better - replacing current block")
            # Decrease ledger for old miner
            old_addr = current_last["coinbaseAddress"]
            if old_addr in self.ledger and self.ledger[old_addr] > 0:
                self.ledger[old_addr] -= 1
                
            # Remove old block from hash map
            old_hash = current_last["blockHash"]
            if old_hash in self.block_by_hash:
                del self.block_by_hash[old_hash]
                
            # Remove old block from chain
            self.blocks.pop()
            
            # Add new block
            self.blocks.append(new_block)
            self.block_by_hash[new_block["blockHash"]] = new_block
            
            # Update ledger for new miner
            new_addr = new_block["coinbaseAddress"]
            self.ledger[new_addr] = self.ledger.get(new_addr, 0) + 1
            
            # Signal that a block replacement occurred
            self.block_replacement_event.set()
        else:
            print("Current block is better - keeping it")

    def wait_for_block_change(self, timeout=None):
        """Wait for a block replacement event"""
        result = self.block_replacement_event.wait(timeout)
        self.block_replacement_event.clear()
        return result

    def _calculate_block_hash(self, block):
        """Calculate hash of a block header"""
        # Create a copy without blockHash field
        block_copy = block.copy()
        block_copy.pop("blockHash", None)
        
        # Sort keys for consistent serialization
        block_json = json.dumps(block_copy, sort_keys=True)
        return hashlib.sha256(block_json.encode()).hexdigest()

    def is_merkelized(self) -> bool:
        """Indicate this is a merklelized object for syncing"""
        return True
        
    def get_latest_digest(self) -> str:
        """Return the hash of the latest block for sync"""
        if not self.blocks:
            return self.GENESIS_HASH
        return self.blocks[-1]["blockHash"]
        
    def has_digest(self, hash_digest: str) -> bool:
        """Check if we have a block with the given hash"""
        return hash_digest in self.block_by_hash
        
    def is_valid_digest(self, hash_digest: str) -> bool:
        """Verify if a digest is valid for this chain"""
        # Check if this hash is in our known blocks
        return hash_digest in self.block_by_hash
        
    def add_digest(self, hash_digest: str) -> bool:
        """Add a digest directly (used in merkle sync)"""
        # Not needed as we add blocks through add_message
        return False
        
    def gossip_object(self, digest) -> List[SharedMessage]:
        """Return messages from the given digest to the latest"""
        if not self.has_digest(digest):
            return []
            
        # Find index of the block with this digest
        start_idx = None
        for i, block in enumerate(self.blocks):
            if block["blockHash"] == digest:
                start_idx = i
                break
                
        if start_idx is None:
            return []
            
        # Return all subsequent blocks as messages
        result = []
        for i in range(start_idx + 1, len(self.blocks)):
            result.append(SharedMessage(data=self.blocks[i]))
            
        return result
        
    def get_messages_since_digest(self, digest: str) -> List[SharedMessage]:
        """Same as gossip_object for this implementation"""
        return self.gossip_object(digest)
        
    def create_block(self, nonce=None):
        """Create a new block (used for mining)"""
        if not self.coinbase_address:
            raise SharedObjectException("No coinbase address set for mining")
        
        with self.block_change_lock:    
            prev_block = self.blocks[-1]
            
            # Double-check that we're mining at the right height
            next_height = len(self.blocks)
            
            block = {
                "message_type": "BEACON_BLOCK",
                "blockHeight": next_height,
                "prevBlockHash": prev_block["blockHash"],
                "timestamp": int(time.time()),
                "coinbaseAddress": self.coinbase_address,
                "nonce": nonce or 0,
            }
            
            if nonce is not None:
                # If nonce provided, calculate hash and add it
                block["blockHash"] = self._calculate_block_hash(block)
                
            return block
        
    def mine_block(self):
        """Mine a new block with PoW"""
        if not self.coinbase_address:
            raise SharedObjectException("No coinbase address set for mining")
            
        # Create block template
        block = self.create_block()
        
        # Calculate PoW
        challenge = block["coinbaseAddress"] + block["prevBlockHash"]
        nonce, block_hash = self.pow_primitive.create_proof(challenge)
        
        # Update block with nonce and hash
        block["nonce"] = nonce
        block["blockHash"] = block_hash
        
        return block
        
    def get_random_number(self, block_hash=None):
        """
        Get a random number derived from a block hash
        If block_hash is None, uses the latest block hash
        """
        if block_hash is None:
            if not self.blocks:
                return 0
            block_hash = self.blocks[-1]["blockHash"]
        
        # Convert hash to a number between 0 and 1
        hash_int = int(block_hash, 16)
        max_int = 2 ** (len(block_hash) * 4)  # 4 bits per hex character
        return hash_int / max_int
        
    def get_random_int(self, min_val, max_val, block_hash=None):
        """Get a random integer in the specified range"""
        random_val = self.get_random_number(block_hash)
        return min_val + int(random_val * (max_val - min_val + 1))


def generate_eth_address():
    """Generate an Ethereum-style address (simplified)"""
    # Generate a random private key
    private_key = os.urandom(32)
    
    # Hash it to simulate derivation of Ethereum address
    address_bytes = hashlib.sha256(private_key).digest()[-20:]
    return "0x" + address_bytes.hex()


class BeaconMiner:
    """Class to handle mining blocks for the RandomnessBeacon"""
    
    def __init__(self, node, beacon_obj, mining_interval=10):
        """
        Initialize the miner
        
        node: ChaincraftNode - the node to broadcast from
        beacon_obj: RandomnessBeacon - the shared object
        mining_interval: int - seconds between mining attempts
        """
        self.node = node
        self.beacon = beacon_obj
        self.mining_interval = mining_interval
        self.running = False
        self.restart_mining = False
    
    def start(self):
        """Start the mining process in a background thread"""
        import threading
        
        self.running = True
        self.thread = threading.Thread(target=self._mine_loop, daemon=True)
        self.thread.start()
        
        # Start a parallel thread to watch for block changes
        self.watcher_thread = threading.Thread(target=self._watch_for_changes, daemon=True)
        self.watcher_thread.start()
    
    def stop(self):
        """Stop the mining process"""
        self.running = False
        
    def _watch_for_changes(self):
        """Watch for block chain changes and trigger mining restarts"""
        while self.running:
            # Wait for a block change event
            if self.beacon.wait_for_block_change(timeout=0.5):
                print(f"Miner detected block change, flagging for restart")
                self.restart_mining = True
    
    def _mine_loop(self):
        """Main mining loop"""
        miner_address = self.beacon.coinbase_address
        short_address = miner_address[:8] + "..." if miner_address else "unknown"
        print(f"Miner {short_address} starting mining loop")
        
        while self.running:
            try:
                # Check if we need to restart mining due to chain changes
                if self.restart_mining:
                    print(f"Miner {short_address} restarting mining process due to chain update")
                    self.restart_mining = False
                    continue  # Skip to next iteration with fresh state
                
                # Make sure we're working on the correct height
                next_height = len(self.beacon.blocks)
                prev_hash = self.beacon.blocks[-1]["blockHash"]
                
                # Mine a block
                block = self.beacon.mine_block()
                
                # Double-check that the chain hasn't changed while mining
                current_height = len(self.beacon.blocks)
                current_top_hash = self.beacon.blocks[-1]["blockHash"]
                
                if current_height != next_height or current_top_hash != prev_hash:
                    print(f"Miner {short_address}: Chain changed while mining, discarding block")
                    continue
                    
                # Broadcast the block
                try:
                    self.node.create_shared_message(block)
                    print(f"Miner {short_address} found block at height {block['blockHeight']} with hash {block['blockHash'][:8]}...")
                except SharedObjectException as e:
                    # The block might have been replaced while we were mining
                    print(f"Miner {short_address}: Block rejected - chain may have changed: {str(e)}")
                
            except Exception as e:
                print(f"Mining error for {short_address}: {str(e)}")
                
            # Wait for next interval
            time.sleep(self.mining_interval)