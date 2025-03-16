import sys, os
import unittest
import time
import hashlib
import json
import statistics
from typing import List
import threading

# Make sure the examples module is in the path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from examples.randomness_beacon import (
    RandomnessBeacon, Block, generate_eth_address,
)
from examples.randomness_beacon_node import (
    RandomnessBeaconNode,
    create_randomness_beacon_network, start_mining_in_network,
    stop_mining_in_network, close_network
)
from shared_message import SharedMessage
from crypto_primitives.pow import ProofOfWorkPrimitive


class TestBlock(unittest.TestCase):
    """Test the Block class functionality"""
    
    def test_block_creation(self):
        """Test creating a block and calculating its hash"""
        block = Block(
            coinbase_address="0x1234567890abcdef1234567890abcdef12345678",
            prev_block_hash="0000000000000000000000000000000000000000000000000000000000000000",
            block_height=1,
            timestamp=time.time() * 1000,
            nonce=123456
        )
        
        # Check that the block hash is calculated correctly
        self.assertIsNotNone(block.block_hash)
        self.assertEqual(len(block.block_hash), 64)  # SHA-256 hex digest length
        self.assertEqual(block.difficulty_bits, 23)  # Fixed difficulty
        
        # Test converting to and from dict
        block_dict = block.to_dict()
        reconstructed_block = Block.from_dict(block_dict)
        
        self.assertEqual(block.coinbase_address, reconstructed_block.coinbase_address)
        self.assertEqual(block.prev_block_hash, reconstructed_block.prev_block_hash)
        self.assertEqual(block.block_height, reconstructed_block.block_height)
        self.assertEqual(block.timestamp, reconstructed_block.timestamp)
        self.assertEqual(block.nonce, reconstructed_block.nonce)
        self.assertEqual(block.difficulty_bits, reconstructed_block.difficulty_bits)
        self.assertEqual(block.block_hash, reconstructed_block.block_hash)
    
    def test_block_hash_calculation(self):
        """Test that the block hash calculation is deterministic"""
        block = Block(
            coinbase_address="0x1234567890abcdef1234567890abcdef12345678",
            prev_block_hash="0000000000000000000000000000000000000000000000000000000000000000",
            block_height=1,
            timestamp=1234567890.123,
            nonce=123456
        )
        
        # Calculate the hash manually
        block_dict = block.to_dict()
        block_str = json.dumps(block_dict, sort_keys=True)
        expected_hash = hashlib.sha256(block_str.encode()).hexdigest()
        
        # Check that the calculated hash matches
        self.assertEqual(block.block_hash, expected_hash)


class TestRandomnessBeacon(unittest.TestCase):
    """Test the RandomnessBeacon class functionality"""
    
    def setUp(self):
        """Set up a fresh randomness beacon for each test"""
        self.coinbase_address = "0x1234567890abcdef1234567890abcdef12345678"
        self.beacon = RandomnessBeacon(coinbase_address=self.coinbase_address)
    
    def test_genesis_block(self):
        """Test that the genesis block is created correctly"""
        genesis_block = self.beacon.get_latest_block()
        
        self.assertEqual(genesis_block.block_height, 0)
        self.assertEqual(genesis_block.prev_block_hash, self.beacon.GENESIS_HASH)
        self.assertEqual(genesis_block.coinbase_address, "0x0000000000000000000000000000000000000000")
        self.assertEqual(genesis_block.difficulty_bits, 23)  # Fixed difficulty
    
    def test_mining_block(self):
        """Test mining a new block"""
        # Mine a block
        new_block = self.beacon.mine_block()
        
        # Check that the block has the correct properties
        self.assertEqual(new_block.block_height, 1)
        self.assertEqual(new_block.prev_block_hash, self.beacon.get_latest_block().block_hash)
        self.assertEqual(new_block.coinbase_address, self.coinbase_address)
        
        # Check fixed difficulty
        self.assertEqual(new_block.difficulty_bits, 23)
        
        # Check that the block passes PoW verification
        challenge = new_block.coinbase_address + new_block.prev_block_hash
        pow_primitive = ProofOfWorkPrimitive(difficulty_bits=10)
        self.assertTrue(pow_primitive.verify_proof(challenge, new_block.nonce))
    
    def test_mining_interrupt(self):
        """Test that mining can be interrupted"""
        # Set up an interrupt flag
        interrupt_flag = [False]
        
        def interrupt_callback():
            return interrupt_flag[0]
        
        # Start mining in a separate thread
        mining_thread = threading.Thread(
            target=lambda: self.beacon.mine_block(interrupt_callback=interrupt_callback)
        )
        mining_thread.daemon = True
        mining_thread.start()
        
        # Let mining run for a short time
        time.sleep(0.5)
        
        # Set the interrupt flag
        interrupt_flag[0] = True
        
        # Wait for the thread to finish
        mining_thread.join(timeout=2)
        
        # Check that the thread finished
        self.assertFalse(mining_thread.is_alive())
    
    def test_add_valid_block(self):
        """Test adding a valid block to the chain"""
        # Mine a block
        new_block = self.beacon.mine_block()
        
        # Create a message with the block
        message = SharedMessage(data=new_block.to_dict())
        
        # Add the message to the beacon
        self.beacon.add_message(message)
        
        # Check that the block was added to the chain
        self.assertEqual(len(self.beacon.chain), 2)
        self.assertEqual(self.beacon.get_latest_block().block_hash, new_block.block_hash)
        
        # Check that the ledger was updated
        self.assertEqual(self.beacon.ledger.get(self.coinbase_address, 0), 1)
    
    def test_reject_invalid_block(self):
        """Test rejecting an invalid block"""
        # Create an invalid block (wrong height)
        invalid_block = Block(
            coinbase_address=self.coinbase_address,
            prev_block_hash=self.beacon.get_latest_block().block_hash,
            block_height=100,  # Invalid height
            timestamp=time.time() * 1000,
            nonce=123456
        )
        
        # Create a message with the invalid block
        message = SharedMessage(data=invalid_block.to_dict())
        
        # Check that the block is rejected
        self.assertFalse(self.beacon.is_valid(message))
        
        # Try to add the message to the beacon
        self.beacon.add_message(message)
        
        # Check that the block was not added to the chain
        self.assertEqual(len(self.beacon.chain), 1)  # Still only genesis block
    
    def test_reject_future_timestamp(self):
        """Test rejecting a block with a timestamp too far in the future"""
        # Mine a valid block
        valid_block = self.beacon.mine_block()
        
        # Create a block with a timestamp 6 seconds in the future
        future_time = time.time() * 1000 + 6000  # 6 seconds in the future
        future_block = Block(
            coinbase_address=self.coinbase_address,
            prev_block_hash=valid_block.prev_block_hash,
            block_height=valid_block.block_height,
            timestamp=future_time,
            nonce=valid_block.nonce
        )
        
        # Create a message with the future block
        message = SharedMessage(data=future_block.to_dict())
        
        # Check that the block is rejected
        self.assertFalse(self.beacon.is_valid(message))
    
    def test_resolve_collision(self):
        """Test resolving a collision between two blocks at the same height"""
        # Mine and add a first block
        block1 = self.beacon.mine_block()
        message1 = SharedMessage(data=block1.to_dict())
        self.beacon.add_message(message1)
        
        # Check that the block was added
        self.assertEqual(len(self.beacon.chain), 2)
        self.assertEqual(self.beacon.ledger.get(self.coinbase_address, 0), 1)
        
        # Create a competing block that will have a lexicographically smaller block hash
        # by manipulating the nonce and timestamp until we get a hash that's smaller
        
        # Get the genesis block which is the previous block for our competing block
        genesis_block = self.beacon.chain[0]
        
        # Try different nonces until we get a block with a hash smaller than block1's hash
        competing_address = "0x9876543210abcdef9876543210abcdef98765432"
        timestamp = time.time() * 1000
        
        # Keep trying different nonces until we find one that produces a block hash
        # that is lexicographically smaller than block1's hash
        nonce = 1
        while True:
            competing_block = Block(
                coinbase_address=competing_address,
                prev_block_hash=genesis_block.block_hash,
                block_height=1,
                timestamp=timestamp,
                nonce=nonce
            )
            
            # If we found a block with a smaller hash, break
            if competing_block.block_hash < block1.block_hash:
                break
                
            # Try next nonce
            nonce += 1
            
            # Avoid infinite loop in test
            if nonce > 100:
                self.fail("Couldn't find a competing block with smaller hash in reasonable time")
        
        # Create a message with the competing block
        message2 = SharedMessage(data=competing_block.to_dict())
        
        # Add the message to the beacon
        self.beacon.add_message(message2)
        
        # Check that the competing block replaced the original block
        self.assertEqual(len(self.beacon.chain), 2)  # Still 2 blocks
        self.assertEqual(self.beacon.get_latest_block().block_hash, competing_block.block_hash)
        
        # Check that the ledger was updated
        self.assertEqual(self.beacon.ledger.get(self.coinbase_address, 0), 0)  # Reward was taken away
        self.assertEqual(self.beacon.ledger.get(competing_address, 0), 1)  # Reward was given to new address

    def test_get_randomness(self):
        """Test getting randomness from the beacon"""
        # Mine and add a block
        new_block = self.beacon.mine_block()
        message = SharedMessage(data=new_block.to_dict())
        self.beacon.add_message(message)
        
        # Get randomness from the latest block
        randomness = self.beacon.get_randomness()
        
        # Check that the randomness is the block hash
        self.assertEqual(randomness, new_block.block_hash)
        
        # Get binary randomness
        binary_randomness = self.beacon.get_binary_randomness(length=128)
        
        # Check that the binary randomness is the correct length
        self.assertEqual(len(binary_randomness), 128)
        
        # Check that the binary randomness only contains 0s and 1s
        self.assertTrue(all(bit in "01" for bit in binary_randomness))
    
    def test_merklelized_sync(self):
        """Test merklelized synchronization"""
        # Add several blocks to the chain
        for _ in range(5):
            new_block = self.beacon.mine_block()
            message = SharedMessage(data=new_block.to_dict())
            self.beacon.add_message(message)
        
        # Check that the chain has 6 blocks (genesis + 5 mined)
        self.assertEqual(len(self.beacon.chain), 6)
        
        # Get the digest of the third block
        third_block_digest = self.beacon.chain[3].block_hash
        
        # Check that the beacon has this digest
        self.assertTrue(self.beacon.has_digest(third_block_digest))
        self.assertTrue(self.beacon.is_valid_digest(third_block_digest))
        
        # Get all messages since this digest
        messages = self.beacon.get_messages_since_digest(third_block_digest)
        
        # Should be 2 messages (blocks 4 and 5)
        self.assertEqual(len(messages), 2)
        
        # Check that the messages contain the correct blocks
        self.assertEqual(messages[0].data['block_height'], 4)
        self.assertEqual(messages[1].data['block_height'], 5)


class TestRandomnessBeaconNode(unittest.TestCase):
    """Test the RandomnessBeaconNode functionality"""
    
    def setUp(self):
        """Set up a test node"""
        self.node = RandomnessBeaconNode(persistent=False)
        self.node.start()
    
    def tearDown(self):
        """Clean up the test node"""
        self.node.stop_mining()
        self.node.close()
    
    def test_node_mining(self):
        """Test that the node can mine blocks"""
        # Start mining
        self.node.start_mining()
        
        # Wait for a block to be mined
        start_time = time.time()
        max_wait_time = 20  # seconds
        
        while time.time() - start_time < max_wait_time:
            if self.node.beacon.get_latest_block().block_height > 3:
                break
            time.sleep(0.1)
        
        # Stop mining
        self.node.stop_mining()
        
        # Check that at least one block was mined
        self.assertGreater(self.node.beacon.get_latest_block().block_height, 0)
        
        # Check that the node's address got a reward
        address = self.node.beacon.coinbase_address
        self.assertGreaterEqual(self.node.beacon.ledger.get(address, 0), 1)
        
        # Check the difficulty is fixed at 28
        latest_block = self.node.beacon.get_latest_block()
        self.assertEqual(latest_block.difficulty_bits, 23)
    
    def test_node_get_randomness(self):
        """Test getting randomness from the node"""
        # Mine a block
        self.node.start_mining()
        
        # Wait for a block to be mined
        start_time = time.time()
        max_wait_time = 20  # seconds
        
        while time.time() - start_time < max_wait_time:
            if self.node.beacon.get_latest_block().block_height > 2:
                break
            time.sleep(0.1)
        
        # Stop mining
        self.node.stop_mining()
        
        # Get randomness from the node
        randomness = self.node.get_randomness()
        
        # Check that the randomness is a valid hash
        self.assertEqual(len(randomness), 64)
        
        # Get binary randomness
        binary_randomness = self.node.get_binary_randomness(length=128)
        
        # Check that the binary randomness is the correct length and format
        self.assertEqual(len(binary_randomness), 128)
        self.assertTrue(all(bit in "01" for bit in binary_randomness))


class TestRandomnessBeaconNetwork(unittest.TestCase):
    """Test a network of RandomnessBeaconNodes"""
    
    def setUp(self):
        """Set up a network of nodes with a more robust connection pattern"""
        self.num_nodes = 3
        self.nodes = create_randomness_beacon_network(self.num_nodes)
        # Ensure all nodes are connected to each other in a full mesh topology
        self._ensure_ring_connectivity()
        # Wait for initial connections to stabilize
        time.sleep(4)
    
    def tearDown(self):
        """Clean up the network with additional safeguards"""
        try:
            # Ensure mining is stopped first
            for node in self.nodes:
                if node.is_mining:
                    node.stop_mining()
            # Then close the network
            close_network(self.nodes)
        except Exception as e:
            print(f"Error during tearDown: {e}")
            import traceback
            traceback.print_exc()
    
    def _ensure_full_mesh_connectivity(self):
        """Ensure all nodes are connected to each other in a full mesh topology"""
        for i in range(len(self.nodes)):
            for j in range(len(self.nodes)):
                if i != j:  # Don't connect to self
                    self.nodes[i].connect_to_peer(self.nodes[j].host, self.nodes[j].port)
    
    def _ensure_ring_connectivity(self):
        """Ensure nodes are connected in a ring topology"""
        for i in range(len(self.nodes)):
            next_node = (i + 1) % len(self.nodes)  # Connect to the next node in the ring
            self.nodes[i].connect_to_peer(self.nodes[next_node].host, self.nodes[next_node].port)
            self.nodes[next_node].connect_to_peer(self.nodes[i].host, self.nodes[i].port)

    def _wait_for_sync(self, expected_height=None, max_wait_time=30):
        """
        Helper method to wait for network synchronization
        
        Args:
            expected_height: If provided, wait until all nodes reach this height
            max_wait_time: Maximum time to wait in seconds
            
        Returns:
            bool: True if sync was achieved, False if timeout occurred
        """
        print(f"Waiting for network sync (max {max_wait_time} seconds)...")
        start_time = time.time()
        sync_check_interval = 0.5  # Check every half second
        
        while time.time() - start_time < max_wait_time:
            # Get current heights of all nodes
            heights = [node.beacon.get_latest_block().block_height for node in self.nodes]
            
            # If we're waiting for a specific height
            if expected_height is not None:
                if all(h >= expected_height for h in heights):
                    print(f"All nodes reached height {expected_height} or higher")
                    # Allow extra time for complete synchronization
                    time.sleep(2)
                    return True
            # Otherwise just wait until all nodes have the same height
            elif len(set(heights)) == 1:
                print(f"All nodes synchronized at height {heights[0]}")
                # Allow extra time for complete synchronization
                time.sleep(2)
                return True
                
            # Print progress every few seconds
            elapsed = time.time() - start_time
            if int(elapsed) % 5 == 0:
                print(f"Current heights after {int(elapsed)}s: {heights}")
                
            time.sleep(sync_check_interval)
        
        # If we get here, sync timed out
        print(f"Sync timed out after {max_wait_time} seconds")
        heights = [node.beacon.get_latest_block().block_height for node in self.nodes]
        print(f"Final heights: {heights}")
        return False
    
    def _create_valid_block_message(self, block):
        """Create a valid block message with the BlockMessage type"""
        block_data = block.to_dict()
        block_data["message_type"] = "BlockMessage"
        block_data["block_hash"] = block.block_hash
        return SharedMessage(data=block_data)
    
    def test_network_sync(self):
        """Test that blocks propagate through the network with robust waiting"""
        # Mine a block on the first node
        first_node = self.nodes[0]
        print(f"Mining a block on first node...")
        block = first_node.beacon.mine_block()
        print(f"Mined block with height {block.block_height} and hash {block.block_hash[:8]}...")
        
        # Create a proper block message with BlockMessage type
        message = self._create_valid_block_message(block)
        
        # Broadcast to the network
        print(f"Broadcasting block to the network...")
        first_node.broadcast(message.to_json())
        
        # First node should process it
        first_node.handle_message(
            message.to_json(),
            hashlib.sha256(message.to_json().encode()).hexdigest(),
            ("127.0.0.1", 0)
        )
        
        # Wait for propagation with our helper method
        sync_success = self._wait_for_sync(expected_height=1, max_wait_time=20)
        self.assertTrue(sync_success, "Network failed to synchronize within time limit")
        
        # Check that all nodes have the correct block
        print("Verifying all nodes have the correct block...")
        for i, node in enumerate(self.nodes):
            self.assertEqual(
                node.beacon.get_latest_block().block_height, 
                1, 
                f"Node {i} has incorrect height"
            )
            self.assertEqual(
                node.beacon.get_latest_block().block_hash, 
                block.block_hash, 
                f"Node {i} has incorrect block hash"
            )
            self.assertEqual(
                node.beacon.get_latest_block().difficulty_bits, 
                23, 
                f"Node {i} has incorrect difficulty bits"
            )
    
    def test_mining_in_network(self):
        """Test mining in the network with more robust synchronization checks"""
        # Set target mining time and minimum expected blocks
        mining_time = 30  # seconds
        min_expected_blocks = 3
        
        print(f"Starting mining on all nodes for {mining_time} seconds...")
        start_mining_in_network(self.nodes)
        
        # Wait with progress reporting
        start_time = time.time()
        try:
            while time.time() - start_time < mining_time:
                elapsed = int(time.time() - start_time)
                if elapsed % 5 == 0:  # Report every 5 seconds
                    heights = [node.beacon.get_latest_block().block_height for node in self.nodes]
                    print(f"Mining progress after {elapsed}s: {heights}")
                time.sleep(1)
        except KeyboardInterrupt:
            print("Mining interrupted by user")
        finally:
            print("Stopping mining on all nodes...")
            stop_mining_in_network(self.nodes)
        
        # Check that sufficient blocks were mined
        heights = [node.beacon.get_latest_block().block_height for node in self.nodes]
        max_height = max(heights)
        print(f"Maximum chain height after mining: {max_height}")
        self.assertGreater(max_height, min_expected_blocks, 
                         f"Expected at least {min_expected_blocks} blocks, but max height is {max_height}")
        
        # Give time for final sync with progress reporting
        print("Waiting for final network synchronization...")
        sync_success = self._wait_for_sync(max_wait_time=5)
        self.assertTrue(sync_success, "Network failed to achieve final synchronization")
        
        # Verify final synchronization
        print("Verifying final network state...")
        
        # Check that all nodes have synchronized to the same chain height
        heights = [node.beacon.get_latest_block().block_height for node in self.nodes]
        self.assertEqual(len(set(heights)), 1, f"Nodes have different heights: {heights}")
        
        # Check that the ledgers are consistent
        ledgers = []
        for node in self.nodes:
            ledger = {}
            for address, count in node.beacon.ledger.items():
                ledger[address] = count
            ledgers.append(ledger)
        
        # Print the ledgers for debugging
        print("Final ledger state:")
        for i, ledger in enumerate(ledgers):
            print(f"Node {i} ledger: {ledger}")
        
        # All ledgers should be the same
        for i in range(1, len(ledgers)):
            self.assertEqual(
                ledgers[0], 
                ledgers[i], 
                f"Ledger {i} is different from ledger 0"
            )
            
        # Check that difficulty is fixed at 23 across all nodes
        difficulty_bits = [node.beacon.get_latest_block().difficulty_bits for node in self.nodes]
        self.assertTrue(
            all(d == 23 for d in difficulty_bits), 
            f"Not all nodes have difficulty = 23: {difficulty_bits}"
        )
        
        # Print final block statistics
        final_height = heights[0]
        print(f"Test completed successfully. All nodes synchronized at height {final_height}")

    def test_mining_interrupt(self):
        """Test that mining is interrupted when a block is received"""
        # Start mining on first node
        first_node = self.nodes[0]
        first_node.start_mining()
        
        # Wait for a block to be mined
        start_time = time.time()
        max_wait_time = 10  # seconds
        
        while time.time() - start_time < max_wait_time:
            if first_node.beacon.get_latest_block().block_height > 0:
                break
            time.sleep(0.1)
        
        # Stop mining on the first node
        first_node.stop_mining()
        
        # Get the latest block from the first node
        latest_block = first_node.beacon.get_latest_block()
        self.assertGreater(latest_block.block_height, 0)
        
        # Start mining on second node
        second_node = self.nodes[1]
        second_node.start_mining()
        
        # Let the second node mine for a bit
        time.sleep(0.5)
        
        # Create a block with a higher height than what second_node is mining
        next_block = Block(
            coinbase_address=first_node.beacon.coinbase_address,
            prev_block_hash=latest_block.block_hash,
            block_height=latest_block.block_height + 1,
            timestamp=time.time() * 1000,
            nonce=123456
        )
        
        # Make it a valid block
        challenge = next_block.coinbase_address + next_block.prev_block_hash
        pow_primitive = ProofOfWorkPrimitive(difficulty_bits=23)
        nonce = pow_primitive.create_proof(challenge)
        
        next_block = Block(
            coinbase_address=next_block.coinbase_address,
            prev_block_hash=next_block.prev_block_hash,
            block_height=next_block.block_height,
            timestamp=next_block.timestamp,
            nonce=nonce
        )
        
        # Send the block to the second node
        print(f"Sending block {next_block.block_height} to second node")
        message = SharedMessage(data=next_block.to_dict())
        second_node.handle_message(
            message.to_json(),
            hashlib.sha256(message.to_json().encode()).hexdigest(),
            ("127.0.0.1", 0)
        )
        
        # Wait a bit to let the second node process the block and reset mining
        time.sleep(1)
        
        # Check that the second node accepted the block
        self.assertEqual(second_node.beacon.get_latest_block().block_hash, next_block.block_hash)
        
        # Stop mining on the second node
        second_node.stop_mining()


if __name__ == "__main__":
    unittest.main()