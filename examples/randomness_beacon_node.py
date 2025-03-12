import json
import hashlib
import time
import threading
from typing import List, Dict, Optional, Tuple, Any, Callable

from shared_message import SharedMessage
from chaincraft import ChaincraftNode
from examples.randomness_beacon import RandomnessBeacon, Block, generate_eth_address

# Backoff time between sync attempts (seconds)
SYNC_BACKOFF_TIME = 2

class RandomnessBeaconNode(ChaincraftNode):
    """
    A node in the randomness beacon network.
    """
    
    def __init__(
        self,
        coinbase_address: Optional[str] = None,
        **kwargs
    ):
        """
        Initialize a randomness beacon node.
        
        Args:
            coinbase_address: The address of this node. If None, a random address will be generated.
            **kwargs: Additional arguments to pass to the ChaincraftNode constructor.
        """
        super().__init__(**kwargs)
        
        # Create a randomness beacon shared object
        self.beacon = RandomnessBeacon(coinbase_address=coinbase_address)
        
        # Add the beacon as a shared object
        self.add_shared_object(self.beacon)
        
        # Mining thread
        self.mining_thread = None
        self.is_mining = False
        
        # Add a mining interruption event
        self.mining_interrupt = threading.Event()
        
        # Track the latest block height being mined
        self.mining_block_height = 0
        
        # Add a synchronization thread
        self.sync_thread = None
        self.should_sync = False
        self.last_sync_time = 0
        
        # Add a lock for thread safety
        self.lock = threading.RLock()
    
    def start(self) -> None:
        """Start the node and begin periodic synchronization"""
        super().start()
        self.should_sync = True
        self.sync_thread = threading.Thread(target=self._periodic_sync, daemon=True)
        self.sync_thread.start()
    
    def close(self) -> None:
        """Stop the node and all threads"""
        self.should_sync = False
        self.stop_mining()
        if self.sync_thread:
            self.sync_thread.join(timeout=1)
        super().close()
    
    def start_mining(self) -> None:
        """Start the mining thread"""
        with self.lock:
            if not self.mining_thread or not self.mining_thread.is_alive():
                self.is_mining = True
                self.mining_interrupt.clear()
                self.mining_thread = threading.Thread(target=self._mine_blocks, daemon=True)
                self.mining_thread.start()
                print(f"Mining started on node with address {self.beacon.coinbase_address[:10]}...")
    
    def stop_mining(self) -> None:
        """Stop the mining thread"""
        with self.lock:
            if self.is_mining:
                self.is_mining = False
                self.mining_interrupt.set()  # Signal the mining thread to interrupt
                if self.mining_thread:
                    self.mining_thread.join(timeout=1)
                    self.mining_thread = None
                print("Mining stopped")
    
    def handle_message(self, message_json: str, message_hash: str, peer_address: Tuple[str, int]) -> None:
        """
        Handle a message from a peer.
        Override to add interruption of mining when a valid block is received.
        
        Args:
            message_json: The JSON string of the message.
            message_hash: The hash of the message.
            peer_address: The address of the peer that sent the message.
        """
        # Parse the message
        try:
            # Parse the message as a shared message
            shared_message = SharedMessage.from_json(message_json)
            
            # Check if this is potentially a block message
            if shared_message.data is not None and isinstance(shared_message.data, dict):
                # Check if it's a BlockMessage type
                if shared_message.data.get("message_type") == "BlockMessage":
                    # Get the current mining height
                    with self.lock:
                        current_mining_height = self.mining_block_height
                    
                    block_data = shared_message.data
                    if 'block_height' in block_data:
                        current_height = self.beacon.get_latest_block().block_height
                        incoming_height = block_data['block_height']
                        
                        # If the incoming block is for a height we're currently mining
                        # or for a future height, interrupt mining
                        if incoming_height >= current_mining_height:
                            print(f"Received block for height {incoming_height}, interrupting mining at height {current_mining_height}")
                            with self.lock:
                                self.mining_interrupt.set()
            
            # Process the message normally after checking
            super().handle_message(message_json, message_hash, peer_address)
            
            # After processing, reset interrupt flag and restart mining if needed
            if self.is_mining and self.mining_interrupt.is_set():
                with self.lock:
                    self.mining_interrupt.clear()
                
        except Exception as e:
            print(f"Error handling message: {e}")
            import traceback
            traceback.print_exc()
    
    def _mine_blocks(self) -> None:
        """Mine blocks continuously"""
        print(f"Starting mining thread with address {self.beacon.coinbase_address[:10]}...")
        
        while self.is_mining and self.is_running:
            try:
                # Update the block height we're mining for
                with self.lock:
                    self.mining_block_height = self.beacon.get_latest_block().block_height + 1
                    current_mining_height = self.mining_block_height
                
                print(f"Mining block at height {current_mining_height}...")
                
                # Create an interrupt callback
                def should_interrupt():
                    return self.mining_interrupt.is_set()
                
                # Mine a new block with interrupt support
                new_block = self.beacon.mine_block(interrupt_callback=should_interrupt)
                
                # If mining was interrupted, skip this iteration
                if new_block is None:
                    print("Mining was interrupted")
                    continue
                
                print(f"Found a valid block at height {new_block.block_height} with hash {new_block.block_hash[:8]}")
                
                # Create a message with the block
                block_data = new_block.to_dict()
                block_data["block_hash"] = new_block.block_hash  # Explicitly include the hash
                block_message = SharedMessage(data=block_data)
                
                # Send the block to all peers
                print(f"Broadcasting block at height {new_block.block_height} to peers...")
                self.broadcast(block_message.to_json())
                
                # Also add it locally
                print(f"Adding mined block locally...")
                message_json = block_message.to_json()
                self.handle_message(
                    message_json,
                    hashlib.sha256(message_json.encode()).hexdigest(),
                    ("127.0.0.1", 0)
                )
                
                # Sleep a little to prevent flooding the network
                time.sleep(0.1)
            except Exception as e:
                print(f"Error mining block: {e}")
                import traceback
                traceback.print_exc()
                time.sleep(1)  # Sleep on error to avoid tight error loops
    
    def _periodic_sync(self) -> None:
        """Periodically sync with peers to ensure we have the latest blocks"""
        while self.should_sync and self.is_running:
            try:
                # Only sync if enough time has passed since last sync
                current_time = time.time()
                if current_time - self.last_sync_time >= SYNC_BACKOFF_TIME:
                    self.last_sync_time = current_time
                    
                    # Get our current latest digest
                    latest_digest = self.beacon.get_latest_digest()
                    
                    # Request updates from peers
                    print(f"Requesting beacon updates from peers (current digest: {latest_digest[:8]})")
                    self.request_shared_object_update("RandomnessBeacon", latest_digest)
                
                # Sleep to avoid high CPU usage
                time.sleep(1)
            except Exception as e:
                print(f"Error in periodic sync: {e}")
                time.sleep(2)  # Sleep longer on error
    
    def request_shared_object_update(self, class_name: str, digest: str) -> None:
        """
        Request updates for a shared object from peers.
        
        Args:
            class_name: The name of the shared object class.
            digest: The current digest of the object.
        """
        # Create a message to request updates
        update_request = {
            "REQUEST_SHARED_OBJECT_UPDATE": {
                "class_name": class_name,
                "digest": digest
            }
        }
        
        # Broadcast the request
        try:
            message_json = json.dumps(update_request)
            self.broadcast(message_json)
        except Exception as e:
            print(f"Error requesting shared object update: {e}")
    
    def get_randomness(self, block_height: Optional[int] = None) -> str:
        """
        Get the randomness for a specific block height.
        
        Args:
            block_height: The block height to get the randomness for.
            
        Returns:
            str: The randomness value (a hex string).
        """
        return self.beacon.get_randomness(block_height)
    
    def get_binary_randomness(self, block_height: Optional[int] = None, length: int = 256) -> str:
        """
        Get a binary string of randomness from a block.
        
        Args:
            block_height: The block height to get the randomness for.
            length: The length of the binary string to return (default: 256 bits).
            
        Returns:
            str: A binary string of random bits.
        """
        return self.beacon.get_binary_randomness(block_height, length)

# Additional utility functions for running a randomness beacon network

def create_randomness_beacon_network(num_nodes: int, topology: str = "ring") -> List[RandomnessBeaconNode]:
    """
    Create a network of randomness beacon nodes.
    
    Args:
        num_nodes: The number of nodes to create.
        topology: The network topology ("ring", "full_mesh", "star")
        
    Returns:
        List[RandomnessBeaconNode]: The list of nodes in the network.
    """
    nodes = []
    for _ in range(num_nodes):
        node = RandomnessBeaconNode(
            persistent=False,
            debug=False
        )
        node.start()
        nodes.append(node)
    
    # Connect the nodes based on the specified topology
    if topology == "ring":
        # Ring topology: each node connects to its neighbors in a ring
        for i in range(num_nodes):
            next_node = (i + 1) % num_nodes
            nodes[i].connect_to_peer(nodes[next_node].host, nodes[next_node].port)
            nodes[next_node].connect_to_peer(nodes[i].host, nodes[i].port)
    elif topology == "full_mesh":
        # Full mesh: every node connects to every other node
        for i in range(num_nodes):
            for j in range(i + 1, num_nodes):
                nodes[i].connect_to_peer(nodes[j].host, nodes[j].port)
                nodes[j].connect_to_peer(nodes[i].host, nodes[i].port)
    elif topology == "star":
        # Star topology: all nodes connect to the first node
        for i in range(1, num_nodes):
            nodes[0].connect_to_peer(nodes[i].host, nodes[i].port)
            nodes[i].connect_to_peer(nodes[0].host, nodes[0].port)
    
    # Give some time for connections to establish
    time.sleep(2)
    
    # Force initial synchronization by broadcasting from each node
    for node in nodes:
        node.request_shared_object_update("RandomnessBeacon", node.beacon.get_latest_digest())
    
    return nodes


def start_mining_in_network(nodes: List[RandomnessBeaconNode], staggered: bool = True) -> None:
    """
    Start mining in all nodes in the network.
    
    Args:
        nodes: The list of nodes in the network.
        staggered: If True, start mining with a delay between nodes to avoid simultaneous starts.
    """
    for i, node in enumerate(nodes):
        if staggered:
            # Slightly stagger the mining start to reduce collisions
            time.sleep(0.5)  
        node.start_mining()
        print(f"Started mining on node {i}")


def stop_mining_in_network(nodes: List[RandomnessBeaconNode]) -> None:
    """
    Stop mining in all nodes in the network.
    
    Args:
        nodes: The list of nodes in the network.
    """
    for node in nodes:
        node.stop_mining()


def force_network_sync(nodes: List[RandomnessBeaconNode]) -> None:
    """
    Force synchronization between all nodes in the network.
    
    Args:
        nodes: The list of nodes in the network.
    """
    print("Forcing network synchronization...")
    
    # Have each node request updates
    for node in nodes:
        node.request_shared_object_update("RandomnessBeacon", node.beacon.get_latest_digest())
    
    # Give time for messages to propagate
    time.sleep(2)
    
    # Check if additional sync rounds are needed
    heights = [node.beacon.get_latest_block().block_height for node in nodes]
    if len(set(heights)) > 1:
        print(f"Nodes still at different heights: {heights}")
        # Try again with the node that has the highest block
        max_height = max(heights)
        max_height_nodes = [nodes[i] for i in range(len(nodes)) if heights[i] == max_height]
        
        for node in max_height_nodes:
            latest_digest = node.beacon.get_latest_digest()
            print(f"Broadcasting from node with max height {max_height}, digest {latest_digest[:8]}")
            node.request_shared_object_update("RandomnessBeacon", latest_digest)
        
        # Give time for messages to propagate
        time.sleep(2)


def wait_for_network_convergence(nodes: List[RandomnessBeaconNode], max_wait_time: int = 60, check_interval: float = 1.0) -> bool:
    """
    Wait for all nodes in the network to converge to the same chain height.
    
    Args:
        nodes: The list of nodes in the network.
        max_wait_time: Maximum time to wait in seconds.
        check_interval: How often to check convergence.
        
    Returns:
        bool: True if convergence was achieved, False if timed out.
    """
    print(f"Waiting for network convergence (max {max_wait_time} seconds)...")
    
    start_time = time.time()
    last_force_sync = 0
    
    while time.time() - start_time < max_wait_time:
        # Get current heights of all nodes
        heights = [node.beacon.get_latest_block().block_height for node in nodes]
        heights_str = ", ".join([str(h) for h in heights])
        
        if len(set(heights)) == 1:
            # All nodes have the same height
            print(f"Network converged at height {heights[0]}")
            
            # Verify that all nodes have the same chain tip
            digests = [node.beacon.get_latest_digest() for node in nodes]
            if len(set(digests)) == 1:
                print(f"All nodes have the same chain tip: {digests[0][:8]}")
                return True
            else:
                # Nodes have same height but different blocks - force sync
                print(f"Nodes have same height but different blocks. Force syncing...")
                force_network_sync(nodes)
        else:
            print(f"Node heights: {heights_str}")
            
            # Force sync every 10 seconds if not converged
            current_time = time.time()
            if current_time - last_force_sync >= 10:
                force_network_sync(nodes)
                last_force_sync = current_time
        
        time.sleep(check_interval)
    
    # If we get here, convergence timed out
    print(f"Network convergence timed out after {max_wait_time} seconds")
    heights = [node.beacon.get_latest_block().block_height for node in nodes]
    print(f"Final heights: {heights}")
    return False


def close_network(nodes: List[RandomnessBeaconNode]) -> None:
    """
    Close all nodes in the network.
    
    Args:
        nodes: The list of nodes in the network.
    """
    print("Closing network...")
    stop_mining_in_network(nodes)
    time.sleep(1)  # Give time for mining to stop
    
    for node in nodes:
        try:
            node.close()
        except Exception as e:
            print(f"Error closing node: {e}")


def print_network_state(nodes: List[RandomnessBeaconNode]) -> None:
    """
    Print the current state of the network.
    
    Args:
        nodes: The list of nodes in the network.
    """
    print("\nCurrent network state:")
    for i, node in enumerate(nodes):
        latest_block = node.beacon.get_latest_block()
        address = node.beacon.coinbase_address
        print(f"Node {i} (address: {address[:10]}...): " +
              f"Chain height: {latest_block.block_height}, " +
              f"Latest block: {latest_block.block_hash[:8]}, " +
              f"Mined blocks: {node.beacon.ledger.get(address, 0)}")


def test_network(num_nodes: int = 3, mining_time: int = 30, topology: str = "ring") -> None:
    """
    Test the randomness beacon network.
    
    Args:
        num_nodes: The number of nodes to create.
        mining_time: The number of seconds to mine for.
        topology: The network topology to use.
    """
    print(f"Creating a {topology} network of {num_nodes} nodes...")
    nodes = create_randomness_beacon_network(num_nodes, topology)
    
    print(f"Starting mining for {mining_time} seconds...")
    start_mining_in_network(nodes)
    
    # Wait for mining to happen
    try:
        for i in range(mining_time):
            if i % 5 == 0:  # Every 5 seconds
                print_network_state(nodes)
            time.sleep(1)
        
        # Stop mining
        print("Stopping mining...")
        stop_mining_in_network(nodes)
        
        # Wait for final convergence
        wait_for_network_convergence(nodes, max_wait_time=30)
        
        # Print final state
        print("\nFinal network state:")
        print_network_state(nodes)
        
        # Verify that all ledgers are consistent
        ledgers = []
        for node in nodes:
            ledger = {}
            for address, count in node.beacon.ledger.items():
                ledger[address] = count
            ledgers.append(ledger)
        
        # Check if all ledgers are the same
        if all(ledger == ledgers[0] for ledger in ledgers):
            print("All ledgers are consistent!")
        else:
            print("WARNING: Ledgers are inconsistent!")
            for i, ledger in enumerate(ledgers):
                print(f"Node {i} ledger: {ledger}")
        
    finally:
        print("Closing network...")
        close_network(nodes)