from typing import Dict, Optional, Any
import json
import hashlib

from shared_message import SharedMessage


class BlockMessage(SharedMessage):
    """
    A specialized message type for transmitting blocks in the randomness beacon network.
    This extends SharedMessage to enforce structure and type safety for block data.
    """
    
    MESSAGE_TYPE = "block"
    
    def __init__(
        self,
        coinbase_address: str,
        prev_block_hash: str,
        block_height: int,
        timestamp: float,
        nonce: int,
        difficulty_bits: int,
        block_hash: Optional[str] = None,
        message_id: Optional[str] = None
    ):
        """
        Initialize a block message with the required block fields.
        
        Args:
            coinbase_address: The coinbase address of the block
            prev_block_hash: The hash of the previous block
            block_height: The height of the block
            timestamp: The timestamp of the block
            nonce: The nonce used for proof of work
            difficulty_bits: The difficulty bits for proof of work
            block_hash: The hash of the block (optional)
            message_id: Optional message ID
        """
        # Create block data dictionary
        block_data = {
            'coinbase_address': coinbase_address,
            'prev_block_hash': prev_block_hash,
            'block_height': block_height,
            'timestamp': timestamp,
            'nonce': nonce,
            'difficulty_bits': difficulty_bits
        }
        
        # Add block hash if provided
        if block_hash:
            block_data['block_hash'] = block_hash
            
        # Initialize with structured data and message type
        super().__init__(
            data=block_data,
            message_type=self.MESSAGE_TYPE,
            message_id=message_id
        )
    
    @classmethod
    def from_block(cls, block: Any) -> 'BlockMessage':
        """
        Create a BlockMessage from a Block object.
        
        Args:
            block: The Block object to convert
            
        Returns:
            BlockMessage: A new block message
        """
        return cls(
            coinbase_address=block.coinbase_address,
            prev_block_hash=block.prev_block_hash,
            block_height=block.block_height,
            timestamp=block.timestamp,
            nonce=block.nonce,
            difficulty_bits=block.difficulty_bits,
            block_hash=block.block_hash
        )
    
    @classmethod
    def from_dict(cls, block_dict: Dict[str, Any]) -> 'BlockMessage':
        """
        Create a BlockMessage from a dictionary.
        
        Args:
            block_dict: Dictionary containing block data
            
        Returns:
            BlockMessage: A new block message
        """
        # Extract optional block_hash
        block_hash = block_dict.get('block_hash')
        
        return cls(
            coinbase_address=block_dict['coinbase_address'],
            prev_block_hash=block_dict['prev_block_hash'],
            block_height=block_dict['block_height'],
            timestamp=block_dict['timestamp'],
            nonce=block_dict['nonce'],
            difficulty_bits=block_dict['difficulty_bits'],
            block_hash=block_hash
        )
    
    @classmethod
    def from_shared_message(cls, message: SharedMessage) -> Optional['BlockMessage']:
        """
        Convert a generic SharedMessage to a BlockMessage if possible.
        
        Args:
            message: The SharedMessage to convert
            
        Returns:
            Optional[BlockMessage]: A BlockMessage if conversion was successful, None otherwise
        """
        # Check if this is a block message
        if message.message_type != cls.MESSAGE_TYPE:
            return None
            
        # Check if data contains all required fields
        required_fields = [
            'coinbase_address', 'prev_block_hash', 'block_height',
            'timestamp', 'nonce', 'difficulty_bits'
        ]
        
        if not message.data or not all(field in message.data for field in required_fields):
            return None
            
        # Create a new BlockMessage
        return cls.from_dict(message.data)
    
    def get_block_data(self) -> Dict[str, Any]:
        """
        Get the block data from this message.
        
        Returns:
            Dict[str, Any]: The block data
        """
        return self.data