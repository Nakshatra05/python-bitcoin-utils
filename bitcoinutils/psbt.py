"""
BIP-174 Partially Signed Bitcoin Transaction Format implementation.

This module provides the PSBT class and related functionality to work with partially
signed Bitcoin transactions according to BIP-174 specification.

Classes:
    PSBT: Main class representing a Partially Signed Bitcoin Transaction
"""

from typing import Optional, List, Dict, Any, Tuple
import struct
import hashlib
from copy import deepcopy

from bitcoinutils.transactions import Transaction, TxInput, TxOutput
from bitcoinutils.keys import PublicKey, PrivateKey
from bitcoinutils.script import Script
from bitcoinutils.utils import (
    encode_varint,
    vi_to_int,
    b_to_h,
    h_to_b,
)

# PSBT Key-Value Pair Types
PSBT_GLOBAL_UNSIGNED_TX = 0x00
PSBT_GLOBAL_XPUB = 0x01
PSBT_GLOBAL_TX_VERSION = 0x02
PSBT_GLOBAL_FALLBACK_LOCKTIME = 0x03
PSBT_GLOBAL_INPUT_COUNT = 0x04
PSBT_GLOBAL_OUTPUT_COUNT = 0x05
PSBT_GLOBAL_TX_MODIFIABLE = 0x06
PSBT_GLOBAL_VERSION = 0xFB
PSBT_GLOBAL_PROPRIETARY = 0xFC

PSBT_IN_NON_WITNESS_UTXO = 0x00
PSBT_IN_WITNESS_UTXO = 0x01
PSBT_IN_PARTIAL_SIG = 0x02
PSBT_IN_SIGHASH_TYPE = 0x03
PSBT_IN_REDEEM_SCRIPT = 0x04
PSBT_IN_WITNESS_SCRIPT = 0x05
PSBT_IN_BIP32_DERIVATION = 0x06
PSBT_IN_FINAL_SCRIPTSIG = 0x07
PSBT_IN_FINAL_SCRIPTWITNESS = 0x08
PSBT_IN_POR_COMMITMENT = 0x09
PSBT_IN_RIPEMD160 = 0x0A
PSBT_IN_SHA256 = 0x0B
PSBT_IN_HASH160 = 0x0C
PSBT_IN_HASH256 = 0x0D
PSBT_IN_PROPRIETARY = 0xFC

PSBT_OUT_REDEEM_SCRIPT = 0x00
PSBT_OUT_WITNESS_SCRIPT = 0x01
PSBT_OUT_BIP32_DERIVATION = 0x02
PSBT_OUT_PROPRIETARY = 0xFC

# PSBT Magic Bytes
PSBT_MAGIC_BYTES = b'psbt\xff'

# BIP-370 Transaction Modifiable Flags
PSBT_MOD_INPUTS = 0x01
PSBT_MOD_OUTPUTS = 0x02

class PSBTError(Exception):
    """Base exception for PSBT-related errors."""
    pass

class PSBT:
    """Represents a Partially Signed Bitcoin Transaction (PSBT).
    
    Implements BIP-174 specification for handling partially signed Bitcoin transactions.
    Supports serialization, deserialization, combining, signing, and finalizing PSBTs.
    
    Attributes:
        version (int): PSBT version number
        tx (Transaction): The unsigned transaction
        inputs (List[Dict]): List of input maps containing PSBT fields
        outputs (List[Dict]): List of output maps containing PSBT fields
        xpubs (Dict): Global xpub map
        proprietary (Dict): Global proprietary key-value pairs
        unknown (Dict): Unknown global key-value pairs
        modifiable (int): BIP-370 modifiable flags
    """

    def __init__(self, tx: Optional[Transaction] = None):
        """Initialize a new PSBT object.
        
        Args:
            tx (Transaction, optional): Unsigned transaction to base PSBT on
        """
        self.version: int = 0
        self.tx = tx if tx else Transaction([], [])
        self.inputs: List[Dict[int, bytes]] = [{} for _ in self.tx.inputs]
        self.outputs: List[Dict[int, bytes]] = [{} for _ in self.tx.outputs]
        self.xpubs: Dict[bytes, bytes] = {}
        self.proprietary: Dict[bytes, bytes] = {}
        self.unknown: Dict[bytes, bytes] = {}
        self.modifiable: int = 0

    @staticmethod
    def parse_key(key: bytes) -> Tuple[int, bytes]:
        """Parse a PSBT key and return its type and data.
        
        Args:
            key: Raw bytes of the key
            
        Returns:
            Tuple containing key type and key data
        """
        key_type = key[0]
        key_data = key[1:] if len(key) > 1 else b''
        return key_type, key_data

    def serialize(self) -> bytes:
        """Serialize PSBT to bytes according to BIP-174.
        
        Returns:
            Serialized PSBT as bytes
        """
        # Magic bytes
        out = PSBT_MAGIC_BYTES

        # Global map
        if self.tx:
            # Unsigned tx
            tx_bytes = self.tx.to_bytes(self.tx.has_segwit)
            out += encode_varint(1) + bytes([PSBT_GLOBAL_UNSIGNED_TX]) + encode_varint(len(tx_bytes)) + tx_bytes

        # Version
        out += encode_varint(1) + bytes([PSBT_GLOBAL_VERSION]) + encode_varint(1) + bytes([self.version])

        # BIP-370 modifiable flags
        if self.modifiable:
            out += encode_varint(1) + bytes([PSBT_GLOBAL_TX_MODIFIABLE]) + encode_varint(1) + bytes([self.modifiable])

        # Separator
        out += b'\x00'

        # Input map
        for psbt_in in self.inputs:
            for key_type, value in sorted(psbt_in.items()):
                out += encode_varint(1) + bytes([key_type]) + encode_varint(len(value)) + value
            out += b'\x00'

        # Output map
        for psbt_out in self.outputs:
            for key_type, value in sorted(psbt_out.items()):
                out += encode_varint(1) + bytes([key_type]) + encode_varint(len(value)) + value
            out += b'\x00'

        return out

    def to_hex(self) -> str:
        """Convert serialized PSBT to hex string.
        
        Returns:
            Hex string representation of PSBT
        """
        return b_to_h(self.serialize())

    @classmethod
    def from_bytes(cls, data: bytes) -> 'PSBT':
        """Create PSBT from bytes.
        
        Args:
            data: Raw PSBT bytes
            
        Returns:
            New PSBT instance
            
        Raises:
            PSBTError: If invalid PSBT format
        """
        if not data.startswith(PSBT_MAGIC_BYTES):
            raise PSBTError("Invalid PSBT magic bytes")

        psbt = cls()
        
        # Skip magic bytes
        pos = len(PSBT_MAGIC_BYTES)
        
        # Parse global map
        while pos < len(data):
            # Check separator
            if data[pos] == 0x00:
                pos += 1
                break
                
            # Read key
            key_len, key_len_size = vi_to_int(data[pos:])
            pos += key_len_size
            key = data[pos:pos + key_len]
            pos += key_len
            
            # Read value
            value_len, value_len_size = vi_to_int(data[pos:])
            pos += value_len_size
            value = data[pos:pos + value_len]
            pos += value_len
            
            # Parse key
            key_type, key_data = PSBT.parse_key(key)
            
            # Handle global fields
            if key_type == PSBT_GLOBAL_UNSIGNED_TX:
                psbt.tx = Transaction.from_raw(b_to_h(value))
                psbt.inputs = [{} for _ in psbt.tx.inputs]
                psbt.outputs = [{} for _ in psbt.tx.outputs]
            elif key_type == PSBT_GLOBAL_VERSION:
                psbt.version = value[0]
            elif key_type == PSBT_GLOBAL_TX_MODIFIABLE:
                psbt.modifiable = value[0]
            elif key_type == PSBT_GLOBAL_XPUB:
                psbt.xpubs[key_data] = value
            elif key_type == PSBT_GLOBAL_PROPRIETARY:
                psbt.proprietary[key_data] = value
            else:
                psbt.unknown[key] = value

        # Parse input maps
        for i in range(len(psbt.inputs)):
            while pos < len(data):
                if data[pos] == 0x00:
                    pos += 1
                    break
                    
                # Read key
                key_len, key_len_size = vi_to_int(data[pos:])
                pos += key_len_size
                key = data[pos:pos + key_len]
                pos += key_len
                
                # Read value  
                value_len, value_len_size = vi_to_int(data[pos:])
                pos += value_len_size
                value = data[pos:pos + value_len]
                pos += value_len
                
                # Parse key
                key_type, key_data = PSBT.parse_key(key)
                psbt.inputs[i][key_type] = value

        # Parse output maps
        for i in range(len(psbt.outputs)):
            while pos < len(data):
                if data[pos] == 0x00:
                    pos += 1
                    break
                    
                # Read key
                key_len, key_len_size = vi_to_int(data[pos:])
                pos += key_len_size
                key = data[pos:pos + key_len]
                pos += key_len
                
                # Read value
                value_len, value_len_size = vi_to_int(data[pos:])
                pos += value_len_size
                value = data[pos:pos + value_len]
                pos += value_len
                
                # Parse key
                key_type, key_data = PSBT.parse_key(key)
                psbt.outputs[i][key_type] = value

        return psbt

    @classmethod
    def from_hex(cls, hex_string: str) -> 'PSBT':
        """Create PSBT from hex string.
        
        Args:
            hex_string: Hex string of serialized PSBT
            
        Returns:
            New PSBT instance
        """
        return cls.from_bytes(h_to_b(hex_string))

    def combine(self, other: 'PSBT') -> None:
        """Combine this PSBT with another.
        
        Implements the PSBT combiner role from BIP-174.
        
        Args:
            other: Another PSBT to combine with this one
            
        Raises:
            PSBTError: If PSBTs are incompatible
        """
        if not isinstance(other, PSBT):
            raise PSBTError("Can only combine with another PSBT")
            
        if self.tx.serialize() != other.tx.serialize():
            raise PSBTError("Cannot combine PSBTs with different transactions")

        # Combine inputs
        for i, (self_input, other_input) in enumerate(zip(self.inputs, other.inputs)):
            for key_type, value in other_input.items():
                if key_type in self_input and self_input[key_type] != value:
                    raise PSBTError(f"Conflicting value for input {i} key type {key_type}")
                self_input[key_type] = value

        # Combine outputs
        for i, (self_output, other_output) in enumerate(zip(self.outputs, other.outputs)):
            for key_type, value in other_output.items():
                if key_type in self_output and self_output[key_type] != value:
                    raise PSBTError(f"Conflicting value for output {i} key type {key_type}")
                self_output[key_type] = value

        # Combine xpubs
        for xpub, value in other.xpubs.items():
            if xpub in self.xpubs and self.xpubs[xpub] != value:
                raise PSBTError(f"Conflicting value for xpub {xpub.hex()}")
            self.xpubs[xpub] = value

        # Combine modifiable flags
        self.modifiable |= other.modifiable

    def sign(self, key: PrivateKey) -> int:
        """Sign any unsigned inputs that can be signed with this private key.
        
        Implements the PSBT signer role from BIP-174.
        
        Args:
            key: Private key to sign with
            
        Returns:
            Number of inputs that were signed
        """
        signed = 0
        pubkey = key.get_public_key()
        pubkey_bytes = h_to_b(pubkey.to_hex())

        for i, psbt_in in enumerate(self.inputs):
            # Skip if already signed by this key
            if PSBT_IN_PARTIAL_SIG in psbt_in:
                continue

            # Get UTXO info
            if PSBT_IN_NON_WITNESS_UTXO in psbt_in:
                # Legacy input
                prev_tx = Transaction.from_raw(b_to_h(psbt_in[PSBT_IN_NON_WITNESS_UTXO]))
                utxo = prev_tx.outputs[self.tx.inputs[i].txout_index]
                script_code = utxo.script_pubkey
                
                # Sign
                sig = key.sign_input(self.tx, i, script_code)
                psbt_in[PSBT_IN_PARTIAL_SIG] = h_to_b(sig) + pubkey_bytes
                signed += 1
                
            elif PSBT_IN_WITNESS_UTXO in psbt_in:
                # Segwit input
                utxo = TxOutput.from_raw(b_to_h(psbt_in[PSBT_IN_WITNESS_UTXO]))[0]
                
                # Get correct script to sign with
                if PSBT_IN_WITNESS_SCRIPT in psbt_in:
                    script_code = Script.from_raw(b_to_h(psbt_in[PSBT_IN_WITNESS_SCRIPT]))
                else:
                    script_code = utxo.script_pubkey
                    
                # Sign
                sig = key.sign_segwit_input(self.tx, i, script_code, utxo.amount)
                psbt_in[PSBT_IN_PARTIAL_SIG] = h_to_b(sig) + pubkey_bytes
                signed += 1

        return signed

    def finalize(self) -> None:
        """Finalize this PSBT.
        
        Implements the PSBT finalizer role from BIP-174.
        Converts partial signatures and redeem scripts into final scriptSigs and witnesses.
        
        Raises:
            PSBTError: If PSBT cannot be finalized
        """
        for i, psbt_in in enumerate(self.inputs):
            if PSBT_IN_FINAL_SCRIPTSIG in psbt_in or PSBT_IN_FINAL_SCRIPTWITNESS in psbt_in:
                continue

            # Handle different input types
            if PSBT_IN_NON_WITNESS_UTXO in psbt_in:
                # Legacy input
                if PSBT_IN_PARTIAL_SIG not in psbt_in:
                    continue
                    
                sig = psbt_in[PSBT_IN_PARTIAL_SIG]
                if PSBT_IN_REDEEM_SCRIPT in psbt_in:
                    # P2SH
                    redeem_script = psbt_in[PSBT_IN_REDEEM_SCRIPT]
                    psbt_in[PSBT_IN_FINAL_SCRIPTSIG] = sig + redeem_script
                else:
                    # P2PKH
                    psbt_in[PSBT_IN_FINAL_SCRIPTSIG] = sig
                    
            elif PSBT_IN_WITNESS_UTXO in psbt_in:
                # Segwit input
                if PSBT_IN_PARTIAL_SIG not in psbt_in:
                    continue
                    
                sig = psbt_in[PSBT_IN_PARTIAL_SIG]
                witness = []
                
                if PSBT_IN_WITNESS_SCRIPT in psbt_in:
                    # P2WSH
                    witness_script = psbt_in[PSBT_IN_WITNESS_SCRIPT]
                    witness = [sig, witness_script]
                else:
                    # P2WPKH
                    witness = [sig]
                    
                psbt_in[PSBT_IN_FINAL_SCRIPTWITNESS] = encode_varint(len(witness)) + b''.join(witness)

    def extract(self) -> Transaction:
        """Extract the final signed transaction.
        
        Implements the PSBT extractor role from BIP-174.
        
        Returns:
            The final Transaction object
            
        Raises:
            PSBTError: If transaction is not fully signed
        """
        final_tx = deepcopy(self.tx)

        for i, psbt_in in enumerate(self.inputs):
            if PSBT_IN_FINAL_SCRIPTSIG in psbt_in:
                final_tx.inputs[i].script_sig = Script.from_raw(b_to_h(psbt_in[PSBT_IN_FINAL_SCRIPTSIG]))
                
            if PSBT_IN_FINAL_SCRIPTWITNESS in psbt_in:
                witness_stack = []
                witness_data = psbt_in[PSBT_IN_FINAL_SCRIPTWITNESS]
                pos = 0
                
                stack_len, size = vi_to_int(witness_data)
                pos += size
                
                for _ in range(stack_len):
                    item_len, size = vi_to_int(witness_data[pos:])
                    pos += size
                    witness_stack.append(witness_data[pos:pos + item_len])
                    pos += item_len
                    
                final_tx.witnesses.append(witness_stack)

        return final_tx

    def add_input(self, txin: TxInput) -> None:
        """Add a new input to the PSBT.
        
        Args:
            txin: The TxInput to add
            
        Raises:
            PSBTError: If inputs are not modifiable
        """
        if not (self.modifiable & PSBT_MOD_INPUTS):
            raise PSBTError("PSBT inputs are not modifiable")
            
        self.tx.inputs.append(txin)
        self.inputs.append({})

    def add_output(self, txout: TxOutput) -> None:
        """Add a new output to the PSBT.
        
        Args:
            txout: The TxOutput to add
            
        Raises:
            PSBTError: If outputs are not modifiable
        """
        if not (self.modifiable & PSBT_MOD_OUTPUTS):
            raise PSBTError("PSBT outputs are not modifiable")
            
        self.tx.outputs.append(txout)
        self.outputs.append({})

    def set_modifiable(self, inputs: bool = False, outputs: bool = False) -> None:
        """Set which parts of the PSBT are modifiable.
        
        Args:
            inputs: Whether inputs can be added
            outputs: Whether outputs can be added
        """
        self.modifiable = 0
        if inputs:
            self.modifiable |= PSBT_MOD_INPUTS
        if outputs:
            self.modifiable |= PSBT_MOD_OUTPUTS
