"""Tests for the PSBT implementation."""

import unittest
from bitcoinutils.setup import setup
from bitcoinutils.transactions import Transaction, TxInput, TxOutput
from bitcoinutils.keys import PrivateKey, P2pkhAddress
from bitcoinutils.script import Script
from bitcoinutils.psbt import PSBT, PSBTError
from bitcoinutils.utils import to_satoshis

class TestPSBT(unittest.TestCase):
    def setUp(self):
        setup('testnet')
        
        # Test keys
        self.sk1 = PrivateKey.from_wif('cTALNpTpRbbxTCJ2A5Vq88UxT44w1PE2cYqiB3n4hRvzyCev1Wwo')
        self.sk2 = PrivateKey.from_wif('cRvyLwCPLU88jsyj94L7iJjQX5C2f8koG4G2gevN4BeSGcEvfKe9')
        
        # Test addresses
        self.addr1 = self.sk1.get_public_key().get_address()
        self.addr2 = self.sk2.get_public_key().get_address()
        
        # Create test transaction
        self.txin = TxInput('76464c2b9e2af4d63ef38a77964b3b77e629dddefc5cb9eb1a3645b1608b790f', 0)
        self.txout = TxOutput(to_satoshis(0.1), self.addr1.to_script_pub_key())
        self.tx = Transaction([self.txin], [self.txout])

    def test_create_psbt(self):
        """Test creating a new PSBT."""
        psbt = PSBT(self.tx)
        self.assertEqual(len(psbt.inputs), 1)
        self.assertEqual(len(psbt.outputs), 1)
        self.assertEqual(psbt.version, 0)

    def test_serialize_deserialize(self):
        """Test PSBT serialization and deserialization."""
        psbt = PSBT(self.tx)
        serialized = psbt.serialize()
        deserialized = PSBT.from_bytes(serialized)
        
        self.assertEqual(deserialized.version, psbt.version)
        self.assertEqual(len(deserialized.inputs), len(psbt.inputs))
        self.assertEqual(len(deserialized.outputs), len(psbt.outputs))
        self.assertEqual(deserialized.tx.serialize(), psbt.tx.serialize())

    def test_combine(self):
        """Test combining two PSBTs."""
        psbt1 = PSBT(self.tx)
        psbt2 = PSBT(self.tx)
        
        # Add different data to each PSBT
        psbt1.inputs[0][0x00] = b'test1'
        psbt2.inputs[0][0x01] = b'test2'
        
        psbt1.combine(psbt2)
        
        self.assertEqual(psbt1.inputs[0][0x00], b'test1')
        self.assertEqual(psbt1.inputs[0][0x01], b'test2')

    def test_sign(self):
        """Test signing a PSBT."""
        psbt = PSBT(self.tx)
        
        # Add UTXO info
        prev_tx = Transaction([TxInput('0000000000000000000000000000000000000000000000000000000000000000', 0)],
                            [TxOutput(to_satoshis(1.0), self.addr1.to_script_pub_key())])
        psbt.inputs[0][0x00] = prev_tx.serialize().encode()
        
        signed = psbt.sign(self.sk1)
        self.assertEqual(signed, 1)
        self.assertIn(0x02, psbt.inputs[0])  # Check for partial signature

    def test_finalize_extract(self):
        """Test finalizing and extracting transaction from PSBT."""
        psbt = PSBT(self.tx)
        
        # Add UTXO info
        prev_tx = Transaction([TxInput('0000000000000000000000000000000000000000000000000000000000000000', 0)],
                            [TxOutput(to_satoshis(1.0), self.addr1.to_script_pub_key())])
        psbt.inputs[0][0x00] = prev_tx.serialize().encode()
        
        # Sign
        psbt.sign(self.sk1)
        
        # Finalize
        psbt.finalize()
        
        # Extract
        final_tx = psbt.extract()
        self.assertIsInstance(final_tx, Transaction)
        self.assertEqual(len(final_tx.inputs), 1)
        self.assertEqual(len(final_tx.outputs), 1)

if __name__ == '__main__':
    unittest.main()
