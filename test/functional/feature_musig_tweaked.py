#!/usr/bin/env python3
# Copyright (c) 2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test musig signing with a tweaked key."""
import hashlib
from io import BytesIO
import random

from test_framework.test_framework import BitcoinTestFramework
from test_framework.script import CScript, TaprootSignatureHash, OP_1
from test_framework.key import ECKey, generate_schnorr_nonce
from test_framework.musig import generate_musig_key, aggregate_schnorr_nonces, sign_musig, aggregate_musig_signatures
from test_framework.messages import CTransaction, COutPoint, CTxIn, CTxOut, CScriptWitness, CTxInWitness
from test_framework.util import assert_equal
from test_framework.address import program_to_witness

class key_musig_tweaked(BitcoinTestFramework):

    def set_test_params(self):
        self.num_nodes = 1

    def run_test(self):

        self.nodes[0].generate(101)
        balance = self.nodes[0].getbalance()

        # Repeat test for random number of participants/tweaking signer/hashtype
        for i in range(0, 10):

            num_participants = random.randint(2, 20)

            # Key Generation.
            keys = []
            pubkeys = []
            for _ in range(num_participants):
                private_key = ECKey()
                private_key.generate()
                public_key = private_key.get_pubkey()
                keys.append((private_key, public_key))
                pubkeys.append(public_key)

            c_map, pk_musig = generate_musig_key(pubkeys)

            keys_c = []
            for private, public in keys:
                private_c = private.mul(c_map[public])
                public_c = public.mul(c_map[public])
                keys_c.append((private_c, public_c))

            # Tweak Musig public key.
            tweak = hashlib.sha256(b'tweak').digest()
            pk_musig_tweaked = pk_musig.tweak_add(tweak)

            # Create Segwit V1 Output.
            pk_musig_tweaked_data = pk_musig_tweaked.get_bytes()
            pk_musig_tweaked_data_v1 = bytes([pk_musig_tweaked_data[0] & 1]) + pk_musig_tweaked_data[1:]
            segwit_address = program_to_witness(1, pk_musig_tweaked_data_v1)

            # Send funds to musig public key (V1 Segwit Output)
            txid = self.nodes[0].sendtoaddress(segwit_address, balance / 100000)
            tx_hex = self.nodes[0].getrawtransaction(txid)
            tx = CTransaction()
            tx.deserialize(BytesIO(bytes.fromhex(tx_hex)))
            tx.rehash()

            # Determine Segwit output sent from wallet.
            index = 0
            outputs = tx.vout
            output = outputs[index]
            while (output.scriptPubKey != CScript([OP_1, pk_musig_tweaked_data_v1])):
                index += 1
                output = outputs[index]
            output_value = output.nValue

            tx_schnorr = CTransaction()
            tx_schnorr.nVersion = 1
            tx_schnorr.nLockTime = 0
            outpoint = COutPoint(tx.sha256, index)
            tx_schnorr_in = CTxIn(outpoint=outpoint)
            tx_schnorr.vin = [tx_schnorr_in]

            dest_addr = self.nodes[0].getnewaddress(address_type="bech32")
            scriptpubkey = bytes.fromhex(self.nodes[0].getaddressinfo(dest_addr)['scriptPubKey'])
            min_fee = int(self.nodes[0].getmempoolinfo()['mempoolminfee'] * 100000000)
            dest_output = CTxOut(nValue=output_value - min_fee, scriptPubKey=scriptpubkey)
            tx_schnorr.vout = [dest_output]

            # Generate Sighash for signing.
            hash_types = [0, 1, 2, 3, 0x81, 0x82, 0x83]
            hash_idx = random.randint(0, len(hash_types) - 1)
            sighash = TaprootSignatureHash(tx_schnorr, [output], hash_types[hash_idx])

            # Nonce creation.
            nonce_map = {}
            nonce_points = []
            for private_c, public_c in keys_c:
                nonce_map[public_c] = generate_schnorr_nonce()
                nonce_points.append(nonce_map[public_c].get_pubkey())

            R_agg, negated = aggregate_schnorr_nonces(nonce_points)

            # Negate all individual nonces if R_agg was negated.
            if negated:
                for pk, _ in nonce_map.items():
                    nonce_map[pk].negate()

            # Musig Signing.
            sigs = []
            tweak_idx = random.randint(0, len(keys_c) - 1)
            for idx, (private_c, public_c) in enumerate(keys_c):
                # One person must tweak keys.
                private_c = private_c.tweak_add(tweak) if idx == tweak_idx else private_c
                signature = sign_musig(private_c, nonce_map[public_c], R_agg, pk_musig_tweaked, sighash)
                sigs.append(signature)
            sig_agg = aggregate_musig_signatures(sigs)

            if hash_idx is not 0:
                sig_agg += hash_types[hash_idx].to_bytes(1, 'big')

            # Construct transaction witness.
            witness = CScriptWitness()
            witness.stack.append(sig_agg)
            witness_in = CTxInWitness()
            witness_in.scriptWitness = witness
            tx_schnorr.wit.vtxinwit.append(witness_in)

            # Serialize transaction for broadcast.
            tx_schnorr_str = tx_schnorr.serialize().hex()
            assert_equal(
                [{'txid': tx_schnorr.rehash(), 'allowed': True}],
                self.nodes[0].testmempoolaccept([tx_schnorr_str])
            )

if __name__ == '__main__':
    key_musig_tweaked().main()
