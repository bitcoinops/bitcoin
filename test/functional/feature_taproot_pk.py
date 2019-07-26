#!/usr/bin/env python3
# Copyright (c) 2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test pubkey descriptors for taproot outputs."""
import hashlib
from io import BytesIO
import random

from test_framework.address import program_to_witness
from test_framework.key import ECKey
from test_framework.messages import COutPoint, CTxIn, CTxOut, CTxInWitness
from test_framework.script import TapLeaf, TapTree, CTransaction, TaprootSignatureHash
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, hex_str_to_bytes

def tx_from_hex(hexstring):
    tx = CTransaction()
    f = BytesIO(hex_str_to_bytes(hexstring))
    tx.deserialize(f)
    return tx

class tapleaf_pk_desc(BitcoinTestFramework):

    def set_test_params(self):
        self.num_nodes = 1

    def run_test(self):

        self.nodes[0].generate(101)
        bal = self.nodes[0].getbalance()

        # Repeat test for random tree structure (huffman weights).
        # (Test takes a while to complete.)
        for i in range(0, 5):

            # KeyPairs.
            sec_map = {}
            pkv = []
            for _ in range(10):
                sec = ECKey()
                sec.generate()
                pkv.append(sec.get_pubkey())
                sec_map[pkv[-1].get_bytes()] = sec

            # Hash & Preimage.
            preimage = bytes.fromhex('f6dea1fafb5a58df766747091dd70eafe50119687f5e56137d054b39ce8645fa')
            h = hashlib.new('ripemd160')
            h.update(preimage)
            ripemd160_digest = h.hexdigest()

            # Timedelay in blocks
            delay = 200

            tapleafs = []

            desc1 = 'ts(pk({}))'.format(pkv[0].get_bytes().hex())
            tapleaf1 = TapLeaf()
            tapleaf1.from_desc(desc1)
            tapleafs.append(tapleaf1)
            assert(tapleaf1.desc == desc1)

            desc2 = 'ts(pkhash({},{}))'.format(pkv[0].get_bytes().hex(), ripemd160_digest)
            tapleaf2 = TapLeaf()
            tapleaf2.from_desc(desc2)
            tapleafs.append(tapleaf2)
            assert(tapleaf2.desc == desc2)

            # Index to mark beginning of timelocked tapscripts in tapleafs array.
            delayed_tapscripts_idx = 2

            desc3 = 'ts(pkolder({},{}))'.format(pkv[0].get_bytes().hex(), delay)
            tapleaf3 = TapLeaf()
            tapleaf3.from_desc(desc3)
            tapleafs.append(tapleaf3)
            assert(tapleaf3.desc == desc3)

            desc4 = 'ts(pkhasholder({},{},{}))'.format(pkv[0].get_bytes().hex(), ripemd160_digest, delay)
            tapleaf4 = TapLeaf()
            tapleaf4.from_desc(desc4)
            tapleafs.append(tapleaf4)
            assert(tapleaf4.desc == desc4)

            # Construct Taptree with all tapscripts.
            taptree = TapTree()
            taptree.key = pkv[1]
            policy = []
            for tapleaf in tapleafs:
                policy.append((random.randint(1, 10), tapleaf))
            taptree.huffman_constructor(policy)

            # Send to segwit v1 output.
            script, tweak, control_map = taptree.construct()
            addr = program_to_witness(1, script[2:])
            outputs = {}
            outputs[addr] = bal / 100000
            funding_txid_str = self.nodes[0].sendmany("", outputs)
            funding_tx_str = self.nodes[0].getrawtransaction(funding_txid_str)
            funding_tx = tx_from_hex(funding_tx_str)

            # Determine which output is taproot output.
            taproot_index = 0
            utxos = funding_tx.vout
            taproot_output = utxos[taproot_index]
            while (taproot_output.scriptPubKey != script):
                taproot_index += 1
                taproot_output = utxos[taproot_index]
            taproot_value = taproot_output.nValue

            # Generate Transaction for each tapscript spend.
            delayed_txns = []
            for idx, tapleaf_to_spend in enumerate(tapleafs):

                taproot_spend_tx = CTransaction()
                taproot_spend_tx.nLockTime = 0
                funding_tx.rehash()
                taproot_output_point = COutPoint(funding_tx.sha256, taproot_index)

                if idx < delayed_tapscripts_idx:
                    taproot_spend_tx.nVersion = 1
                    tx_input = CTxIn(outpoint=taproot_output_point)
                else:
                    taproot_spend_tx.nVersion = 2
                    tx_input = CTxIn(outpoint=taproot_output_point, nSequence=delay)

                taproot_spend_tx.vin = [tx_input]
                dest_addr = self.nodes[0].getnewaddress(address_type="bech32")
                spk = hex_str_to_bytes(self.nodes[0].getaddressinfo(dest_addr)['scriptPubKey'])
                min_fee = 5000
                dest_out = CTxOut(nValue=taproot_value - min_fee, scriptPubKey=spk)
                taproot_spend_tx.vout = [dest_out]

                # Construct witness according to required satisfaction elements.
                htv = [0, 1, 2, 3, 0x81, 0x82, 0x83]
                sighash = TaprootSignatureHash(taproot_spend_tx, [taproot_output], htv[0], 0, scriptpath=True, tapscript=tapleaf_to_spend.script)
                witness_elements = []
                for typ, data in tapleaf_to_spend.sat:
                    if typ == 'preimage':
                        witness_elements.append(preimage)
                    elif typ == 'sig':
                        sig = sec_map[data].sign_schnorr(sighash)
                        witness_elements.append(sig)

                taproot_spend_tx.wit.vtxinwit.append(CTxInWitness())
                taproot_spend_tx.wit.vtxinwit[0].scriptWitness.stack = witness_elements + [tapleaf_to_spend.script, control_map[tapleaf_to_spend.script]]
                taproot_spend_str = taproot_spend_tx.serialize().hex()

                # Timelocked txns will fail.
                if idx < delayed_tapscripts_idx:
                    assert_equal(
                        [{'txid': taproot_spend_tx.rehash(), 'allowed': True}],
                        self.nodes[0].testmempoolaccept([taproot_spend_str])
                    )
                else:
                    assert_equal(
                        [{'txid': taproot_spend_tx.rehash(), 'allowed': False, 'reject-reason': '64: non-BIP68-final'}],
                        self.nodes[0].testmempoolaccept([taproot_spend_str])
                    )
                    delayed_txns.append(taproot_spend_tx)

            # Rebroadcast timelocked txs after delay.
            self.nodes[0].generate(delay)

            for tx in delayed_txns:
                assert_equal(
                    [{'txid': tx.rehash(), 'allowed': True}],
                    self.nodes[0].testmempoolaccept([tx.serialize().hex()])
                )

if __name__ == '__main__':
    tapleaf_pk_desc().main()
