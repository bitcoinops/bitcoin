#!/usr/bin/env python3
# Copyright (c) 2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test taptree construction."""
from io import BytesIO
import random

from test_framework.address import program_to_witness
from test_framework.key import ECKey
from test_framework.messages import CTransaction, COutPoint, CTxIn, CTxOut, CTxInWitness, ser_string
from test_framework.script import TapTree, TapLeaf, TaprootSignatureHash, TaggedHash
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import hex_str_to_bytes, assert_equal

def tx_from_hex(hexstring):
    tx = CTransaction()
    f = BytesIO(hex_str_to_bytes(hexstring))
    tx.deserialize(f)
    return tx

class taptree_constructor(BitcoinTestFramework):

    def set_test_params(self):
        self.num_nodes = 1

    def run_test(self):
        self.nodes[0].generate(101)
        bal = self.nodes[0].getbalance()

        for n in range(1, 10):
            sec_map = {}
            pkv = []
            for _ in range(n):
                sec = ECKey()
                sec.generate()
                pkv.append(sec.get_pubkey())
                sec_map[pkv[-1]] = sec

            # Generate scripts
            pk_tapleafs = []
            tapscript_pk_map = {}
            for pk in pkv:
                tl = TapLeaf()
                tl.from_keys([pk])
                pk_tapleafs.append(tl)
                tapscript_pk_map[tl.script] = pk

            # csa_tapleafs, _ = TapLeaf.generate_threshold_csa(n, pkv[:m])
            tapleafs = pk_tapleafs

            # Build Tree.
            taptree = TapTree()
            int_sec = ECKey()
            int_sec.generate()
            int_pubkey = int_sec.get_pubkey()
            policy = []
            for tapleaf in tapleafs:
                policy.append((random.randint(1, 10), tapleaf))
            taptree.huffman_constructor(policy)
            taptree.key = int_pubkey

            # Construct output.
            script, tweak, control_map = taptree.construct()
            addr = program_to_witness(1, script[2:])
            outputs = {}
            outputs[addr] = bal / 100000

            # Verify Controlblock.
            for tapleaf in tapleafs:
                control = control_map[tapleaf.script]
                version = control[0] & 0xfe
                int_pubkey_b = bytes([(control[0] & 0x01) + 2]) + control[1:33]
                m = len(control[33:]) // 32
                k = TaggedHash("TapLeaf", bytes([version]) + ser_string(tapleaf.script))
                for i in range(m):
                    e = control[33 + 32 * i:65 + 32 * i]
                    if k < e:
                        k = TaggedHash("TapBranch", k + e)
                    else:
                        k = TaggedHash("TapBranch", e + k)
                t = TaggedHash("TapTweak", int_pubkey_b + k)
                assert_equal(t, tweak)

            # Send to taproot output.
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

            # Test each Script Path.
            for tapleaf_to_spend in tapleafs:

                # Generate spending transaction
                # [version][in][][locktime]
                taproot_spend_tx = CTransaction()
                taproot_spend_tx.nVersion = 1
                taproot_spend_tx.nLockTime = 0
                funding_tx.rehash()
                taproot_output_point = COutPoint(funding_tx.sha256, taproot_index)
                tx_input = CTxIn(outpoint=taproot_output_point)
                taproot_spend_tx.vin = [tx_input]

                # Spend amount back to wallet.
                # [version][in][out][locktime]
                dest_addr = self.nodes[0].getnewaddress(address_type="bech32")
                spk = hex_str_to_bytes(self.nodes[0].getaddressinfo(dest_addr)['scriptPubKey'])
                min_fee = 5000
                dest_out = CTxOut(nValue=taproot_value - min_fee, scriptPubKey=spk)
                taproot_spend_tx.vout = [dest_out]

                htv = [0, 1, 2, 3, 0x81, 0x82, 0x83]
                htv_idx = random.randint(0, len(htv) - 1)
                sighash = TaprootSignatureHash(taproot_spend_tx, [taproot_output], htv[htv_idx], 0, scriptpath=True, tapscript=tapleaf_to_spend.script)

                # Determine signatures and publickeys necessary to spend this tapscript.
                pk = tapscript_pk_map[tapleaf_to_spend.script]
                sec = sec_map[pk]
                sig = sec.sign_schnorr(sighash)
                taproot_spend_tx.wit.vtxinwit.append(CTxInWitness())

                # 65B signature required for non-zero hash_type.
                if htv_idx is not 0:
                    sig += htv[htv_idx].to_bytes(1, 'big')
                taproot_spend_tx.wit.vtxinwit[0].scriptWitness.stack = [sig] + [tapleaf_to_spend.script, control_map[tapleaf_to_spend.script]]
                taproot_spend_str = taproot_spend_tx.serialize().hex()

                assert_equal(
                    [{'txid': taproot_spend_tx.rehash(), 'allowed': True}],
                    self.nodes[0].testmempoolaccept([taproot_spend_str])
                )

if __name__ == '__main__':
    taptree_constructor().main()
