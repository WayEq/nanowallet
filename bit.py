# MIT License
#
# Copyright (c) 2017 https://github.com/WayEq
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.


#!/usr/bin/python 

import bitcoin
import hashlib
import hmac
import urllib.request
import json
import re
import struct
import enum
import os
import bitarray


debug_mode = True
query_blockchain = True

# Constants
bits_per_word = 11
acceptable_word_counts = [12, 15, 18, 21, 24]
hardened_index_offset = 2 ** 31
extended_public_key_version_bytes = b"\x04\x88\xB2\x1E"
extended_private_key_version_bytes = b"\x04\x88\xAD\xE4"
testnet_magic_byte = 0x6F
public_magic_byte = 0x00
testnet_wif_prefix = 0xEF
public_wif_prefix = 0x80


class Network(enum.Enum):
    MAINNET = 0
    TESTNET = 1


class KeyType(enum.Enum):
    PUBLIC = 0
    PRIVATE = 1


class ShiftableBitArray(bitarray.bitarray):
    def __lshift__(self, count):
        return self[count:] + type(self)('0') * count

    def __rshift__(self, count):
        return type(self)('0') * count + self[:-count]

    def __repr__(self):
        return "{}('{}')".format(type(self).__name__, self.to01())


def exit_with_error(error):
    print(error)
    exit(-1)


def debug_print(message):
    if debug_mode:
        print(message)


def validate_mnemonic(words, lines):
    if len(words) not in acceptable_word_counts:
        exit_with_error("Mnemonic word count must be one of: " + str(acceptable_word_counts))
    for word in words:
        if word not in lines:
            exit_with_error("Word not found in mnemonic index: " + word)


def get_buffer_length(buff):
    return str(len(buff.tobytes()))


def print_binary(buff):
    return "".join('{:08b}'.format(x) for x in buff)


def print_hex(buff):
    return "".join("{:02x}".format(c) for c in buff)


def mnemonic_to_entropy_and_checksum(words, lines):
    mnemonic_words = words.split()
    num_words = len(mnemonic_words)
    entropy_and_checksum_bit_size = num_words * bits_per_word
    nums = []
    for word in words.split():
        nums.append(lines.index(word))
    entropy_and_checksum = ShiftableBitArray(entropy_and_checksum_bit_size)
    entropy_and_checksum.setall(False)
    for num in nums:
        or_target = bitarray.bitarray(str('{0:011b}'.format(num)))
        while len(or_target) < len(entropy_and_checksum):
            or_target.insert(0, False)
        entropy_and_checksum = entropy_and_checksum << bits_per_word
        entropy_and_checksum = entropy_and_checksum | or_target
    return entropy_and_checksum


def get_checksum_bits(data, checksum_bit_length):
    m = hashlib.sha256()
    m.update(data.tobytes())
    digest = m.digest()
    return digest[0] >> 8 - checksum_bit_length


# TODO: combine these checksum methods
def binary_verify_checksum(data_and_checksum, checksum_length):
    entropy = data_and_checksum[0:-checksum_length]
    checksum = data_and_checksum[-checksum_length:]
    digest = bitcoin.bin_dbl_sha256(bytes(entropy))
    computed_checksum = digest[0:checksum_length]
    debug_print("computed: " + print_hex(digest))
    if computed_checksum != checksum:
        print("checksum failed!")


def verify_checksum(data_and_checksum, checksum_length):
    entropy = data_and_checksum[0:-checksum_length].tobytes()
    checksum = data_and_checksum[-checksum_length:].tobytes()[0] >> 8 - checksum_length
    debug_print("data: " + print_hex(entropy))
    debug_print("checksum: " + str(checksum))
    m = hashlib.sha256()
    m.update(entropy)
    digest = m.digest()
    computed_checksum = digest[0] >> 8 - checksum_length
    if computed_checksum != checksum:
        exit_with_error("checksum failed!")


def extend_key(chain_code, key):
    return chain_code + key


def derive_child_key(parent_key, parent_chain_code, index, key_type, hardened=False):
    if hardened:
        if key_type == KeyType.PUBLIC:
            exit_with_error("Can not derive a hardened public child key from parent public key")
        input_data = bytearray(b'\x00') + parent_key
    else:
        if key_type == KeyType.PUBLIC:
            input_data = bitcoin.compress(parent_key)
        else:
            public_key = bitcoin.privkey_to_pubkey(parent_key)
            input_data = bitcoin.compress(public_key)

    input_data += int(index).to_bytes(4, byteorder='big')
    key = parent_chain_code
    (key_offset, chain_code) = hmac_digest_and_split(key, input_data)
    if key_type == KeyType.PUBLIC:
        point = bitcoin.decompress(bitcoin.privkey_to_pubkey(key_offset))
        parent_point = bitcoin.decompress(parent_key)
        return bitcoin.add_pubkeys(point, parent_point), chain_code
    else:
        key = (int.from_bytes(parent_key, byteorder='big', signed=False) + int.from_bytes(key_offset, byteorder='big',
                                                                                          signed=False)) % bitcoin.N
        return key.to_bytes(32, byteorder='big', signed=False), chain_code


def hmac_digest_and_split(key, data, key_type='sha512'):
    m = hmac.new(key, data, key_type)
    hashed_seed = m.digest()
    key = hashed_seed[0:int(len(hashed_seed) / 2)]
    chain_code = hashed_seed[int(len(hashed_seed) / 2):]
    return key, chain_code


def derive_child_from_path(derivation_path, parent_key, key_type, parent_chain_code,network=Network.MAINNET):
    debug_print("Deriving: " + derivation_path)
    match = re.fullmatch(r"m(/\d+'?)+", derivation_path)
    if match is None:
        exit_with_error("bad path")
    depth = 0
    pubkey = 0
    for path_segment in derivation_path.split("/")[1:]:
        depth += 1
        last_char = len(path_segment) - 1
        hardened = False
        if path_segment[last_char] == "'":
            hardened = True
            path_segment = path_segment[:-1]
        parent_key, parent_chain_code, pubkey = derive_child(parent_key, parent_chain_code, int(path_segment), depth,
                                                             key_type, hardened,False,network)
    child_key = parent_key
    child_chain_code = parent_chain_code
    return child_key, child_chain_code, pubkey


def derive_child(parent_key, parent_chain_code, index, depth, key_type, hardened=False, master=False,network=Network.MAINNET):
    if hardened:
        index += hardened_index_offset
    (childKey, childChainCode) = derive_child_key(parent_key, parent_chain_code, index, key_type, hardened)
    debug_print("Derived Child key: " + print_hex(childKey))
    debug_print("Derived Child chain code: " + print_hex(childChainCode))

    wif = generate_wif_from_key(childKey, Network.MAINNET,False)
    debug_print("wif: " + wif)

    wif_compressed = generate_wif_from_key(childKey,Network.MAINNET,True)
    debug_print("wif (compressed): " + wif_compressed)

    if key_type == KeyType.PRIVATE:
        child_pub_key = bitcoin.privkey_to_pubkey(childKey)
        compressed_child_pub_key = bitcoin.compress(child_pub_key)
        debug_print("Child Pub Key: " + print_hex(child_pub_key))
        debug_print("Child Pub Key (Compressed) : " + print_hex(compressed_child_pub_key))
        print_extended_keys(childChainCode, childKey, compressed_child_pub_key, depth, index,
                            master, parent_key)
    else:
        child_pub_key = childKey
    return childKey, childChainCode, child_pub_key


def generate_wif_from_key(childKey, network,compressed=True):
    prefix = public_wif_prefix if network == Network.MAINNET else testnet_wif_prefix
    wif_binary = prefix.to_bytes(1,'big') + childKey
    if compressed:
        wif_binary += 0x01.to_bytes(1,'big')
    checksum = bitcoin.bin_dbl_sha256(wif_binary)[0:4]
    wif = bitcoin.changebase(wif_binary + checksum, 256, 58)
    return wif


def print_extended_keys(child_chain_code, child_key, compressed_child_pub_key, depth, index, master,
                        parent_private_key):
    if master:
        parent_key_fingerprint = b'\x00\x00\x00\x00'
    else:
        pubkey = bitcoin.compress(bitcoin.privkey_to_pubkey(parent_private_key))
        sha_ = bitcoin.bin_sha256(pubkey)
        ripemd_ = bitcoin.bin_ripemd160(sha_)
        parent_key_fingerprint = ripemd_[0:4]
    debug_print("Parent Fingerprint: " + print_hex(parent_key_fingerprint))
    child_extended_public_key = serialize_extended_key(extended_public_key_version_bytes, depth, parent_key_fingerprint,
                                                       index,
                                                       extend_key(child_chain_code, compressed_child_pub_key))
    child_extended_private_key = serialize_extended_key(extended_private_key_version_bytes, depth,
                                                        parent_key_fingerprint, index,
                                                        extend_key(child_chain_code, b'\x00' + child_key))
    debug_print("Extended Public Key for (depth,index):   (" + str(depth) + "," + str(index) + ")  "
                + child_extended_public_key)
    debug_print("Extended Private Key for (depth,index): (" + str(depth) + "," + str(index) + ")  "
                + child_extended_private_key)


def serialize_extended_key(version_bytes, depth, parent_key_fingerprint, child_number, extended_key):
    depth = depth.to_bytes(1, byteorder='big')
    index = child_number.to_bytes(4, byteorder='big')
    serialized = version_bytes + depth + parent_key_fingerprint + index + extended_key
    checksum = bitcoin.bin_dbl_sha256(serialized)[0:4]
    serialized += checksum
    return bitcoin.changebase(serialized, 256, 58)


def query_address_info(address, network=Network.MAINNET):
    if not query_blockchain:
        return 0
    debug_print("Querying: " + address)

    address_balance_url = "https://testnet.blockexplorer.com/api/addr/" if network == Network.TESTNET else "https://blockexplorer.com/api/addr/"
    address_balance_url += address
    print("url: " + address_balance_url)

    request = urllib.request.Request(address_balance_url)
    request.add_header('User-Agent',
                       "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36")
    address_info_json = json.loads(urllib.request.urlopen(request).read())
    balance = address_info_json.get('balanceSat')

    print("Balance: " + str(balance))
    return balance


def pretty_format_account_balance(balance):
    sats = balance % 10 ** 2
    balance = (balance - sats) / 10 ** 2
    u_btc = int(balance % 10 ** 3)
    balance = (balance - u_btc) / 10 ** 3
    m_btc = int(balance % 10 ** 3)
    balance = (balance - m_btc) / 10 ** 3
    btc = balance
    return str(btc) + " BTC " + str(m_btc) + " mBTC " + str(u_btc) + " uBTC " + str(sats) + " satoshis"


def get_wallet_balance_from_seed(bip39_mnemonic, bip39_password, derivation_path, last_child_index_to_search,
                                 network=Network.MAINNET):
    bip39_mnemonic = bip39_mnemonic.strip()
    mnemonic_words = bip39_mnemonic.split()
    with open('words.txt') as file:
        lines = file.read().splitlines()
    validate_mnemonic(mnemonic_words, lines)
    entropy_and_checksum = mnemonic_to_entropy_and_checksum(bip39_mnemonic, lines)
    verify_checksum(entropy_and_checksum, int(len(mnemonic_words) / 3))
    salt = "mnemonic" + bip39_password
    seed = hashlib.pbkdf2_hmac('sha512', bytearray(bip39_mnemonic, 'utf-8'), bytearray(salt, 'utf-8'), 2048)
    debug_print("seed: " + print_hex(seed))
    (master_private_key, master_chain_code) = hmac_digest_and_split(bytearray("Bitcoin seed", 'utf-8'), seed, 'sha512')
    debug_print("Master Private Key: " + print_hex(master_private_key))
    debug_print("Master Chain Code: " + print_hex(master_chain_code))
    master_public_key = bitcoin.privkey_to_pubkey(master_private_key)
    compressed_master_public_key = bitcoin.compress(master_public_key)
    debug_print("Master Public Key: " + print_hex(master_public_key))
    debug_print("Master Public Key (Compressed) : " + print_hex(compressed_master_public_key))
    print_extended_keys(master_chain_code, master_private_key, compressed_master_public_key, 0, 0, True, None)
    total_balance = 0

    magic_byte = public_magic_byte if network == Network.MAINNET else testnet_magic_byte
    for i in range(0, last_child_index_to_search):
        child_key, child_chain_code, child_pub_key = derive_child_from_path(
            derivation_path=derivation_path + str(i),
            parent_key=master_private_key,
            key_type=KeyType.PRIVATE,
            parent_chain_code=master_chain_code,
            network=network)
        address = bitcoin.pubkey_to_address(bitcoin.compress(child_pub_key), magic_byte)
        print("\nAddress: " + address + "\n")
        total_balance += query_address_info(address, network)
    print("Total Balance for this Wallet: " + pretty_format_account_balance(total_balance))


def deserialize_extended_key(extended_key):
    binary_key = bytearray(bitcoin.changebase(extended_key, 58, 256))
    binary_verify_checksum(binary_key, 4)
    (version_bytes, depth, parent_key_fingerprint, child_number, chain_code, key, checksum) = struct.unpack(
        '@4sc4s4s32s33s4s', binary_key)
    if version_bytes != extended_public_key_version_bytes:
        exit_with_error("Invalid version bytes on extended key")
    return version_bytes, depth, parent_key_fingerprint, child_number, chain_code, key


def get_wallet_balance_from_extended_public_key(extended_public_key, derivation_path, last_child_index_to_search,
                                                network=Network.MAINNET):
    (versionBytes, depth, parentKeyFingerprint, index, chainCode, pubKey) = deserialize_extended_key(
        extended_public_key)
    index = int.from_bytes(index, 'big')
    hardened = index >= 2 ** 31
    if hardened:
        index -= 2 ** 31
    debug_print("XPUB Info:  Depth: " + str(ord(depth)) + " index: " + str(index) + " hardened: " + str(hardened))
    total_balance = 0

    magic_byte = public_magic_byte if network == Network.MAINNET else testnet_magic_byte
    for i in range(0, last_child_index_to_search):
        child_key, child_chain_code, child_pub_key = derive_child_from_path(
            derivation_path=derivation_path + str(i),
            parent_key=pubKey,
            key_type=KeyType.PUBLIC,
            parent_chain_code=chainCode,
            network=network)
        address = bitcoin.pubkey_to_address(bitcoin.compress(child_pub_key), magic_byte)
        total_balance += query_address_info(address)
    print("Total Balance for this Wallet: " + pretty_format_account_balance(total_balance))

def generate_transaction(in_transaction,vout,script_sig,sequence,to_address,amount):
    version=1
    locktime=0


def generate_wallet(key_size=128):
    random = os.urandom(int(key_size/8))
    print("entropy: " + print_hex(random))
    array = bitarray.bitarray()
    for b in random:
        array += bitarray.bitarray('{0:08b}'.format(b))

    checksum_size = int(key_size / 32)
    cs = get_checksum_bits(array, checksum_size)
    # TODO: how to not hard code 4 bits of checksum?
    cs_binary = '{0:04b}'.format(cs)
    print("checksum: " + cs_binary)
    array += cs_binary
    with open('words.txt') as file:
        lines = file.read().splitlines()
    mnemonic = []
    while len(array) > 0:
        word = ShiftableBitArray(16)
        word.setall(False)
        word[5:] = array[:bits_per_word]
        array = array[bits_per_word:]
        tobytes = word.tobytes()
        mnemonic_word = lines[int.from_bytes(tobytes, 'big')]
        mnemonic.append(mnemonic_word)
    mnemonic_phrase = ' '.join(mnemonic)
    validate_mnemonic(mnemonic, lines)

    verify_checksum(mnemonic_to_entropy_and_checksum(mnemonic_phrase, lines), int(len(mnemonic) / 3))
    print(mnemonic_phrase)

# Main program

with open('seed.txt') as f:
    splitlines = f.read().splitlines()
    mnemonic = splitlines[0]
    password = splitlines[1]  # Optional, use a blank line if no path
    path = splitlines[2]
    search_breadth = splitlines[3]

get_wallet_balance_from_seed(mnemonic, password, path, int(search_breadth),Network.TESTNET)

with open('xpub.txt') as f:
    splitlines = f.read().splitlines()
    xPub = splitlines[0]
    path = splitlines[1]
    search_breadth = splitlines[2]
# get_wallet_balance_from_extended_public_key(xPub, path, int(search_breadth), Network.MAINNET)
# generateWallet()

