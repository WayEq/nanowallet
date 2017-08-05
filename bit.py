#!/usr/bin/python 

import bitcoin
import hashlib
import hmac
import urllib.request
import json
import re
import struct
import enum
from bitarray import bitarray
from secp256k1 import PrivateKey, PublicKey

debug_mode = False

# Constants
bits_per_word = 11
acceptable_word_counts = [12, 15, 18, 21, 24]
hardened_index_offset = 2 ** 31
extended_public_key_version_bytes = b"\x04\x88\xB2\x1E"
extended_private_key_version_bytes = b"\x04\x88\xAD\xE4"


class KeyType(enum.Enum):
    PUBLIC = 0
    PRIVATE = 1


class ShiftableBitArray(bitarray):
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
        or_target = bitarray(str('{0:011b}'.format(num)))
        while len(or_target) < len(entropy_and_checksum):
            or_target.insert(0, False)
        entropy_and_checksum = entropy_and_checksum << bits_per_word
        entropy_and_checksum = entropy_and_checksum | or_target
    return entropy_and_checksum


# TODO: combine these checksum methods
def binary_verify_checksum(dataAndChecksum, checksumLen):
    entropy = dataAndChecksum[0:-checksumLen]
    checksum = dataAndChecksum[-checksumLen:]
    digest = bitcoin.bin_dbl_sha256(bytes(entropy))
    computedCS = digest[0:checksumLen]
    debug_print("computed: " + print_hex(digest))
    if computedCS != checksum:
        print("checksum failed!")


def verify_checksum(dataAndChecksum, checksumLen):
    entropy = dataAndChecksum[0:-checksumLen].tobytes()
    checksum = dataAndChecksum[-checksumLen:].tobytes()[0] >> 8 - checksumLen
    debug_print("data: " + print_hex(entropy))
    debug_print("checksum: " + str(checksum))
    m = hashlib.sha256()
    m.update(entropy)
    digest = m.digest()
    computedCS = digest[0] >> 8 - checksumLen
    if computedCS != checksum:
        exit_with_error("checksum failed!")


def generate_master_public_key(master_priv_key):
    pk = PrivateKey(master_priv_key, True)
    return pk.pubkey.serialize()


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
            pubKey = bitcoin.privkey_to_pubkey(parent_key)
            input_data = bitcoin.compress(pubKey)

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


def derive_child_from_path(derivation_path, parent_key, key_type, parent_chain_code):
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
                                                             key_type, hardened)
    child_key = parent_key
    child_chain_code = parent_chain_code
    return child_key, child_chain_code, pubkey


def derive_child(parent_key, parent_chain_code, index, depth, key_type, hardened=False, master=False):
    if hardened:
        index += hardened_index_offset
    (childKey, childChainCode) = derive_child_key(parent_key, parent_chain_code, index, key_type, hardened)
    debug_print("Derived Child key: " + print_hex(childKey))
    debug_print("Derived Child chain code: " + print_hex(childChainCode))

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


def serialize_extended_key(version_bytes, depth, parent_key_fingerprint, child_number, extendedKey):
    depth = depth.to_bytes(1, byteorder='big')
    index = child_number.to_bytes(4, byteorder='big')
    serialized = version_bytes + depth + parent_key_fingerprint + index + extendedKey
    checksum = bitcoin.bin_dbl_sha256(serialized)[0:4]
    serialized += checksum
    return bitcoin.changebase(serialized, 256, 58)


def query_address_info(address):
    print("Querying: " + address)
    address_info_json = json.loads(
        urllib.request.urlopen("http://blockchain.info/rawaddr/" + address + "?limit=0").read())
    print("Address: " + address_info_json.get('address'))
    balance = address_info_json.get('final_balance')
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


def get_wallet_balance_from_seed(bip39_mnemonic, bip39_password, derivation_path, last_child_index_to_search):
    bip39_mnemonic = bip39_mnemonic.strip()
    mnemonic_words = bip39_mnemonic.split()
    with open('words.txt') as f:
        lines = f.read().splitlines()
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
    for i in range(0, last_child_index_to_search):
        child_key, child_chain_code, child_pub_key = derive_child_from_path(
            derivation_path=derivation_path + str(i),
            parent_key=master_private_key,
            key_type=KeyType.PRIVATE,
            parent_chain_code=master_chain_code)

        address = bitcoin.pubkey_to_address(bitcoin.compress(child_pub_key))
        print(address)
        total_balance += query_address_info(address)
    print("Total Balance for this Wallet: " + pretty_format_account_balance(total_balance))


def deserialize_extended_key(extended_key):
    binary_key = bytearray(bitcoin.changebase(extended_key, 58, 256))
    binary_verify_checksum(binary_key, 4)
    (version_bytes, depth, parent_key_fingerprint, child_number, chain_code, key, checksum) = struct.unpack(
        '@4sc4s4s32s33s4s', binary_key)
    if version_bytes != extended_public_key_version_bytes:
        exit_with_error("Invalid version bytes on extended key")
    return version_bytes, depth, parent_key_fingerprint, child_number, chain_code, key


def get_wallet_balance_from_extended_public_key(extended_public_key, derivation_path, last_child_index_to_search):
    (versionBytes, depth, parentKeyFingerprint, index, chainCode, pubKey) = deserialize_extended_key(
        extended_public_key)
    index = int.from_bytes(index, 'big')
    hardened = index >= 2 ** 31
    if hardened:
        index -= 2 ** 31
    debug_print("XPUB Info:  Depth: " + str(ord(depth)) + " index: " + str(index) + " hardened: " + str(hardened))
    total_balance = 0
    for i in range(0, last_child_index_to_search):
        childKey, childChainCode, childPubKey = derive_child_from_path(
            derivation_path=derivation_path + str(i),
            parent_key=pubKey,
            key_type=KeyType.PUBLIC,
            parent_chain_code=chainCode)
        address = bitcoin.pubkey_to_address(bitcoin.compress(childPubKey))
        print(address)
        total_balance += query_address_info(address)
    print("Total Balance for this Wallet: " + pretty_format_account_balance(total_balance))


#### Main program

with open('seed.txt') as f:
    splitlines = f.read().splitlines()
    mnemonic = splitlines[0]
    password = splitlines[1]  # Optional, use a blank line if no path
    path = splitlines[2]
    search_breadth = splitlines[3]

get_wallet_balance_from_seed(mnemonic, password, path, int(search_breadth))

with open('xpub.txt') as f:
    splitlines = f.read().splitlines()
    xPub = splitlines[0]
    path = splitlines[1]
    search_breadth = splitlines[2]
get_wallet_balance_from_extended_public_key(xPub, path, int(search_breadth))
