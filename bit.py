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

debugMode = True

# Constants
bitsPerWord = 11
acceptableWordCounts = [12, 15, 18, 21, 24]
hardenedIndexOffset = 2**31
xPubversionBytes = b"\x04\x88\xB2\x1E"
xPrvversionBytes = b"\x04\x88\xAD\xE4"


class KeyType(enum.Enum):
    PUBLIC = 0
    PRIVATE = 1

class mybitarray(bitarray):
    def __lshift__(self, count):
        return self[count:] + type(self)('0') * count
    def __rshift__(self, count):
        return type(self)('0') * count + self[:-count]
    def __repr__(self):
        return "{}('{}')".format(type(self).__name__, self.to01())


def exitWithError(error):
    print(error)
    exit(-1)


def debugPrint(message):
    if debugMode:
        print(message)

def validateMnemonic(words,lines):
    if len(words) not in acceptableWordCounts:
        exitWithError("Mnemonic word count must be one of: " + str(acceptableWordCounts))
    for word in words:
            if word not in lines:
                exitWithError("Word not found in mnemonic index: " + word)


def getbufflen(buff): 
    return str(len(buff.tobytes()))


def printb(buff):
    return "".join('{:08b}'.format(x) for x in buff)


def printh(buff):
    return "".join("{:02x}".format(c) for c in buff)


def mnemonicToEntropyAndChecksum(words,lines):
    mnemonicWords = words.split()
    numWords = len(mnemonicWords)
    entropyAndChecksumBitSize = numWords * bitsPerWord
    nums = []
    for word in words.split():
        nums.append(lines.index(word))
    entropyAndChecksum = mybitarray(entropyAndChecksumBitSize)
    entropyAndChecksum.setall(False)
    for num in nums:
        orTarget = bitarray(str('{0:011b}'.format(num)))
        while len(orTarget) < len(entropyAndChecksum):
            orTarget.insert(0,False)
        entropyAndChecksum = entropyAndChecksum << bitsPerWord
        entropyAndChecksum = entropyAndChecksum | orTarget
    return entropyAndChecksum

# TODO: combine these checksum methods
def bin_verifyChecksum(dataAndChecksum, checksumLen):
    entropy = dataAndChecksum[0:-checksumLen]
    checksum = dataAndChecksum[-checksumLen:]
    digest = bitcoin.bin_dbl_sha256(bytes(entropy))
    computedCS = digest[0:checksumLen]
    debugPrint("computed: " + printh(digest))
    if computedCS != checksum:
        print("checksum failed!")

def verifyChecksum(dataAndChecksum, checksumLen):
    entropy = dataAndChecksum[0:-checksumLen].tobytes()
    checksum = dataAndChecksum[-checksumLen:].tobytes()[0] >> 8 - checksumLen
    debugPrint("data: " + printh(entropy))
    debugPrint("checksum: " + str(checksum))
    m = hashlib.sha256()
    m.update(entropy)
    digest = m.digest()
    computedCS = digest[0] >> 8-checksumLen
    if computedCS != checksum:
        exitWithError("checksum failed!")

def generateMasterPubKey(masterPrivKey):
        pk = PrivateKey(masterPrivKey,True)
        return pk.pubkey.serialize()


def extendKey(chainCode,key):
    return chainCode + key


def deriveChildKey(parentKey, parentChainCode, index, type, hardened=False):
    if hardened:
        if type == KeyType.PUBLIC:
            exitWithError("Can not derive a hardened public child key from parent public key")
        inputData = bytearray(b'\x00') + parentKey
    else:
        if type == KeyType.PUBLIC:
            inputData = bitcoin.compress(parentKey)
        else :
            pubKey = bitcoin.privkey_to_pubkey(parentKey)
            inputData = bitcoin.compress(pubKey)

    inputData += int(index).to_bytes(4,byteorder='big')
    key = parentChainCode
    (keyOffset,chainCode) = hmacDigestAndSplit(key, inputData)
    if type == KeyType.PUBLIC:
        point = bitcoin.decompress(bitcoin.privkey_to_pubkey(keyOffset))
        parentPoint = bitcoin.decompress(parentKey)
        return bitcoin.add_pubkeys(point,parentPoint),chainCode

    else:
        key = (int.from_bytes(parentKey,byteorder='big',signed=False) + int.from_bytes(keyOffset,byteorder='big',signed=False)) % bitcoin.N
    return key.to_bytes(32,byteorder='big',signed=False),chainCode


def hmacDigestAndSplit(key, data, type='sha512'):
    m = hmac.new(key,data,type)
    hashedSeed = m.digest()
    privKey = hashedSeed[0:int(len(hashedSeed) / 2)]
    chainCode = hashedSeed[int(len(hashedSeed) / 2):]
    return (privKey,chainCode)

def deriveChildFromPath(path,parentPrivateKey, type, parentChainCode):
    debugPrint("Deriving: " + path)
    match = re.fullmatch(r"m(/\d+'?)+", path)
    if match == None:
        exitWithError("bad path")
    depth=0
    pubkey = 0
    for pathSegment in path.split("/")[1:]:
        depth += 1
        lastChar = len(pathSegment) - 1
        hardened = False
        if pathSegment[lastChar] == "'":
            hardened = True
            pathSegment = pathSegment[:-1]
        parentPrivateKey,parentChainCode,pubkey = deriveChild(parentPrivateKey,parentChainCode,int(pathSegment),depth,type, hardened)
    return parentPrivateKey,parentChainCode,pubkey


def deriveChild(parentPrivateKey, parentChainCode, index, depth, type, hardened=False, master=False):
    if (hardened):
        index += hardenedIndexOffset
    (childKey, childChainCode) = deriveChildKey(parentPrivateKey, parentChainCode, index, type, hardened)
    debugPrint("Derived Child key: " + printh(childKey))
    debugPrint("Derived Child chain code: " + printh(childChainCode))

    if type == KeyType.PRIVATE:
        childPubKey = bitcoin.privkey_to_pubkey(childKey)
        compressedChildPubKey = bitcoin.compress(childPubKey)
        debugPrint("Child Pub Key: " + printh(childPubKey))
        debugPrint("Child Pub Key (Compressed) : " + printh(compressedChildPubKey))
        printExtendedKeys(childChainCode, childKey, compressedChildPubKey, depth, index,
                                             master, parentPrivateKey)
    else:
        childPubKey = childKey
    return childKey, childChainCode, childPubKey


def printExtendedKeys(childChainCode, childKey, compressedChildPubKey, depth, index, master, parentPrivateKey):
    if master:
        parentKeyFingerprint = b'\x00\x00\x00\x00'
    else:
        pubkey = bitcoin.compress(bitcoin.privkey_to_pubkey(parentPrivateKey))
        sha_ = bitcoin.bin_sha256(pubkey)
        ripemd_ = bitcoin.bin_ripemd160(sha_)
        parentKeyFingerprint = ripemd_[0:4]
    debugPrint("Parent Fingerprint: " + printh(parentKeyFingerprint))
    childxpub = serializeExtendedKey(xPubversionBytes, depth, parentKeyFingerprint, index,
                                     extendKey(childChainCode, compressedChildPubKey))
    childxprv = serializeExtendedKey(xPrvversionBytes, depth, parentKeyFingerprint, index,
                                     extendKey(childChainCode, b'\x00' + childKey))
    print("Extended Public Key for (depth,index):   (" + str(depth) + "," + str(index) + ")  " + childxpub)
    print("Extended Private Key for (depth,index): (" + str(depth) + "," + str(index) + ")  " + childxprv)


def serializeExtendedKey(versionBytes,depth,parentKeyFingerprint,childNumber,extendedKey):
    depth = depth.to_bytes(1, byteorder='big')
    index = childNumber.to_bytes(4, byteorder='big')
    serialized = versionBytes + depth + parentKeyFingerprint + index + extendedKey
    checksum = bitcoin.bin_dbl_sha256(serialized)[0:4]
    serialized += checksum
    return bitcoin.changebase(serialized, 256, 58)


def queryAddressInfo(address):
    print("Querying: " + address)
    addressInfoJson = json.loads(
        urllib.request.urlopen("http://blockchain.info/rawaddr/" + address + "?limit=0").read())
    print("Address: " + addressInfoJson.get('address'))
    balance = addressInfoJson.get('final_balance')
    print("Balance: " + str(balance))
    return balance


def prettyFormatAccountBalance(balance):
    sats = balance % 10**2
    balance = (balance - sats)  / 10**2
    uBTC = int(balance % 10**3)
    balance = (balance - uBTC) / 10**3
    mBTC = int(balance % 10**3)
    balance = (balance - mBTC) / 10**3
    btc = balance
    return str(btc) + " BTC " + str(mBTC) + " mBTC " + str(uBTC) + " uBTC " + str(sats) + " satoshis"


def getWalletBalanceFromSeed(mnemonic,password,derivationPath):


    mnemonic = mnemonic.strip()
    mnemonicWords = mnemonic.split()
    with open('words.txt') as f:
        lines = f.read().splitlines()
    validateMnemonic(mnemonicWords, lines)
    entropyAndChecksum = mnemonicToEntropyAndChecksum(mnemonic, lines)
    verifyChecksum(entropyAndChecksum,int(len(mnemonicWords)/3))
    salt = "mnemonic" + password
    seed = hashlib.pbkdf2_hmac('sha512', bytearray(mnemonic, 'utf-8'), bytearray(salt, 'utf-8'), 2048)
    debugPrint("seed: " + printh(seed))
    (masterPrivKey, masterChainCode) = hmacDigestAndSplit(bytearray("Bitcoin seed", 'utf-8'), seed, 'sha512')
    debugPrint("Master Private Key: " + printh(masterPrivKey))
    debugPrint("Master Chain Code: " + printh(masterChainCode))
    masterPubKey = bitcoin.privkey_to_pubkey(masterPrivKey)
    compressedMasterPubKey = bitcoin.compress(masterPubKey)
    debugPrint("Master Public Key: " + printh(masterPubKey))
    debugPrint("Master Public Key (Compressed) : " + printh(compressedMasterPubKey))
    printExtendedKeys(masterChainCode,masterPrivKey,compressedMasterPubKey,0,0,True,None)
    totalBalance = 0
    lastChildIndexToSearch = 2
    for i in range(0, lastChildIndexToSearch):
        childKey, childChainCode, childPubKey = deriveChildFromPath(
            path=derivationPath + str(i),
            parentPrivateKey=masterPrivKey,
            type=KeyType.PRIVATE,
            parentChainCode=masterChainCode)

        address = bitcoin.pubkey_to_address(bitcoin.compress(childPubKey))
        print(address)
        totalBalance += queryAddressInfo(address)
    print("Total Balance for this Wallet: " + prettyFormatAccountBalance(totalBalance))

def deserializeExtendedKey(extendedKey):
    binaryKey = bytearray(bitcoin.changebase(extendedKey, 58,256))
    bin_verifyChecksum(binaryKey,4)
    (versionBytes,depth,parentKeyFingerprint,childNumber,chainCode,key,checksum) = struct.unpack('@4sc4s4s32s33s4s',binaryKey)
    if versionBytes != xPubversionBytes:
        exitWithError("Invalid version bytes on extended key")
    return (versionBytes, depth, parentKeyFingerprint, childNumber, chainCode,key)


def getWalletBalanceFromXpub(xPub,path):
    (versionBytes, depth, parentKeyFingerprint, index, chainCode, pubKey) = deserializeExtendedKey(xPub)
    index = int.from_bytes(index, 'big')
    hardened =  index >= 2**31
    if hardened:
        index -= 2**31
    debugPrint("XPUB Info:  Depth: " + str(ord(depth)) + " index: " + str(index) + " hardened: " + str(hardened))
    totalBalance = 0
    lastChildIndexToSearch = 10
    for i in range(0, lastChildIndexToSearch):
        childKey, childChainCode, childPubKey = deriveChildFromPath(
            path=path + str(i),
            parentPrivateKey=pubKey,
            type=KeyType.PUBLIC,
            parentChainCode=chainCode)
        address = bitcoin.pubkey_to_address(bitcoin.compress(childPubKey))
        print(address)
        totalBalance += queryAddressInfo(address)
    print("Total Balance for this Wallet: " + prettyFormatAccountBalance(totalBalance))

#### Main program

with open('seed.txt') as f:
    splitlines = f.read().splitlines()
    mnemonic = splitlines[0]
    password = splitlines[1] # Optional, use a blank line if no path
    path = splitlines[2]

getWalletBalanceFromSeed(mnemonic,password,path)

with open('xpub.txt') as f:
    splitlines = f.read().splitlines()
    xPub = splitlines[0]
    path = splitlines[1]
getWalletBalanceFromXpub(xPub,path)
