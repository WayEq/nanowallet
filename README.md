# nanowallet

**This can be used to check balances on the block chain.**

Method 1 (From an extended public key):

_See example file xpub-sample.txt_

To build the list of addresses from an extended pubic key and query their balances:
1. Create a file called xpub.txt
2. On the first line, list the base58 encoded xpub string
3. The 2nd line defines the derivation path.
5. The 3rd line defines a number that restricts the breadth of indices to search, one level below the derivation path listed on the previous line. 

Method 2 (From a bip39 mnemonic seed):

_See example file seed-sample.txt_

_Security Note: You probably shouldn't do this, unless you personally audit the code. The danger is that someone slipped in logic to store or forward your seed, which could be use to claim all your funds. Proceed only if you know what you're doing._

1. Create a file called seed.txt
2. On the first line, list the mnemonic words. Acceptable mnemonics have 12, 15, 18, 21, 24 words seperated by one space, with no quotation characters. 
3. The 2nd line defines (optional) password. 
4. The 3rd line defines the derivation path. 
5. The 4th line defines a number that restricts the breadth of indices to search, one level below the derivation path listed on the previous line.


