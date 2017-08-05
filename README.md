# nanowallet

**This can be used to check balances on the block chain.**


To build the list of addresses from a bip39 seed and query their balances:
1. Create a file called seed.txt
2. On the first line, list the mnemonic words. Acceptable mnemonics have 12, 15, 18, 21, 24 words seperated by one space, with no quotation characters. 
3. The 2nd line defines (optional) password. 
4. The 3rd line defines the derivation path. 
5. The 4th line defines the breadth of indices to search, one level below the derivation path listed on the previous line.

To build the list of addresses from an extended pubic key and query their balances:
1. Create a file called xpub.txt
2. On the first line, list the base58 encoded xpub string
3. The 2nd line defines the derivation path.
5. The 3rd line defines the breadth of indices to search, one level below the derivation path listed on the previous line.
