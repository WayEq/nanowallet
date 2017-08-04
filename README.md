# nanowallet

This can be used to check balances on the block chain.

To build the list of addresses from a bip39 seed, create a file called seed.txt, with the first line populated
with the seed words, and the second line the (optional) password. Currently only works for bip44 style 
accounts.

To build the list of addresses from an extended pubic key, create a file called xpub.txt, with the first line
populated with the base58 xpub string, and the second line being the derivation path.
