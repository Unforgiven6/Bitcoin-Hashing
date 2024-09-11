# Bitcoin-Hashing
Bitcoin hashing using SHA-256 is a cryptographic process that secures transactions on the Bitcoin network. It uses the Secure Hash Algorithm 256-bit to transform an input into a fixed-length, 256-bit (32-byte) string, regardless of the input size.

**Mining:**

In Bitcoin mining, SHA-256 is used in the "proof-of-work" process. Miners repeatedly hash block header data, which includes the previous block hash, timestamp, transaction information, and a random number called a nonce.

**Double Hashing:**

Bitcoin applies SHA-256 twice to the block header to enhance security, a process known as double SHA-256.

**Hash Target:**

The goal is to find a hash that is lower than a target value set by the Bitcoin network. Miners adjust the nonce and hash the data until they find a valid hash, which allows them to add the block to the blockchain and earn a reward.

By doing Bitcoin hashing, it ensures the integrity of the blockchain by making it computationally difficult to alter historical data.

<br>What is a **Blockchain**?<br/>

A blockchain is a _chain of digital data blocks_.

- Each blocks can store digital information about financial transactions such as date, time, dollar, sender, receiver or it can be medical records or property purchase deeds and much more.
- Chaining of blocks is done through cryptographic hashing algorithms, such as SHA-256, Scrypt, etc.
- Blocks which are chained together, its data can never be changed again (Immutable !).
- Entire block chain is publicly available to anyone who wants to see it, in exactly the way it was once added to the blockchain.
- Blockchain is a distributed and decentralized public ledger. 
