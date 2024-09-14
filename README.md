# Bitcoin-Hashing
Bitcoin hashing using SHA-256 is a cryptographic process that secures transactions on the Bitcoin network. It uses the Secure Hash Algorithm 256-bit to transform an input into a fixed-length, 256-bit (32-byte) string, regardless of the input size.

**Mining**

In Bitcoin mining, SHA-256 is used in the "proof-of-work" process. Miners repeatedly hash block header data, which includes the previous block hash, timestamp, transaction information, and a random number called a nonce.

**Double Hashing**

Bitcoin applies SHA-256 twice to the block header to enhance security, a process known as double SHA-256.

**Hash Target**

The goal is to find a hash that is lower than a target value set by the Bitcoin network. Miners adjust the nonce and hash the data until they find a valid hash, which allows them to add the block to the blockchain and earn a reward.

By doing Bitcoin hashing, it ensures the integrity of the blockchain by making it computationally difficult to alter historical data.

## <br>What is a **Blockchain**?<br/>

A blockchain is a _chain of digital data blocks_.

- Each blocks can store digital information about financial transactions such as date, time, dollar, sender, receiver or it can be medical records or property purchase deeds and much more.
- Chaining of blocks is done through cryptographic hashing algorithms, such as SHA-256, Scrypt, etc.
- Blocks which are chained together, its data can never be changed again (Immutable!).
- Entire block chain is publicly available to anyone who wants to see it, in exactly the way it was once added to the blockchain.
- Blockchain is a distributed and decentralized public ledger. 

## <br>**Types of implementations:**<br/>
### **Serial Implementation**

<p align="center">
  <img src="https://github.com/user-attachments/assets/7bf4330b-bc34-498b-b7e5-b82e59952965" />
</p>

In a serial implementation, the hash function (SHA-256) is applied one step at a time. The process happens in sequential order, and there’s no overlap or simultaneous processing of different parts of the hash computation.

1. **Nonce iteration:** A nonce is selected, and the input data (including the nonce) is passed into the SHA-256 hashing algorithm.
2. **First SHA-256:** The first SHA-256 operation is computed on the input.
3. **Second SHA-256:** The result from the first hash is then passed through SHA-256 again (double SHA-256).
4. **Check target:** The resulting hash is compared to the target difficulty.
5. **Repeat:** If the result is not below the target, the nonce is incremented, and the process repeats.

**Characteristics**

- **Single thread or core:** The algorithm runs on a single processor core or thread.
- **Limited throughput:** Since each nonce is processed one by one, this approach is slower, making it inefficient for large-scale mining.
- **Low resource usage:** While slower, serial implementations don’t require much hardware or power.

### **Parallel Implementation**

<p align="center">
  <img src="https://github.com/user-attachments/assets/75cce849-5faa-44e0-826f-4159b2cb3ac7" />
</p>!

In a parallel implementation, multiple instances of the hash function are computed simultaneously. This can be done using hardware (e.g., ASICs, GPUs, or FPGAs) or software threads running in parallel on multicore processors. To Perform 16 SHA256 operations in parallel, 16 copies of SHA256 logic is required and this will consume more logic within FPGA.

1. **Multiple nonces:** Several different nonces are tried simultaneously, each processed by a separate thread or processing core.
2. **Parallel hashing:** The SHA-256 hashing (double SHA-256) is computed in parallel for each nonce.
3. **Check targets:** The results from all the hashes are checked against the target.
4. **Continue:** If none of the results meet the target, new nonces are assigned, and the process repeats in parallel.

**Characteristics**

- **High throughput:** Multiple hashes are computed simultaneously, making the process significantly faster and more efficient.
- **Hardware acceleration:** Parallel implementations often use GPUs, FPGAs, or ASICs, which are optimized for the SHA-256 hashing process.
- **High resource usage:** Parallel implementations require more power and resources due to the use of specialized hardware and more processing cores.
- **Mining farms:** Bitcoin miners typically use parallel implementations across large arrays of ASICs in mining farms to maximize the chances of finding the correct hash.

**16 Nonces vs 8 Nonces**

Arria-II FPGA will not able to fit 16 instances of SHA256. To solve this, first perform in parallel implementation of SHA256 for nonce 0 to 7 and then re-use same logic and one more time perform SHA256 operation in parallel for nonce 8 to 16. This will required 8 instances of SHA256.

In the files, `bitcoin_hashing_no_itr.sv` has codes for no iterations in SHA256 operations, and `bitcoin_hashing_itr.sv` has iterations which will work for most FPGA models.
