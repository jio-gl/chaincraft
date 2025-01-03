# chaincraft

Chaincraft: The platform for blockchain education and prototyping

## Roadmap

- [x] Gossip: Sharing JSON messages between the nodes (`SharedMessage`).
- [x] Permanent storage: the JSON messages are stored in key/value.
- [x] Discovery: Global or Local Discovery of new nodes.
- [x] Mandatory and Optional Fields and Types: Some format for JSON, prevalidation. Ban peers sending invalid format.
- [ ] `SharedObject` list that is updated by `SharedMessages` (inside can go Linked Fields Chaining). Ban peers sending invalid messages.
- [ ] Primitives (RSA, ECSA, VDF, VRF, Signature Aggregation, LSH, Quantum-resistant Primitives)
- [ ] Indexing (MongoDB-like)
- [ ] Merklelized Storage: to know quicker when some a SharedObject is broken or which index for a linear array of messages/blocks.

## `SharedMessage`

- `prevalidation(message) : boolean` with mandatory/optional fields and types.
- Test `isValid(message)` for all `SharedObjects` like Ledgers or Mempools.
- Do update for all shared objects with `addMessage(message)`.

## `SharedObject`

- `isValid(SharedMessage) : boolean`: a message `m` if valid is `all( isValid(m ) for o in sharedObject)`
- `addMessage(ShareMessage) : void`: is "added" to all ShredObjects if is valid like `[o.addMessage(m) for o in sharedObject]`
- `isMerkelized()/hasDigest() : boolean`
- `getDigest() : SharedMessage`
- `isValidDigest() : boolean` to check if the digest for the shared object is valid.
- `gossipObject(peer,myDigest) : List(SharedMessage)` to sync the SharedObject locally, requesting more messages.
- Local `SharedObject` gossip using `hasDigest()`, `getDigest()`, `gossipObject()` and `isValidDigest()`. 

# Example (Bitcoin)

- The shared object are `Ledger` and `Mempool`.
- A bitcoin transaction `tx` is only a transfer for simplicity.
- Example: `Ledger.isValid(tx)` is `true` if the sender has enough balance in account to do the transfer.
- Example `Mempool.addMessage(tx)` will do a sorted insert into the priority queue of `Mempool` based on the fee that the sender is paying, higher fees gets more priority to be included in the next block of transactions.

## Design Principles for Prototyping Blockchains and Protocols

- Blockchain Trilemma (Tradeoff):
    - Security
    - Scalability
    - Decentralization
- Time Synchronization (Tradeoff): having better synced time has pros and cons.
    - Totally Async (no validation of timestamps)
    - Eventually Synced (timestamps are used for some things, but you accept timestamp far away in time)
    - Bounded Synced Time (`timestamp +/- delta` are the only valid messages, where delta is 15 seconds for example).
    - Totally Time-synced, like depend on time being totally synced.
- Identity and Anon User (Tradeoff):
    - Totally Anon Users.
    - Anon Users w/Resources (think Proof-of-Work without signatures)
    - Identified with Signatures.
    - Signature plus protocol to accept the new identity (think adding a validator to Proof-of-Stake).
- Levels of Data Synchronization:
    - Torrent: very liberal and concurrent.
    - Blockchain: very restrictive and sequential.
    - Middle-ground: decentralized app (non-financial)
        - Eventually consistent.
        - All data is validated.
        - Example1: Decentralized Messenger (santi).
        - Example2: Decentralized AI

## Brainstorming in DeAI

- Prededetemined Training Sample Blocks List: B1, B2, ..., Bn..
- Eventually: block Bi is processed.
- Is Okey if Bn is processed and validated and distributed and B(n-1) is not yet available.
- Alternative: a node can propose Bn if is missing, Bn-1 is known, or wants to replace existing Bn.


## Run tests

Run all tests:

```bash
python -m unittest discover -v -s tests
```

Result:
```bash
...
----------------------------------------------------------------------
Ran 38 tests in 61.963s

OK
```

A single testfile:

```bash
python -m unittest tests/test_start.py
```

To run a single test inside a testfile:

```bash
python -m unittest -v -k test_local_discovery_enabled tests/test_local_discovery.py
```
