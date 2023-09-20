# Rundler Architecture

there are 3 main process that are execute when running the rundler application and they are `rpc`, `builder` and `op_pool`.

## RPC

The rpc module is used to expose a JSONRPC http api, much like a normal Ethereum node. To see the available requests, please refer to the [EIP4337 spec](https://eips.ethereum.org/EIPS/eip-4337) and find the RPC methods section. 
To generate the JSONRPC api, we make use of [Parity's][parity] [jsonrpsee library][jsonrpsee] and its useful macro definitions.

## Builder

The builder module is used to propose, send and track transactions that need to be bundled together and pushed onto the chain. 

### Bundle Proposer

The bundle proposer is is most important part of Rundler as it performs numerous operations to check whether transactions and valid based on the [EIP4337 spec](https://eips.ethereum.org/EIPS/eip-4337), estimate gas and see if the next bundle
has enough room for it to be included or wait until a new bundle is proposed. 
 
### Bundle Sender 

After the bundle proposal runs, the bundle sender logic will handle the process of propagating a transction on chain and checking on the status to see if it is included in a block. This process also handles the gas increases if the transaction
has any issues being included.
 
### Sender

The sender is a lower level module that is used by the bundle sender to forward the bundled user operations to a node url or to a relay server (eg. Flashbots) if the chain is supported, after the transactions have been sent out to be landed on chain, there are a
couple process that track the status of the operations and perform updates to the gas price if the transaction has not landed within a few blocks.

### Signer

The signer component is used to sign transactions before they are sent to be propogated on chain. The signing process can either be done by a key that is local to the server instance or an AWS KMS key.
When using the KMS option, there also needs to be a configured redis cache to perform locking. The locking is required as if there are multiple instances of the builder modules running, we want to
make sure that none there are two of the services are using the same key with the same nonce. This can lead to an imediate revertion of the bundle if the nonce is not correct when sending the bundle to be
processed on chain.

### Server

The server component is a little bit more complex than the `sender` and the `signer` modules as there is a context of local or distributed options. The local server will work by passing messages between threads and listening to updates from the `pool`.
If the server is running in the distributed mode, messaging is done via gRPC which can be local to the machine or across multiple machines.

## Op Pool

The pool components purpose is to manage the mempool operations. Once a user operation is sent to the RPC server, the pool will add the operation to its mempool to be proposed via the builder and then to be propogated on chain. The Pool should be the 
module that lets the bulder know when a new user operation has been added to the mempool so that it can then be proposed to be incuded in a new bundle.

### Mempool

Within the `op_pool` process, the state of the mempool is updated and controlled by the `mempool` module which provides basic crud operations for the underlying pool and keeps track of address reputation to make sure there is a reduced risk of 
malicious activity when interacting with Rundler.

## TODO make better diagrams 

## Distributed architecture

![distributed](images/multiimage.png)  

## Single Image architecture

![singleimage](images/multiprocess.png)  

[parity]: https://www.parity.io/
[jsonrpsee]: https://github.com/paritytech/jsonrpsee