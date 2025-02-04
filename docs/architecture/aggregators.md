# Signature Aggregation

This is an overview of Rundler's support for [ERC-7766: Signature Aggregation](https://eips.ethereum.org/EIPS/eip-7766).

Rundler requires explicit implementations and registration of each signature aggregator that it supports. Due to:

* Signature aggregators have a large amount of "power" in a ERC-4337 bundle. The bundler must trust the signature aggregator implementation to not DOS.
    * Staking and reputation could also work here - but Rundler requires an explicit registry due to the following points.
* The ERC-4337 entrypoint does not provide a way to "meter" the gas used by an aggregator on chain. Thus, bundlers must know how to charge for the aggregator's gas using `preVerificationGas`. This requires explicit knowledge of the aggregator's code.
* Most useful aggregators require an offchain component to perform the signature aggregation efficiently.

## Trait & Registry

The primary aggregator trait is `SignatureAggregator`. Each supported aggregator must implement this trait. This trait includes methods to:

* Return the aggregator's address, costs, and associated dummy UO signature
* Verify UO signatures prior to aggregation and return the UO component of the signature, stripping away anything that isn't needed onchain.
* Aggregate UO signatures

### Costs

The `SignatureAggregator::costs(...) -> AggregatorCosts` function requires special care during implementation. Its return value consists of:

* `execution_fixed_gas`: The fixed gas cost of the onchain aggregator's `validateSignatures` function. It *may* be amortized across all of the UOs in a bundle.  
* `execution_variable_gas`: The per UO added gas cost of the the onchain aggregator's `validateSignatures` function. Each UO using the aggregator will always be charged for this.
* `sig_fixed_length`: The fixed length of an aggregator's signature. The calldata & DA cost for this signature *may* be amortized across all of the UOs in a bundle.
* `sig_variable_length`: The per UO added signature length. The calldata & DA cost for this will always be charged to the UO.

Developers should determine these values using simulation tools and hardcode their values (or calculations) into their implementations.

### Chain Spec Registry

Each signature aggregator is registered on the `ChainSpec` object for access by most components in Rundler. This registry happens in the `bin/rundler` crate's `instantiate_aggregators` function. Developers should add their aggregators to this function for support. Ideally, registration is gated behind (1) CLI flags (2) compile time feature flags (especially if bringing in large dependency crates) (3) a combination of both.

## `PreVerificationGas`

Gas costs associated with signature aggregators are always charged via `PreVerificationGas` (PVG) as the entry point does not provide onchain metering.

### Bundle Size

The PVG calculations, during estimation and fee checks, are done against a specific bundle size. Shared costs *may* be amortized across UOs in the bundle.

NOTE: Rundler does not currently support dynamic bundle sizes during estimation and fee checks. UOs are always charged as if the bundle is size 1. See [here](#dynamic-bundle-size) for more detail.

### PVG Components

* Execution: `execution_fixed_gas` and `execution_variable_gas` from the aggregator contribute here.
* Calldata: `sig_fixed_length` and `sig_variable_length` from the aggregator contribute here.
* DA:`sig_fixed_length` and `sig_variable_length` from the aggregator also contribute here. During DA gas cost estimation the aggregator signature is assumed to be random bytes that have a compression ratio of 1 (i.e. they don't compress). A future update may allow aggregators to specify the compression ratio of their signatures on various L2 stack types.

## Task Support

### RPC

In both `eth_estimateUserOperationGas` and `eth_sendUserOperation`, Rundler has added a `aggregator: Optional<Address>` field to the UO. UOs using an aggregator MUST send the aggregator address they're using as part of these RPC calls. This field is NOT included in the `PackedUserOperation` that the UO uses to generate a signature and is not submitted onchain.

NOTE: this is a deviation from the current ERC-4337 and ERC-7766 specs. It allows the bundler to perform logic on the aggregator without needing to run the UO's `validateUserOp` function, improving latency and simplifying code.

### Pool

When a UO with an `aggregator` set is added to the pool, the pool performs a series of tasks:

1. Checks if the UO's signature aggregator is supported and retrieves the aggregator from the chain spec.
2. Calls the aggregators `validate_user_op_signature`, ensure's that its valid, and retrieves the UO signature object.
3. Transforms the UO with its new signature (retaining the old signature for later aggregation), captures some metadata about the aggregator alongside the UO, and adds to the mempool.

### Builder

During bundle building the builder:

1. Throws out UOs that contain unsupported aggregators (this shouldn't happen in a correctly configured system).
2. Calculates an aggregated signature for the UOs and submits the bundle via the entry point's `handleAggregatedOps` function.

## Future Work

### Builder <> Aggregator Affinity

In order to maximize the amount of UOs aggregated together, UOs that use the same aggregator should have affinity to a builder (or group of builders). This will be built to allow a configurable tradeoff between time to mine latency and aggregation size.

### Dynamic Bundle Size

Rundler currently assumes a bundle size of 1 during:

* PVG gas estimation
* Mempool precheck fee check
* Mempool UO candidate DA fee checking
* Builder bundle inclusion fee check.

This unfortunately means that each UO is charged for the full amount of the fixed components of the aggregators costs. This renders a large class of aggregators as not useful.

A future update may improve this. However, the design here is not straightforward and will require research. High level ideas can be found in a Github issue tracking the work.

## Implementations

Implementations can be found [here](../../crates/aggregators/). Each implementation is its own crate.

### [BLS](../../crates/aggregators/bls/)

The BLS aggregator has support for the BLS aggregator contracts from [eth-infinitism](https://github.com/eth-infinitism/account-abstraction-samples/tree/master/contracts/bls).

Currently, all aggregator functions are implemented using entrypoint calls, as opposed to local BLS logic. A future update may improve this.

NOTE: This is implemented mostly as a POC of aggregation in Rundler. Due to the bundle size [limitations](#dynamic-bundle-size) this aggregator has little practical use and is not recommended for production.

### [PBH](../../crates/aggregators/pbh/)

The PBH aggregator has support for the World Chain Priority Blockspace for Humans signature aggregator. More info can be found [here](https://github.com/worldcoin/world-chain/tree/main/contracts).
