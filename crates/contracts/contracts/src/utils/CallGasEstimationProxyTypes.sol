// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

error EstimateCallGasResult(uint256 gasEstimate, uint256 numRounds);

error EstimateCallGasContinuation(uint256 minGas, uint256 maxGas, uint256 numRounds);

error EstimateCallGasRevertAtMax(bytes revertData);

error TestCallGasResult(bool success, uint256 gasUsed, bytes revertData);

// keccak("CallGasEstimationProxy")[:20]
// Don't use an immutable constant. We want the "deployedBytecode" in
// the generated JSON to contain this constant.
address constant IMPLEMENTATION_ADDRESS_MARKER = 0xA13dB4eCfbce0586E57D1AeE224FbE64706E8cd3;
