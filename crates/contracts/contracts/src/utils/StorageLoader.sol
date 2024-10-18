// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

contract StorageLoader {
    fallback() external payable {
        assembly {
            let cursor := 0

            for {} lt(cursor, calldatasize()) {cursor := add(cursor, 0x20)} {
                let slot := calldataload(cursor)
                mstore(cursor, sload(slot))
            }

            return(0, cursor)
        }
    }
}
