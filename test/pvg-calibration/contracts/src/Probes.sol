// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.26;

// Minimal, dependency-free fixtures for measuring the gas the EntryPoint does
// not meter (i.e. what preVerificationGas has to cover). Every contract here is
// intentionally trivial so that its own cost is small, deterministic and does not
// depend on the calldata it receives.

/// Same layout as EntryPoint v0.7 `PackedUserOperation`.
struct PackedUserOperation {
    address sender;
    uint256 nonce;
    bytes initCode;
    bytes callData;
    bytes32 accountGasLimits;
    uint256 preVerificationGas;
    bytes32 gasFees;
    bytes paymasterAndData;
    bytes signature;
}

/// Storage slots that probe accounts and the probe paymaster allocate and clear, to create
/// state-gas charges and refills in chosen EntryPoint metering spans.
contract Scratch {
    mapping(bytes32 => uint256) public slots;

    function set(bytes32 key) external {
        slots[key] = 1;
    }

    function clear(bytes32 key) external {
        slots[key] = 0;
    }
}

/// Signature-driven storage action a ProbeAccount performs during validation.
/// Layout: `action(1) | key(32) | scratch(20)`, where action 0x01 = set, 0x02 = clear.
/// Any other signature (including shorter ones) performs no action.
library ScratchAction {
    uint256 internal constant LENGTH = 53;

    function perform(bytes calldata sig) internal {
        if (sig.length < LENGTH) {
            return;
        }
        uint8 action = uint8(sig[0]);
        if (action != 1 && action != 2) {
            return;
        }
        bytes32 key = bytes32(sig[1:33]);
        Scratch scratch = Scratch(address(bytes20(sig[33:53])));
        if (action == 1) {
            scratch.set(key);
        } else {
            scratch.clear(key);
        }
    }
}

/// v0.7 account that accepts any signature (of any length) and pays exactly
/// `missingAccountFunds`, like LightAccount/SimpleAccount do. Execution is a no-op
/// fallback, so callData size only affects the EntryPoint's own copying. Also usable as an
/// EIP-7702 delegate (its only state is the immutable EntryPoint address).
///
/// A signature in the `ScratchAction` layout makes validation set or clear a Scratch slot.
contract ProbeAccount {
    address public immutable entryPoint;

    constructor(address _entryPoint) {
        entryPoint = _entryPoint;
    }

    function validateUserOp(PackedUserOperation calldata userOp, bytes32, uint256 missingAccountFunds)
        external
        returns (uint256)
    {
        require(msg.sender == entryPoint, "not from entry point");
        ScratchAction.perform(userOp.signature);
        if (missingAccountFunds != 0) {
            (bool ok,) = payable(msg.sender).call{value: missingAccountFunds}("");
            (ok);
        }
        return 0;
    }

    fallback() external payable {}

    receive() external payable {}
}

interface IEntryPointDeposit {
    function depositTo(address account) external payable;
}

/// CREATE2 factory for ProbeAccount, shaped like SimpleAccountFactory so the
/// deploy-in-op path can be measured without vendor account code.
contract ProbeFactory {
    address public immutable entryPoint;

    constructor(address _entryPoint) {
        entryPoint = _entryPoint;
    }

    function createAccount(uint256 salt) public returns (address account) {
        account = getAddress(salt);
        if (account.code.length > 0) {
            return account;
        }
        account = address(new ProbeAccount{salt: bytes32(salt)}(entryPoint));
    }

    /// Prepares the senders of a bundle in one transaction: optionally deploys each account,
    /// then sends it `accountValue` wei and deposits `depositValue` wei for it in the
    /// EntryPoint. `msg.value` must cover both for every salt.
    function setup(uint256[] calldata salts, bool predeploy, uint256 accountValue, uint256 depositValue)
        external
        payable
    {
        for (uint256 i = 0; i < salts.length; i++) {
            address account = predeploy ? createAccount(salts[i]) : getAddress(salts[i]);
            if (accountValue != 0) {
                (bool ok,) = payable(account).call{value: accountValue}("");
                require(ok, "fund failed");
            }
            if (depositValue != 0) {
                IEntryPointDeposit(entryPoint).depositTo{value: depositValue}(account);
            }
        }
    }

    function getAddress(uint256 salt) public view returns (address) {
        bytes32 hash = keccak256(
            abi.encodePacked(
                bytes1(0xff),
                address(this),
                bytes32(salt),
                keccak256(abi.encodePacked(type(ProbeAccount).creationCode, abi.encode(entryPoint)))
            )
        );
        return address(uint160(uint256(hash)));
    }
}

/// v0.7 paymaster that sponsors everything. paymasterData[0] selects the mode:
///   0 (or empty) - no context, so postOp is never called
///   1            - non-empty context, so postOp is called
///   2            - postOp is called and clears a Scratch slot; paymasterData is
///                  `0x02 | key(32) | scratch(20)`
/// Any other bytes after the mode byte are ignored (used to pad paymasterAndData).
contract ProbePaymaster {
    address public immutable entryPoint;

    /// Emitted from postOp with the pre-penalty cost the EntryPoint passed in.
    event ProbePostOp(uint256 actualGasCost, uint256 actualUserOpFeePerGas);

    constructor(address _entryPoint) {
        entryPoint = _entryPoint;
    }

    function validatePaymasterUserOp(PackedUserOperation calldata userOp, bytes32, uint256)
        external
        view
        returns (bytes memory context, uint256 validationData)
    {
        require(msg.sender == entryPoint, "not from entry point");
        // paymasterAndData = paymaster(20) | pmVerificationGasLimit(16) | postOpGasLimit(16) | data
        bytes calldata pmd = userOp.paymasterAndData;
        if (pmd.length > 52 && pmd[52] == 0x01) {
            context = hex"01";
        } else if (pmd.length >= 105 && pmd[52] == 0x02) {
            context = abi.encode(bytes32(pmd[53:85]), address(bytes20(pmd[85:105])));
        }
        return (context, 0);
    }

    /// Burns almost all of its gas after emitting. Execution gas used then always exceeds
    /// `paymasterPostOpGasLimit` (it adds the EntryPoint's own inner overhead on top), so the
    /// v0.7 unused-gas penalty is zero for any limit that lets postOp run.
    function postOp(uint8, bytes calldata context, uint256 actualGasCost, uint256 actualUserOpFeePerGas)
        external
    {
        require(msg.sender == entryPoint, "not from entry point");
        if (context.length == 64) {
            (bytes32 key, address scratch) = abi.decode(context, (bytes32, address));
            Scratch(scratch).clear(key);
        }
        emit ProbePostOp(actualGasCost, actualUserOpFeePerGas);
        while (gasleft() > POST_OP_GAS_RESERVE) {}
    }

    /// Gas postOp leaves unburned, enough to return.
    uint256 private constant POST_OP_GAS_RESERVE = 600;

    receive() external payable {}
}

/// Burns a fixed amount of gas regardless of calldata (calldata is never read or
/// copied). Used by chain calibration to observe standard calldata pricing in a
/// transaction whose execution cost exceeds the calldata floor.
contract Burner {
    fallback() external payable {
        assembly {
            let x := 0
            for { let i := 0 } lt(i, 20000) { i := add(i, 1) } { x := add(x, mul(i, 3)) }
            if eq(x, 1) { invalid() }
        }
    }
}
