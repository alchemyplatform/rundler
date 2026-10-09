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

/// Same layout as EntryPoint v0.6 `UserOperation`.
struct UserOperationV06 {
    address sender;
    uint256 nonce;
    bytes initCode;
    bytes callData;
    uint256 callGasLimit;
    uint256 verificationGasLimit;
    uint256 preVerificationGas;
    uint256 maxFeePerGas;
    uint256 maxPriorityFeePerGas;
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

/// v0.6 counterpart of `ProbeAccount`: same behaviour, v0.6 `validateUserOp`. Separate from
/// `ProbeAccount` so the v0.7 fixtures keep their bytecode (and their deploy cost).
contract ProbeAccountV06 {
    address public immutable entryPoint;

    constructor(address _entryPoint) {
        entryPoint = _entryPoint;
    }

    function validateUserOp(UserOperationV06 calldata userOp, bytes32, uint256 missingAccountFunds)
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

/// `ProbeFactory` for `ProbeAccountV06`.
contract ProbeFactoryV06 {
    address public immutable entryPoint;

    constructor(address _entryPoint) {
        entryPoint = _entryPoint;
    }

    function createAccount(uint256 salt) public returns (address account) {
        account = getAddress(salt);
        if (account.code.length > 0) {
            return account;
        }
        account = address(new ProbeAccountV06{salt: bytes32(salt)}(entryPoint));
    }

    /// See `ProbeFactory.setup`.
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
                keccak256(abi.encodePacked(type(ProbeAccountV06).creationCode, abi.encode(entryPoint)))
            )
        );
        return address(uint160(uint256(hash)));
    }
}

/// v0.6 counterpart of `ProbePaymaster`, with the same modes in `paymasterAndData[20]` (v0.6 has
/// no paymaster gas limits in `paymasterAndData`):
///   0 (or empty) - no context, so postOp is never called
///   1            - non-empty context, so postOp is called
///   2            - postOp is called and clears a Scratch slot; the data is
///                  `0x02 | key(32) | scratch(20)`
///
/// postOp does not burn gas: v0.6 has no unused-gas penalty, and its postOp limit is the op's
/// whole `verificationGasLimit`.
contract ProbePaymasterV06 {
    address public immutable entryPoint;

    /// Same signature as `ProbePaymaster.ProbePostOp`, so one decoder serves both. v0.6 passes
    /// no fee per gas, so `actualUserOpFeePerGas` is always 0.
    event ProbePostOp(uint256 actualGasCost, uint256 actualUserOpFeePerGas);

    constructor(address _entryPoint) {
        entryPoint = _entryPoint;
    }

    function validatePaymasterUserOp(UserOperationV06 calldata userOp, bytes32, uint256)
        external
        view
        returns (bytes memory context, uint256 validationData)
    {
        require(msg.sender == entryPoint, "not from entry point");
        bytes calldata pmd = userOp.paymasterAndData;
        if (pmd.length > 20 && pmd[20] == 0x01) {
            context = hex"01";
        } else if (pmd.length >= 73 && pmd[20] == 0x02) {
            context = abi.encode(bytes32(pmd[21:53]), address(bytes20(pmd[53:73])));
        }
        return (context, 0);
    }

    function postOp(uint8, bytes calldata context, uint256 actualGasCost) external {
        require(msg.sender == entryPoint, "not from entry point");
        if (context.length == 64) {
            (bytes32 key, address scratch) = abi.decode(context, (bytes32, address));
            Scratch(scratch).clear(key);
        }
        emit ProbePostOp(actualGasCost, 0);
    }

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

/// CREATE2-deploys contracts of a chosen runtime size, to create large EIP-8037 code-deposit
/// (state-gas) charges. The runtime code is `size` zero bytes, so the deposit cost depends on the
/// size only.
contract BlobDeployer {
    event Deployed(address deployed, uint256 size);

    function deploy(bytes32 salt, uint256 size) public returns (address deployed) {
        bytes memory initCode = blobInitCode(size);
        assembly {
            deployed := create2(0, add(initCode, 32), mload(initCode), salt)
        }
        require(deployed != address(0), "deploy failed");
        emit Deployed(deployed, size);
    }

    /// Deploys, then reverts the whole call: state is created and rolled back in one frame.
    function deployThenRevert(bytes32 salt, uint256 size) external {
        deploy(salt, size);
        revert("rolled back");
    }

    /// `PUSH2 size; PUSH0; RETURN`: returns `size` bytes of fresh (zero) memory as the code.
    function blobInitCode(uint256 size) public pure returns (bytes memory) {
        require(size <= 0xffff, "size too large");
        return abi.encodePacked(bytes1(0x61), uint16(size), bytes1(0x5f), bytes1(0xf3));
    }
}

/// v0.7 account with an `execute` entry point, so an op's execution phase can create state
/// (e.g. deploy through `BlobDeployer`). Validation is the same as `ProbeAccount`'s, without the
/// scratch actions. Separate from `ProbeAccount` so the other experiments' fixtures keep their
/// bytecode.
contract ExecAccount {
    address public immutable entryPoint;

    constructor(address _entryPoint) {
        entryPoint = _entryPoint;
    }

    function validateUserOp(PackedUserOperation calldata, bytes32, uint256 missingAccountFunds)
        external
        returns (uint256)
    {
        require(msg.sender == entryPoint, "not from entry point");
        if (missingAccountFunds != 0) {
            (bool ok,) = payable(msg.sender).call{value: missingAccountFunds}("");
            (ok);
        }
        return 0;
    }

    function execute(address target, uint256 value, bytes calldata data) external {
        require(msg.sender == entryPoint, "not from entry point");
        (bool ok, bytes memory ret) = target.call{value: value}(data);
        if (!ok) {
            assembly {
                revert(add(ret, 32), mload(ret))
            }
        }
    }

    receive() external payable {}
}

/// v0.6 counterpart of `ExecAccount`.
contract ExecAccountV06 {
    address public immutable entryPoint;

    constructor(address _entryPoint) {
        entryPoint = _entryPoint;
    }

    function validateUserOp(UserOperationV06 calldata, bytes32, uint256 missingAccountFunds)
        external
        returns (uint256)
    {
        require(msg.sender == entryPoint, "not from entry point");
        if (missingAccountFunds != 0) {
            (bool ok,) = payable(msg.sender).call{value: missingAccountFunds}("");
            (ok);
        }
        return 0;
    }

    function execute(address target, uint256 value, bytes calldata data) external {
        require(msg.sender == entryPoint, "not from entry point");
        (bool ok, bytes memory ret) = target.call{value: value}(data);
        if (!ok) {
            assembly {
                revert(add(ret, 32), mload(ret))
            }
        }
    }

    receive() external payable {}
}
