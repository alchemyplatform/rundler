import { Address, BigInt, Bytes, LogTracer } from "./types";

declare function isPrecompiled(address: Address): boolean;
declare function toAddress(s: string | Bytes): Address;
declare function toHex(x: Bytes): string;
declare function toWord(s: string | Bytes): Bytes;

interface Output {
  phases: Phase[];
  revertData: string | null;
  accessedContractAddresses: string[];
  associatedSlotsByAddress: Record<string, string[]>;
  factoryCalledCreate2Twice: boolean;
  expectedStorage: ExpectedStorage[];
}

interface Phase {
  forbiddenOpcodesUsed: string[];
  usedInvalidGasOpcode: boolean;
  storageAccesses: StorageAccess[];
  calledHandleOps: boolean;
  calledWithValue: boolean;
  ranOutOfGas: boolean;
  undeployedContractAccesses: string[];
}

interface StorageAccess {
  address: string;
  slots: string[];
}

interface ExpectedStorage {
  address: string;
  slots: ExpectedSlot[];
}

interface ExpectedSlot {
  slot: string;
  value: string;
}

type InternalPhase = Omit<
  Phase,
  "forbiddenOpcodesUsed" | "storageAccesses" | "undeployedContractAccesses"
> & {
  forbiddenOpcodesUsed: Set<string>;
  storageAccesses: Map<string, Set<string>>;
  undeployedContractAccesses: Set<string>;
};

((): LogTracer<Output> => {
  const HANDLE_OPS_SELECTOR = "0x1fad948c";
  const FORBIDDEN_OPCODES = new Set([
    "GASPRICE",
    "GASLIMIT",
    "DIFFICULTY",
    "TIMESTAMP",
    "BASEFEE",
    "BLOCKHASH",
    "NUMBER",
    "SELFBALANCE",
    "BALANCE",
    "ORIGIN",
    "CREATE",
    "COINBASE",
    "SELFDESTRUCT",
  ]);
  // If you add any opcodes to this list, make sure they take the contract
  // address as their *second* argument, or modify the handling below.
  const CALL_OPCODES = new Set([
    "CALL",
    "CALLCODE",
    "DELEGATECALL",
    "STATICCALL",
  ]);
  // If you add any opcodes to this list, make sure they take the contract
  // address as their *first* argument, or modify the handling below.
  const EXT_OPCODES = new Set(["EXTCODECOPY", "EXTCODEHASH", "EXTCODELENGTH"]);

  const phases: Phase[] = [];
  let revertData: string | null = null;
  const accessedContractAddresses = new Set<string>();
  const associatedSlotsByAddressMap = new Map<string, Set<string>>();
  const allStorageAccesses = new Map<string, Map<string, string | null>>();
  let factoryCreate2Count = 0;
  let currentPhase = newInternalPhase();
  let entryPointAddress = "";
  let justCalledGas = false;
  let pendingKeccakAddress = "";

  function newInternalPhase(): InternalPhase {
    return {
      forbiddenOpcodesUsed: new Set(),
      usedInvalidGasOpcode: false,
      storageAccesses: new Map(),
      calledHandleOps: false,
      calledWithValue: false,
      ranOutOfGas: false,
      undeployedContractAccesses: new Set(),
    };
  }

  function concludePhase(): void {
    const {
      usedInvalidGasOpcode,
      calledHandleOps,
      calledWithValue,
      ranOutOfGas,
    } = currentPhase;
    const forbiddenOpcodesUsed = [...currentPhase.forbiddenOpcodesUsed];
    const undeployedContractAccesses = [
      ...currentPhase.undeployedContractAccesses,
    ];
    const storageAccesses: StorageAccess[] = [];
    for (const [address, slotsSet] of currentPhase.storageAccesses) {
      storageAccesses.push({ address, slots: [...slotsSet] });
    }
    const phase: Phase = {
      forbiddenOpcodesUsed,
      usedInvalidGasOpcode,
      storageAccesses,
      calledHandleOps,
      calledWithValue,
      ranOutOfGas,
      undeployedContractAccesses,
    };
    phases.push(phase);
    currentPhase = newInternalPhase();
  }

  function bigIntToNumber(n: BigInt): number {
    return parseInt(n.toString());
  }

  function computeIfAbsent<K, V>(map: Map<K, V>, key: K, getValue: () => V): V {
    const value = map.get(key);
    if (value !== undefined) {
      return value;
    }
    const newValue = getValue();
    map.set(key, newValue);
    return newValue;
  }

  return {
    result(_ctx, _db): Output {
      concludePhase();
      const associatedSlotsByAddress: Record<string, string[]> = {};
      for (const [address, slots] of associatedSlotsByAddressMap) {
        associatedSlotsByAddress[address] = [...slots];
      }
      const expectedStorage: ExpectedStorage[] = [];
      for (const [address, slotAccesses] of allStorageAccesses) {
        const slots: ExpectedSlot[] = [];
        for (const [slot, value] of slotAccesses) {
          if (value) {
            slots.push({ slot, value });
          }
        }
        if (slots.length > 0) {
          expectedStorage.push({ address, slots });
        }
      }
      return {
        phases,
        revertData,
        accessedContractAddresses: [...accessedContractAddresses],
        associatedSlotsByAddress,
        factoryCalledCreate2Twice: factoryCreate2Count > 1,
        expectedStorage,
      };
    },

    fault(_log, _db): void {},

    step(log, db): void {
      if (!entryPointAddress) {
        entryPointAddress = toHex(log.contract.getAddress());
      }
      if (log.getGas() < log.getCost()) {
        currentPhase.ranOutOfGas = true;
      }
      if (pendingKeccakAddress) {
        // We just computed what may be an associated address keccak(addr || X),
        // so the result is now on top of the stack. See the comment in the
        // handling of the KECCAK256 opcode below for details.
        const keccakResult = toHex(toWord(log.stack.peek(0).toString(16)));
        computeIfAbsent(
          associatedSlotsByAddressMap,
          pendingKeccakAddress,
          () => new Set()
        ).add(keccakResult);
        pendingKeccakAddress = "";
      }
      const opcode = log.op.toString();
      const entryPointIsExecuting = log.getDepth() === 1;
      if (entryPointIsExecuting) {
        if (opcode === "NUMBER") {
          concludePhase();
        } else if (opcode === "REVERT") {
          const offset = bigIntToNumber(log.stack.peek(0));
          const length = bigIntToNumber(log.stack.peek(1));
          revertData = toHex(log.memory.slice(offset, offset + length));
        }
      } else {
        // The entry point is allowed to freely call `GAS`, but otherwise we
        // require that a call opcode comes next.
        if (justCalledGas && !CALL_OPCODES.has(opcode)) {
          currentPhase.usedInvalidGasOpcode = true;
        }
        justCalledGas = opcode === "GAS";
        if (FORBIDDEN_OPCODES.has(opcode)) {
          currentPhase.forbiddenOpcodesUsed.add(opcode);
        }
      }
      if (opcode === "CREATE2") {
        if (phases.length === 0) {
          // In factory phase.
          factoryCreate2Count++;
        } else {
          currentPhase.forbiddenOpcodesUsed.add(opcode);
        }
      } else if (opcode === "KECCAK256") {
        //
        const offset = bigIntToNumber(log.stack.peek(0));
        const length = bigIntToNumber(log.stack.peek(1));
        if (length >= 32) {
          const keccakInputWord = toHex(log.memory.slice(offset, offset + 32));
          if (keccakInputWord.startsWith("0x000000000000000000000000")) {
            // The word starts with 24 zeroes = 12 zero bytes, so the remaining
            // 20 bytes may represent an address.
            pendingKeccakAddress = "0x" + keccakInputWord.slice(26);
          }
        }
      } else if (opcode === "SLOAD" || opcode === "SSTORE") {
        const address = log.contract.getAddress();
        const addressHex = toHex(address);
        const slot = toWord(log.stack.peek(0).toString(16));
        const slotHex = toHex(slot);
        if (!entryPointIsExecuting) {
          // The entry point can access whatever it wants, but otherwise track
          // access for this phase so we can check validity later.
          computeIfAbsent(
            currentPhase.storageAccesses,
            addressHex,
            () => new Set<string>()
          ).add(slotHex);
        }
        let initialValuesBySlot = computeIfAbsent(
          allStorageAccesses,
          addressHex,
          () => new Map<string, string | null>()
        );
        if (!initialValuesBySlot.has(slotHex)) {
          // If the first access to this slot is a load, then whatever value it
          // contains will be an expected value.
          const expectedValue =
            opcode === "SLOAD" ? toHex(db.getState(address, slot)) : null;
          initialValuesBySlot.set(slotHex, expectedValue);
        }
      } else if (EXT_OPCODES.has(opcode) || CALL_OPCODES.has(opcode)) {
        const index = EXT_OPCODES.has(opcode) ? 0 : 1;
        const address = toAddress(log.stack.peek(index).toString(16));
        if (!isPrecompiled(address)) {
          const addressHex = toHex(address);
          if (
            !accessedContractAddresses.has(addressHex) ||
            currentPhase.undeployedContractAccesses.has(addressHex)
          ) {
            // The spec says validation must not access code of undeployed
            // contracts, but if the operation is deploying the sender, then
            // the entry point itself accesses the sender before it's deployed,
            // as does a typical factory. We break spec a little bit and allow
            // accessing undeployed code if code is deployed there by the end
            // of the phase.
            if (db.getCode(address).length === 0) {
              currentPhase.undeployedContractAccesses.add(addressHex);
            } else {
              currentPhase.undeployedContractAccesses.delete(addressHex);
            }
          }
          accessedContractAddresses.add(addressHex);
        }
      }
    },

    enter(frame) {
      if (toHex(frame.getTo()) === entryPointAddress) {
        if (toHex(frame.getInput().slice(0, 4)) === HANDLE_OPS_SELECTOR) {
          currentPhase.calledHandleOps = true;
        }
      } else {
        const value = frame.getValue();
        if (value != null && value.toString() !== "0") {
          currentPhase.calledWithValue = true;
        }
      }
    },

    exit(_frame) {},
  };
})();
