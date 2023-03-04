import { Address, BigInt, Bytes, LogTracer } from "./types";

declare function isPrecompiled(address: Address): boolean;
declare function toAddress(s: string | Bytes): Address;
declare function toHex(x: Bytes): string;
declare function toWord(s: string | Bytes): Bytes;

interface Output {
  phases: Phase[];
  revertData: string;
  accessedContractAddresses: string[];
  associatedSlotsByAddress: Record<string, string[]>;
  factoryCalledCreate2Twice: boolean;
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
  accesses: SlotAccess[];
}

interface SlotAccess {
  slot: string;
  initialValue: string | null;
}

type InternalPhase = Omit<
  Phase,
  "forbiddenOpcodesUsed" | "storageAccesses" | "undeployedContractAccesses"
> & {
  forbiddenOpcodesUsed: Set<string>;
  storageAccesses: Map<string, Map<string, string | null>>;
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
  let revertData = "";
  const accessedContractAddresses = new Set<string>();
  const associatedSlotsByAddressMap = new Map<string, Set<string>>();
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
    for (const [address, initialValuesBySlot] of currentPhase.storageAccesses) {
      const storageAccess: StorageAccess = { address, accesses: [] };
      for (const [slot, initialValue] of initialValuesBySlot) {
        storageAccess.accesses.push({ slot, initialValue });
      }
      storageAccesses.push(storageAccess);
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
      return {
        phases,
        revertData,
        accessedContractAddresses: [...accessedContractAddresses],
        associatedSlotsByAddress,
        factoryCalledCreate2Twice: factoryCreate2Count > 1,
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
        const keccakResult = toHex(toWord(log.stack.peek(0).toString(16)));
        computeIfAbsent(
          associatedSlotsByAddressMap,
          pendingKeccakAddress,
          () => new Set()
        ).add(keccakResult);
        pendingKeccakAddress = "";
      }
      const opcode = log.op.toString();
      if (log.getDepth() === 1) {
        // EntryPoint is executing.
        if (opcode === "NUMBER") {
          concludePhase();
        } else if (opcode === "REVERT") {
          const offset = bigIntToNumber(log.stack.peek(0));
          const length = bigIntToNumber(log.stack.peek(1));
          revertData = toHex(log.memory.slice(offset, offset + length));
        }
      } else {
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
        const offset = bigIntToNumber(log.stack.peek(0));
        const length = bigIntToNumber(log.stack.peek(1));
        if (length >= 32) {
          pendingKeccakAddress = toHex(
            log.memory.slice(offset + 12, offset + 32)
          );
        }
      }
      if (opcode === "SLOAD" || opcode === "SSTORE") {
        const address = log.contract.getAddress();
        const addressHex = toHex(address);
        const slot = toWord(log.stack.peek(0).toString(16));
        const slotHex = toHex(slot);
        const slotAccesses = computeIfAbsent(
          currentPhase.storageAccesses,
          addressHex,
          () => new Map<string, string | null>()
        );
        if (!slotAccesses.has(slotHex)) {
          const expectedValue =
            opcode === "SLOAD" ? toHex(db.getState(address, slot)) : null;
          slotAccesses.set(slotHex, expectedValue);
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
