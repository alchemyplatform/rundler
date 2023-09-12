import type { Address, BigInt, Bytes, LogStep, LogTracer } from "./types";

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
  expectedStorage: Record<string, Record<string, string>>;
}

interface Phase {
  forbiddenOpcodesUsed: string[];
  forbiddenPrecompilesUsed: string[];
  storageAccesses: StorageAccess[];
  calledBannedEntryPointMethod: boolean;
  addressesCallingWithValue: string[];
  calledNonEntryPointWithValue: boolean;
  ranOutOfGas: boolean;
  undeployedContractAccesses: string[];
}

interface StorageAccess {
  address: string;
  slots: string[];
}

type InternalPhase = Omit<
  Phase,
  | "forbiddenOpcodesUsed"
  | "forbiddenPrecompilesUsed"
  | "storageAccesses"
  | "addressesCallingWithValue"
  | "undeployedContractAccesses"
> & {
  forbiddenOpcodesUsed: StringSet;
  forbiddenPrecompilesUsed: StringSet;
  storageAccesses: Record<string, StringSet>;
  addressesCallingWithValue: StringSet;
  undeployedContractAccesses: StringSet;
};

type StringSet = Record<string, boolean | undefined>;

((): LogTracer<Output> => {
  function stringSet(items: string[]): StringSet {
    const out: StringSet = {};
    items.forEach((item) => (out[item] = true));
    return out;
  }

  const DEPOSIT_TO_SELECTOR = "0xb760faf9";
  const FORBIDDEN_OPCODES = stringSet([
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
  const CALL_OPCODES = stringSet([
    "CALL",
    "CALLCODE",
    "DELEGATECALL",
    "STATICCALL",
  ]);
  // If you add any opcodes to this list, make sure they take the contract
  // address as their *first* argument, or modify the handling below.
  const EXT_OPCODES = stringSet([
    "EXTCODECOPY",
    "EXTCODEHASH",
    "EXTCODELENGTH",
  ]);
  // Whitelisted precompile addresses.
  const PRECOMPILE_WHITELIST = stringSet([
    "0x0000000000000000000000000000000000000001", // ecRecover
    "0x0000000000000000000000000000000000000002", // SHA2-256
    "0x0000000000000000000000000000000000000003", // RIPEMD-160
    "0x0000000000000000000000000000000000000004", // identity
    "0x0000000000000000000000000000000000000005", // modexp
    "0x0000000000000000000000000000000000000006", // ecAdd
    "0x0000000000000000000000000000000000000007", // ecMul
    "0x0000000000000000000000000000000000000008", // ecPairing
    "0x0000000000000000000000000000000000000009", // black2f
  ]);

  const phases: Phase[] = [];
  let revertData: string | null = null;
  const accessedContractAddresses: StringSet = {};
  const associatedSlotsByAddressMap: Record<string, StringSet> = {};
  const allStorageAccesses: Record<string, Record<string, string | null>> = {};
  let factoryCreate2Count = 0;
  let currentPhase = newInternalPhase();
  let entryPointAddress = "";
  let justCalledGas = false;
  let pendingKeccakAddress = "";

  function newInternalPhase(): InternalPhase {
    return {
      forbiddenOpcodesUsed: {},
      forbiddenPrecompilesUsed: {},
      storageAccesses: {},
      calledBannedEntryPointMethod: false,
      addressesCallingWithValue: {},
      calledNonEntryPointWithValue: false,
      ranOutOfGas: false,
      undeployedContractAccesses: {},
    };
  }

  function concludePhase(): void {
    const {
      calledBannedEntryPointMethod,
      calledNonEntryPointWithValue,
      ranOutOfGas,
    } = currentPhase;
    const forbiddenOpcodesUsed = Object.keys(currentPhase.forbiddenOpcodesUsed);
    const forbiddenPrecompilesUsed = Object.keys(
      currentPhase.forbiddenPrecompilesUsed
    );
    const addressesCallingWithValue = Object.keys(
      currentPhase.addressesCallingWithValue
    );
    const undeployedContractAccesses = Object.keys(
      currentPhase.undeployedContractAccesses
    );
    const storageAccesses: StorageAccess[] = [];
    Object.keys(currentPhase.storageAccesses).forEach((address) => {
      const slotsSet = currentPhase.storageAccesses[address];
      storageAccesses.push({ address, slots: Object.keys(slotsSet) });
    });
    const phase: Phase = {
      forbiddenOpcodesUsed,
      forbiddenPrecompilesUsed,
      storageAccesses,
      calledBannedEntryPointMethod,
      addressesCallingWithValue,
      calledNonEntryPointWithValue,
      ranOutOfGas,
      undeployedContractAccesses,
    };
    phases.push(phase);
    currentPhase = newInternalPhase();
  }

  function bigIntToNumber(n: BigInt): number {
    return parseInt(n.toString());
  }

  function computeIfAbsent<K extends keyof any, V>(
    map: Record<K, V>,
    key: K,
    getValue: () => V
  ): V {
    const value = map[key];
    if (value !== undefined) {
      return value;
    }
    const newValue = getValue();
    map[key] = newValue;
    return newValue;
  }

  function getContractCombinedKey(log: LogStep, key: string): string {
    return [toHex(log.contract.getAddress()), key].join(":");
  } 

  return {
    result(_ctx, _db): Output {
      concludePhase();
      const associatedSlotsByAddress: Record<string, string[]> = {};
      Object.keys(associatedSlotsByAddressMap).forEach((address) => {
        const slots = associatedSlotsByAddressMap[address];
        associatedSlotsByAddress[address] = Object.keys(slots);
      });
      const expectedStorage: Record<string, Record<string, string>> = {};
      Object.keys(allStorageAccesses).forEach((address) => {
        const slotAccesses = allStorageAccesses[address];
        const valuesBySlot: Record<string, string> = {};
        let hasValues = false;
        Object.keys(slotAccesses).forEach((slot) => {
          const value = slotAccesses[slot];
          if (value) {
            valuesBySlot[slot] = value;
            hasValues = true;
          }
        });
        if (hasValues) {
          expectedStorage[address] = valuesBySlot;
        }
      });
      return {
        phases,
        revertData,
        accessedContractAddresses: Object.keys(accessedContractAddresses),
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
          (): StringSet => ({})
        )[keccakResult] = true;
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
        if (justCalledGas && !CALL_OPCODES[opcode]) {
          currentPhase.forbiddenOpcodesUsed[getContractCombinedKey(log, "GAS")] = true;
        }
        justCalledGas = opcode === "GAS";
        if (FORBIDDEN_OPCODES[opcode]) {
          currentPhase.forbiddenOpcodesUsed[getContractCombinedKey(log, opcode)] = true;
        }
      }
      if (opcode === "CREATE2") {
        if (phases.length === 0) {
          // In factory phase.
          factoryCreate2Count++;
        } else {
          currentPhase.forbiddenOpcodesUsed[getContractCombinedKey(log, opcode)] = true;
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
            (): StringSet => ({})
          )[slotHex] = true;
        }
        let initialValuesBySlot = computeIfAbsent(
          allStorageAccesses,
          addressHex,
          (): Record<string, string | null> => ({})
        );
        if (!(slotHex in initialValuesBySlot)) {
          // If the first access to this slot is a load, then whatever value it
          // contains will be an expected value. If it's a read, mark it in the
          // map with `null` so we know not to treat its value as expected if we
          // later load from it.
          const expectedValue =
            opcode === "SLOAD" ? toHex(db.getState(address, slot)) : null;
          initialValuesBySlot[slotHex] = expectedValue;
        }
      } else if (EXT_OPCODES[opcode] || CALL_OPCODES[opcode]) {
        const index = EXT_OPCODES[opcode] ? 0 : 1;
        const address = toAddress(log.stack.peek(index).toString(16));
        const addressHex = toHex(address);
        if (!isPrecompiled(address)) {
          if (
            !accessedContractAddresses[addressHex] ||
            currentPhase.undeployedContractAccesses[addressHex]
          ) {
            // The spec says validation must not access code of undeployed
            // contracts, but if the operation is deploying the sender, then
            // the entry point itself accesses the sender before it's deployed,
            // as does a typical factory. We break spec a little bit and allow
            // accessing undeployed code if code is deployed there by the end
            // of the phase.
            if (db.getCode(address).length === 0) {
              currentPhase.undeployedContractAccesses[addressHex] = true;
            } else {
              delete currentPhase.undeployedContractAccesses[addressHex];
            }
          }
          accessedContractAddresses[addressHex] = true;
        } else if (!PRECOMPILE_WHITELIST[addressHex]) {
          currentPhase.forbiddenPrecompilesUsed[getContractCombinedKey(log, addressHex)] = true;
        }
      }
    },

    enter(frame) {
      const from = toHex(frame.getFrom());
      if (from === entryPointAddress) {
        return;
      }
      const isToEntryPoint = toHex(frame.getTo()) === entryPointAddress;
      if (isToEntryPoint) {
        const input = frame.getInput();
        // The spec says that calling entry point methods other than `depositTo`
        // is banned. We deviate and also allow calling the entrypoint with no
        // calldata, as this is equivalent to calling `depositTo` and without it
        // many spec tests fail.
        if (
          input.length > 0 &&
          toHex(input).substring(0, 10) !== DEPOSIT_TO_SELECTOR
        ) {
          currentPhase.calledBannedEntryPointMethod = true;
        }
      }
      const value = frame.getValue();
      if (value != null && value.toString() != "0") {
        if (isToEntryPoint) {
          currentPhase.addressesCallingWithValue[from] = true;
        } else {
          currentPhase.calledNonEntryPointWithValue = true;
        }
      }
    },

    exit(_frame) {},
  };
})();
