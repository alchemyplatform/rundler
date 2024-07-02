// This file is part of Rundler.
//
// Rundler is free software: you can redistribute it and/or modify it under the
// terms of the GNU Lesser General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later version.
//
// Rundler is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with Rundler.
// If not, see https://www.gnu.org/licenses/.

import type { Address, BigInt, Bytes, LogStep, LogTracer } from "./types";

declare function isPrecompiled(address: Address): boolean;
declare function toAddress(s: string | Bytes): Address;
declare function toHex(x: Bytes): string;
declare function toWord(s: string | Bytes): Bytes;

interface Output {
  phases: Phase[];
  revertData: string | null;
  accessedContracts: Record<string, ContractInfo>;
  associatedSlotsByAddress: Record<string, string[]>;
  factoryCalledCreate2Twice: boolean;
  expectedStorage: Record<string, Record<string, string>>;
}

interface Phase {
  forbiddenOpcodesUsed: string[];
  forbiddenPrecompilesUsed: string[];
  storageAccesses: Record<string, AccessInfo>;
  calledBannedEntryPointMethod: boolean;
  addressesCallingWithValue: string[];
  calledNonEntryPointWithValue: boolean;
  ranOutOfGas: boolean;
  undeployedContractAccesses: string[];
  extCodeAccessInfo: Record<string, string>;
}

interface AccessInfo {
  // slot value, just prior this operation
  reads: { [slot: string]: string }
  // count of writes.
  writes: { [slot: string]: number }
}

interface RelevantStepData {
  opcode: string;
  stackEnd: BigInt | null;
}

interface ContractInfo {
  opcode: string;
  length: number;
  header: string;
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
  storageAccesses: Record<string, AccessInfo>;
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
  const SSTORE_REQUIRED_GAS = 2300;
  const FORBIDDEN_OPCODES = stringSet([
    "GASPRICE",
    "GASLIMIT",
    "DIFFICULTY",
    "TIMESTAMP",
    "BASEFEE",
    "BLOCKHASH",
    "BLOBBASEFEE",
    "BLOBHASH",
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
  const EXT_OPCODES = stringSet(["EXTCODECOPY", "EXTCODEHASH", "EXTCODESIZE"]);

  const READ_WRITE_OPCODES = stringSet(["SSTORE", "SLOAD", "TSTORE", "TLOAD"]);
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
    "0x0000000000000000000000000000000000000100", // RIP-7212
  ]);

  const phases: Phase[] = [];
  let revertData: string | null = null;
  const accessedContracts: Record<string, ContractInfo> = {};
  const associatedSlotsByAddressMap: Record<string, StringSet> = {};
  const allStorageAccesses: Record<string, Record<string, string | null>> = {};
  let factoryCreate2Count = 0;
  let currentPhase = newInternalPhase();
  let entryPointAddress = "";
  let pendingKeccakAddress = "";
  let last: RelevantStepData | null = null;
  let secondLast: RelevantStepData | null = null;

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
      extCodeAccessInfo: {},
    };
  }

  function concludePhase(): void {
    const {
      calledBannedEntryPointMethod,
      calledNonEntryPointWithValue,
      ranOutOfGas,
      extCodeAccessInfo,
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

    const phase: Phase = {
      forbiddenOpcodesUsed,
      forbiddenPrecompilesUsed,
      storageAccesses: currentPhase.storageAccesses,
      calledBannedEntryPointMethod,
      addressesCallingWithValue,
      calledNonEntryPointWithValue,
      ranOutOfGas,
      undeployedContractAccesses,
      extCodeAccessInfo,
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

  function countSlot(list: { [key: string]: number | undefined }, key: any) {
    list[key] = (list[key] ?? 0) + 1;
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
        accessedContracts,
        associatedSlotsByAddress,
        factoryCalledCreate2Twice: factoryCreate2Count > 1,
        expectedStorage,
      };
    },


    fault(_log, _db): void { },

    step(log, db): void {
      if (!entryPointAddress) {
        entryPointAddress = toHex(log.contract.getAddress());
      }

      const opcode = log.op.toString();

      if (log.getGas() < log.getCost() || (
        opcode === 'SSTORE' && log.getGas() < SSTORE_REQUIRED_GAS
      )) {
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
        if (last?.opcode === "GAS" && !CALL_OPCODES[opcode]) {
          currentPhase.forbiddenOpcodesUsed[
            getContractCombinedKey(log, "GAS")
          ] = true;
        }

        if (FORBIDDEN_OPCODES[opcode]) {
          currentPhase.forbiddenOpcodesUsed[
            getContractCombinedKey(log, opcode)
          ] = true;
        }
      }

      if (secondLast && EXT_OPCODES[secondLast.opcode]) {
        const opString = `${secondLast.opcode} ${last?.opcode}`;
        if (secondLast?.stackEnd && opString !== "EXTCODESIZE ISZERO") {
          const addr = toAddress(secondLast.stackEnd.toString(16));
          const hexAddr = toHex(addr);
          currentPhase.extCodeAccessInfo[hexAddr] = opcode;
        }
      }

      if (opcode === "CREATE2") {
        if (phases.length === 0) {
          // In factory phase.
          factoryCreate2Count++;
        } else {
          currentPhase.forbiddenOpcodesUsed[
            getContractCombinedKey(log, opcode)
          ] = true;
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
      } else if (READ_WRITE_OPCODES[opcode]) {
        const address = log.contract.getAddress();
        const addressHex = toHex(address);
        const slot = toWord(log.stack.peek(0).toString(16));
        const slotHex = toHex(slot);
        let access = computeIfAbsent(
          currentPhase.storageAccesses,
          addressHex,
          (): AccessInfo => ({
            reads: {},
            writes: {},
          }));

        if (!entryPointIsExecuting) {

          // The entry point can access whatever it wants, but otherwise track
          // access for this phase so we can check validity later.
          if (opcode == "SLOAD") {
            // Read access
            if (access.reads[slotHex] == null && access.writes[slotHex] == null) {
              access.reads[slotHex] = toHex(db.getState(address, slot));
            }

          } else {
            // Write access
            countSlot(access.writes, slotHex)
          }
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
        if (!isPrecompiled(address) && !PRECOMPILE_WHITELIST[addressHex]) {
          if (
            !accessedContracts[addressHex] ||
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
          accessedContracts[addressHex] = {
            header: toHex(db.getCode(address).subarray(0, 3)),
            opcode,
            length: db.getCode(address).length,
          };
        } else if (!PRECOMPILE_WHITELIST[addressHex]) {
          currentPhase.forbiddenPrecompilesUsed[
            getContractCombinedKey(log, addressHex)
          ] = true;
        }
      }

      secondLast = last;
      const stackEnd = log.stack.length() > 0 ? log.stack.peek(0) : null;
      last = { opcode, stackEnd };
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

    exit(_frame) { },
  };
})();
