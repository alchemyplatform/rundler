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


// Adapted with minimal changes from: https://github.com/eth-infinitism/bundler/blob/main/packages/validation-manager/src/BundlerCollectorTracer.ts


// javascript code of tracer function
// NOTE: we process this locally for hardhat, but send to geth for remote tracing.
// should NOT "require" anything, or use logs.
// see LogTrace for valid types (but alas, this one must be javascript, not typescript).

// This file contains references to validation rules, in the format [xxx-###]
// where xxx is OP/STO/COD/EP/SREP/EREP/UREP/ALT, and ### is a number
// the validation rules are defined in erc-aa-validation.md

import { Address, Bytes, LogCallFrame, LogContext, LogDb, LogFrameResult, LogStep, LogTracer } from './types'

// functions available in a context of geth tracer
declare function toAddress(s: string | Bytes): Address;
declare function toHex(x: Bytes): string;
declare function toWord(s: string | Bytes): Bytes;

/**
 * return type of our BundlerCollectorTracer.
 * collect access and opcodes, split into "levels" based on NUMBER opcode
 * keccak, calls and logs are collected globally, since the levels are unimportant for them.
 */
export interface BundlerTracerResult {
  /**
   * storage and opcode info, collected on top-level calls from EntryPoint
   */
  callsFromEntryPoint: TopLevelCallInfo[]

  /**
   * values passed into KECCAK opcode
   */
  keccak: string[]

  /**
   * calls and returns, collected globally
   */
  calls: Array<ExitInfo | MethodInfo>

  /**
   * logs, collected globally
   */
  logs: LogInfo[]

  /**
   * expected storage slots, collected globally
   */
  expectedStorage: Record<string, Record<string, string>>

  debug: string[]
}

export interface MethodInfo {
  type: string
  from: string
  to: string
  method: string
  value: any
  gas: number
}

export interface ExitInfo {
  type: 'REVERT' | 'RETURN'
  gasUsed: number
  data: string
}

export interface TopLevelCallInfo {
  topLevelMethodSig: string
  topLevelTargetAddress: string
  opcodes: { [opcode: string]: number }
  access: { [address: string]: AccessInfo }
  contractInfo: { [addr: string]: ContractInfo }
  extCodeAccessInfo: { [addr: string]: string }
  oog?: boolean
}

/**
 * Contract info
 * 
 * It is illegal to access contracts with no code in validation even if it gets deployed later.
 * This means we need to store the {@link contractSize} of accessed addresses at the time of access.
 * 
 * Capture the "header" of the contract code for validation.
 */
export interface ContractInfo {
  opcode: string
  length: number
  header: string
}

export interface AccessInfo {
  // slot value, just prior to this operation
  reads: { [slot: string]: string }
  // count of writes.
  writes: { [slot: string]: number }
}

export interface LogInfo {
  topics: string[]
  data: string
}

interface RelevantStepData {
  opcode: string
  stackTop3: any[]
}

/**
 * type-safe local storage of our collector. contains all return-value properties.
 * (also defines all "trace-local" variables and functions)
 */
interface BundlerCollectorTracer extends LogTracer<BundlerTracerResult>, BundlerTracerResult {
  lastOp: string
  lastThreeOpcodes: RelevantStepData[]
  stopCollectingTopic: string
  stopCollecting: boolean
  currentLevel: TopLevelCallInfo
  topLevelCallCounter: number
  allStorageAccesses: Record<string, Record<string, string | null>>
  countSlot: (list: { [key: string]: number | undefined }, key: any) => void
  computeIfAbsent<K extends keyof any, V>(
    map: Record<K, V>,
    key: K,
    getValue: () => V
  ): V
} 

/**
 * tracer to collect data for opcode banning.
 * this method is passed as the "tracer" for eth_traceCall (note, the function itself)
 *
 * returned data:
 *  numberLevels: opcodes and memory access, split on execution of "number" opcode.
 *  keccak: input data of keccak opcode.
 *  calls: for each call, an array of [type, from, to, value]
 *  slots: accessed slots (on any address)
 */
((): BundlerCollectorTracer => {
  return {
    callsFromEntryPoint: [],
    currentLevel: null as any,
    keccak: [],
    expectedStorage: {},
    calls: [],
    logs: [],
    debug: [],
    lastOp: '',
    lastThreeOpcodes: [],
    // event sent after all validations are done: keccak("BeforeExecution()")
    stopCollectingTopic: 'bb47ee3e183a558b1a2ff0874b079f3fc5478b7454eacf2bfc5af2ff5878f972',
    stopCollecting: false,
    topLevelCallCounter: 0,
    allStorageAccesses: {},

    fault (log: LogStep, _db: LogDb): void {
      var err = "";
      const log_err = log.getError();
      if (log_err != undefined) {
        err = log_err.toString()
      }
      this.debug.push('fault depth=', log.getDepth().toString(), ' gas=', log.getGas().toString(), ' cost=', log.getCost().toString(), ' err=', err)
    },

    result (_ctx: LogContext, _db: LogDb): BundlerTracerResult {
      Object.keys(this.allStorageAccesses).forEach((address) => {
        const slotAccesses = this.allStorageAccesses[address];
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
          this.expectedStorage[address] = valuesBySlot;
        }
      });

      return {
        callsFromEntryPoint: this.callsFromEntryPoint,
        keccak: this.keccak,
        logs: this.logs,
        calls: this.calls,
        expectedStorage: this.expectedStorage,
        debug: this.debug // for internal debugging.
      }
    },

    enter (frame: LogCallFrame): void {
      if (this.stopCollecting) {
        return
      }
      // this.debug.push('enter gas=', frame.getGas(), ' type=', frame.getType(), ' to=', toHex(frame.getTo()), ' in=', toHex(frame.getInput()).slice(0, 500))
      this.calls.push({
        type: frame.getType(),
        from: toHex(frame.getFrom()),
        to: toHex(frame.getTo()),
        method: toHex(frame.getInput()).slice(0, 10),
        gas: frame.getGas(),
        value: frame.getValue()
      })
    },
    exit (frame: LogFrameResult): void {
      if (this.stopCollecting) {
        return
      }
      this.calls.push({
        type: frame.getError() != null ? 'REVERT' : 'RETURN',
        gasUsed: frame.getGasUsed(),
        data: toHex(frame.getOutput()).slice(0, 4000)
      })
    },

    // increment the "key" in the list. if the key is not defined yet, then set it to "1"
    countSlot (list: { [key: string]: number | undefined }, key: any) {
      list[key] = (list[key] ?? 0) + 1
    },

    computeIfAbsent<K extends keyof any, V>(
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
    },


    step (log: LogStep, db: LogDb): any {
      if (this.stopCollecting) {
        return
      }
      const opcode = log.op.toString()

      const stackSize = log.stack.length()
      const stackTop3 = []
      for (let i = 0; i < 3 && i < stackSize; i++) {
        stackTop3.push(log.stack.peek(i))
      }
      this.lastThreeOpcodes.push({ opcode, stackTop3 })
      if (this.lastThreeOpcodes.length > 3) {
        this.lastThreeOpcodes.shift()
      }
      // this.debug.push(this.lastOp + '-' + opcode + '-' + log.getDepth() + '-' + log.getGas() + '-' + log.getCost())
      if (log.getGas() < log.getCost() || (
        // special rule for SSTORE with gas metering
        opcode === 'SSTORE' && log.getGas() < 2300)
      ) {
        this.currentLevel.oog = true
      }

      if (opcode === 'REVERT' || opcode === 'RETURN') {
        if (log.getDepth() === 1) {
          // exit() is not called on top-level return/revent, so we reconstruct it
          // from opcode
          const ofs = parseInt(log.stack.peek(0).toString())
          const len = parseInt(log.stack.peek(1).toString())
          const data = toHex(log.memory.slice(ofs, ofs + len)).slice(0, 4000)
          // this.debug.push(opcode + ' ' + data)
          this.calls.push({
            type: opcode,
            gasUsed: 0,
            data
          })
        }
        // NOTE: flushing all history after RETURN
        this.lastThreeOpcodes = []
      }

      if (log.getDepth() === 1) {
        if (opcode === 'CALL' || opcode === 'STATICCALL') {
          // stack.peek(0) - gas
          const addr = toAddress(log.stack.peek(1).toString(16))
          const topLevelTargetAddress = toHex(addr)
          // stack.peek(2) - value
          const ofs = parseInt(log.stack.peek(3).toString())
          // stack.peek(4) - len
          const topLevelMethodSig = toHex(log.memory.slice(ofs, ofs + 4))

          this.currentLevel = this.callsFromEntryPoint[this.topLevelCallCounter] = {
            topLevelMethodSig,
            topLevelTargetAddress,
            access: {},
            opcodes: {},
            extCodeAccessInfo: {},
            contractInfo: {}
          }
          this.topLevelCallCounter++
        } else if (opcode === 'LOG1') {
          // ignore log data ofs, len
          const topic = log.stack.peek(2).toString(16)
          if (topic === this.stopCollectingTopic) {
            this.stopCollecting = true
          }
        }
        this.lastOp = ''
        return
      }

      const lastOpInfo = this.lastThreeOpcodes[this.lastThreeOpcodes.length - 2]
      // store all addresses touched by EXTCODE* opcodes
      if (lastOpInfo?.opcode?.match(/^(EXT.*)$/) != null) {
        const addr = toAddress(lastOpInfo.stackTop3[0].toString(16))
        const addrHex = toHex(addr)
        const last3opcodesString = this.lastThreeOpcodes.map(x => x.opcode).join(' ')
        // only store the last EXTCODE* opcode per address - could even be a boolean for our current use-case
        // [OP-051]
        if (last3opcodesString.match(/^(\w+) EXTCODESIZE ISZERO$/) == null) {
          this.currentLevel.extCodeAccessInfo[addrHex] = opcode
          // this.debug.push(`potentially illegal EXTCODESIZE without ISZERO for ${addrHex}`)
        } else {
          // this.debug.push(`safe EXTCODESIZE with ISZERO for ${addrHex}`)
        }
      }

      // not using 'isPrecompiled' to only allow the ones defined by the ERC-4337 as stateless precompiles
      // [OP-062]
      const isAllowedPrecompiled: (address: any) => boolean = (address) => {
        const addrHex = toHex(address)
        const addressInt = parseInt(addrHex)
        // this.debug.push(`isPrecompiled address=${addrHex} addressInt=${addressInt}`)

        // MODIFICATION: allow precompile RIP-7212 through - which is at 256
        return (addressInt > 0 && addressInt < 10) || addressInt == 256
      }
      // [OP-041]
      if (opcode.match(/^(EXT.*|CALL|CALLCODE|DELEGATECALL|STATICCALL)$/) != null) {
        const idx = opcode.startsWith('EXT') ? 0 : 1
        const addr = toAddress(log.stack.peek(idx).toString(16))
        const addrHex = toHex(addr)
        // this.debug.push('op=' + opcode + ' last=' + this.lastOp + ' stacksize=' + log.stack.length() + ' addr=' + addrHex)
        if (this.currentLevel.contractInfo[addrHex] == null && !isAllowedPrecompiled(addr)) {
          this.currentLevel.contractInfo[addrHex] = {
            length: db.getCode(addr).length,
            opcode,
            header: toHex(db.getCode(addr).subarray(0, 3))
          }
        }
      }

      // [OP-012]
      if (this.lastOp === 'GAS' && !opcode.includes('CALL')) {
        // count "GAS" opcode only if not followed by "CALL"
        this.countSlot(this.currentLevel.opcodes, 'GAS')
      }
      if (opcode !== 'GAS') {
        // ignore "unimportant" opcodes:
        if (opcode.match(/^(DUP\d+|PUSH\d+|SWAP\d+|POP|ADD|SUB|MUL|DIV|EQ|LTE?|S?GTE?|SLT|SH[LR]|AND|OR|NOT|ISZERO)$/) == null) {
          this.countSlot(this.currentLevel.opcodes, opcode)
        }
      }
      this.lastOp = opcode

      // MODIFICATION: [OP-070] - Treat TLOAD and TSTORE as SLOAD and SSTORE
      if (opcode === 'SLOAD' || opcode === 'SSTORE' || opcode === 'TLOAD' || opcode === 'TSTORE') {
        const slot = toWord(log.stack.peek(0).toString(16))
        const slotHex = toHex(slot)
        const addr = log.contract.getAddress()
        const addrHex = toHex(addr)
        let access = this.currentLevel.access[addrHex]

        let initialValuesBySlot = this.computeIfAbsent(
          this.allStorageAccesses,
          addrHex,
          (): Record<string, string | null> => ({})
        );

        if (access == null) {
          access = {
            reads: {},
            writes: {}
          }
          this.currentLevel.access[addrHex] = access
        }
        if (opcode === 'SLOAD' || opcode === 'TLOAD') {
          // read slot values before this UserOp was created
          // (so saving it if it was written before the first read)
          if (access.reads[slotHex] == null && access.writes[slotHex] == null) {
            access.reads[slotHex] = toHex(db.getState(addr, slot))
          }

          if (!(slotHex in initialValuesBySlot)) {
            initialValuesBySlot[slotHex] = toHex(db.getState(addr, slot));
          }
        } else {
          this.countSlot(access.writes, slotHex)

          if (!(slotHex in initialValuesBySlot)) {
            initialValuesBySlot[slotHex] = null;
          }
        }
      }

      if (opcode === 'KECCAK256') {
        // collect keccak on 64-byte blocks
        const ofs = parseInt(log.stack.peek(0).toString())
        const len = parseInt(log.stack.peek(1).toString())
        // currently, solidity uses only 2-word (6-byte) for a key. this might change..
        // still, no need to return too much
        if (len > 20 && len < 512) {
          // if (len === 64) {
          this.keccak.push(toHex(log.memory.slice(ofs, ofs + len)))
        }
      } else if (opcode.startsWith('LOG')) {
        const count = parseInt(opcode.substring(3))
        const ofs = parseInt(log.stack.peek(0).toString())
        const len = parseInt(log.stack.peek(1).toString())
        const topics = []
        for (let i = 0; i < count; i++) {
          // eslint-disable-next-line @typescript-eslint/restrict-plus-operands
          topics.push('0x' + log.stack.peek(2 + i).toString(16))
        }
        const data = toHex(log.memory.slice(ofs, ofs + len))
        this.logs.push({
          topics,
          data
        })
      }
    }
  }
})();