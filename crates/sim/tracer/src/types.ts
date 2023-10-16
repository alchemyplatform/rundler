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

// Copied from
// https://github.com/eth-infinitism/bundler/blob/main/packages/bundler/src/GethTracer.ts,
// with some corrections.

export interface BigInt {
  value: number;
  sign: boolean;
  isSmall: boolean;
  toString(radix?: 16): string;
}

// Only the following properties are available on Matic.
export type Bytes = Pick<
  Uint8Array,
  "length" | "byteLength" | "byteOffset" | "buffer" | "set" | "subarray"
>;
export type Address = Bytes; // Always length 20

export interface LogContext {
  type: "CALL" | "CREATE"; // one of the two values CALL and CREATE
  from: Address; // Address, sender of the transaction
  to: Address; // Address, target of the transaction
  input: Bytes; // Buffer, input transaction data
  gas: number; // Number, gas budget of the transaction
  gasUsed: number; //  Number, amount of gas used in executing the transaction (excludes txdata costs)
  gasPrice: number; // Number, gas price configured in the transaction being executed
  intrinsicGas: number; // Number, intrinsic gas for the transaction being executed
  value: BigInt; // big.Int, amount to be transferred in wei
  block: number; // Number, block number
  output: Bytes; // Buffer, value returned from EVM
  time: string; // String, execution runtime

  // And these fields are only available for tracing mined transactions (i.e. not available when doing debug_traceCall):
  blockHash?: Bytes; // - Buffer, hash of the block that holds the transaction being executed
  txIndex?: number; // - Number, index of the transaction being executed in the block
  txHash?: Bytes; // - Buffer, hash of the transaction being executed
}

export interface LogTracer<T> {
  // mandatory: result, fault
  // result is a function that takes two arguments ctx and db, and is expected to return
  // a JSON-serializable value to return to the RPC caller.
  result: (ctx: LogContext, db: LogDb) => T;

  // fault is a function that takes two arguments, log and db, just like step and is
  // invoked when an error happens during the execution of an opcode which wasn’t reported in step. The method log.getError() has information about the error.
  fault: (log: LogStep, db: LogDb) => void;

  // optional (config is geth-level "cfg")
  setup?: (config: any) => any;

  // optional
  step?: (log: LogStep, db: LogDb) => any;

  // enter and exit must be present or omitted together.
  enter?: (frame: LogCallFrame) => void;

  exit?: (frame: LogFrameResult) => void;
}

export interface LogCallFrame {
  // - returns a string which has the type of the call frame
  getType: () => string;
  // - returns the address of the call frame sender
  getFrom: () => Address;
  // - returns the address of the call frame target
  getTo: () => Address;
  // - returns the input as a buffer
  getInput: () => Bytes;
  // - returns a Number which has the amount of gas provided for the frame
  getGas: () => number;
  // - returns a big.Int with the amount to be transferred only if available, otherwise undefined
  getValue: () => BigInt | undefined;
}

export interface LogFrameResult {
  getGasUsed: () => number; // - returns amount of gas used throughout the frame as a Number
  getOutput: () => Bytes; // - returns the output as a buffer
  getError: () => any; // - returns an error if one occurred during execution and undefined` otherwise
}

export interface LogOpCode {
  isPush: () => boolean; // returns true if the opcode is a PUSHn
  toString: () => string; // returns the string representation of the opcode
  toNumber: () => number; // returns the opcode’s number
}

export interface LogMemory {
  slice: (start: number, stop: number) => Bytes; // returns the specified segment of memory as a byte slice
  getUint: (offset: number) => Bytes; // returns the 32 bytes at the given offset
  length: () => number; // returns the memory size
}

export interface LogStack {
  peek: (idx: number) => BigInt; // returns the idx-th element from the top of the stack (0 is the topmost element) as a big.Int
  length: () => number; // returns the number of elements in the stack
}

export interface LogContract {
  getCaller: () => Address; // returns the address of the caller
  getAddress: () => Address; // returns the address of the current contract
  getValue: () => BigInt; // returns the amount of value sent from caller to contract as a big.Int
  getInput: () => Bytes; // returns the input data passed to the contract
}

export interface LogStep {
  op: LogOpCode; // Object, an OpCode object representing the current opcode
  stack: LogStack; // Object, a structure representing the EVM execution stack
  memory: LogMemory; // Object, a structure representing the contract’s memory space
  contract: LogContract; // Object, an object representing the account executing the current operation

  getPC: () => number; // returns a Number with the current program counter
  getGas: () => number; // returns a Number with the amount of gas remaining
  getCost: () => number; // returns the cost of the opcode as a Number
  getDepth: () => number; // returns the execution depth as a Number
  getRefund: () => number; // returns the amount to be refunded as a Number
  getError: () => string | undefined; //  returns information about the error if one occurred, otherwise returns undefined
  // If error is non-empty, all other fields should be ignored.
}

export interface LogDb {
  getBalance: (address: string) => BigInt; // - returns a big.Int with the specified account’s balance
  getNonce: (address: string) => number; // returns a Number with the specified account’s nonce
  getCode: (address: Address) => Bytes; // returns a byte slice with the code for the specified account
  getState: (address: Address, hash: Bytes) => any; // returns the state value for the specified account and the specified hash
  exists: (address: string) => boolean; // returns true if the specified address exists
}
