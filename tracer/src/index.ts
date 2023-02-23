import { LogTracer } from "./types";

declare const big: { NewInt(x: number): BigInt };

declare function toHex(x: any): string;

// For a bad opcode, I want to know; which part it's in, and what contract/method called it.
//

interface Output {
  // opcodeViolationsByContract: Record<string,
  // forbiddenOpcodeCounts: Record<string, number>,
  // invalidGasOpcodeCount: number;
  // storageAccessCounts: Record<string, Record<string, number>>;
}

interface Section {}

((): LogTracer<Output> => {
  let error: string | undefined;
  let revertData: string | undefined;
  let config: any;

  return {
    setup(_config) {
      config = _config;
    },

    result(ctx, db): Output {
      return {
        message: "Hello!!",
        error,
        revertData,
        config,
      };
    },

    fault(log, db): void {
      error = log.getError();
    },

    step(log, db): void {
      if (log.getDepth() === 1 && log.op.toString() === "REVERT") {
        const offset = parseInt(log.stack.peek(0).toString());
        const length = parseInt(log.stack.peek(1).toString());
        revertData = toHex(log.memory.slice(offset, offset + length));
      }
    },
  };
})();
