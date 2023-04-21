import type { BigInt, Bytes, LogStep, LogTracer } from "./types";

declare function toHex(x: Bytes): string;

interface Output {
  phases: Phase[];
  revertData: string | null;
  gasUsed: number;
}

interface Phase {
  gasUsed: number;
  // we don't actually use this in the result, but I added it here for debugging
  gasRemainingAtConclusion: number;
  accountRevertData: string | null;
}

interface InternalPhase {
  gasRemainingAtConclusion: number;
  calledInnerHandleOps: boolean;
  accountRevertData: string | null;
}

((): LogTracer<Output> => {
  const INNER_HANDLE_OPS_SELECTOR = "0x1d732756";
  const phases: InternalPhase[] = [];
  let entryPointAddress: string | null = null;
  let revertData: string | null = null;
  let currentPhaseIdx = 0;
  let currentPhase = newInternalPhase();

  function newInternalPhase(): InternalPhase {
    return {
      gasRemainingAtConclusion: 0,
      calledInnerHandleOps: false,
      accountRevertData: null,
    };
  }

  function bigIntToNumber(n: BigInt): number {
    return parseInt(n.toString());
  }

  function concludePhase(gasRemainingAtConclusion: number) {
    if (currentPhaseIdx < 2) {
      currentPhaseIdx++;
      return;
    }

    currentPhase.gasRemainingAtConclusion = gasRemainingAtConclusion;
    phases.push(currentPhase);
    currentPhase = newInternalPhase();
  }

  function getRevertDataFromLog(log: LogStep): string {
    const offset = bigIntToNumber(log.stack.peek(0));
    const length = bigIntToNumber(log.stack.peek(1));
    return toHex(log.memory.slice(offset, offset + length));
  }

  return {
    result(ctx, db) {
      concludePhase(ctx.gas - ctx.gasUsed);
      let gasBudget = ctx.gas;

      return {
        phases: phases.map((p) => ({
          gasUsed: (() => {
            const used = gasBudget - p.gasRemainingAtConclusion;
            gasBudget = p.gasRemainingAtConclusion;
            return used;
          })(),
          gasRemainingAtConclusion: p.gasRemainingAtConclusion,
          accountRevertData: p.accountRevertData,
        })),
        gasUsed: ctx.gasUsed,
        revertData,
      };
    },
    step(log) {
      if (!entryPointAddress) {
        entryPointAddress = toHex(log.contract.getAddress());
      }
      const entryPointIsExecuting = log.getDepth() === 1;
      // account executes at depth 3 during phase 2 of simulation
      // depth is 3 because the entrypoint calls itself first (this.innerHandleOps) which then calls the account
      const accountIsExecuting =
        currentPhase.calledInnerHandleOps && log.getDepth() === 3;

      const opcode = log.op.toString();

      if (entryPointIsExecuting) {
        switch (opcode) {
          case "NUMBER":
            concludePhase(log.getGas());
            break;
          case "REVERT":
            revertData = getRevertDataFromLog(log);
            break;
          default:
            break;
        }
      } else if (accountIsExecuting) {
        switch (opcode) {
          case "REVERT":
            currentPhase.accountRevertData = getRevertDataFromLog(log);
            break;
          default:
            break;
        }
      }
    },
    fault() {},

    enter(frame) {
      if (toHex(frame.getTo()) === entryPointAddress) {
        if (toHex(frame.getInput().slice(0, 4)) === INNER_HANDLE_OPS_SELECTOR) {
          currentPhase.calledInnerHandleOps = true;
        }
      }
    },
    exit(_frame) {},
  };
})();
