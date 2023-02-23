import { Bytes, LogTracer } from "./types";

declare function toHex(x: Bytes): string;

interface Output {}

((): LogTracer<Output> => {
  let error: string | undefined;
  let revertData: string | undefined;
  let logs: string[] = [];

  function log(s: string = ""): void {
    logs.push(s);
  }

  function logAboutValue(x: any): void {
    log(`Type: ${typeof x}`);
    log(`Class: ${x.constructor.name}`);
    log(`Keys:`);
    logProperties(x);
    log(`Prototype keys:`);
    logProperties(x.constructor.prototype);
  }

  function logProperties(x: any): void {
    Object.getOwnPropertyNames(x).forEach((key) => log(`  ${key}`));
  }

  const that = this;

  return {
    result(ctx, db): Output {
      log("BigInt:");
      log();
      logAboutValue(ctx.value);
      log();
      log("Address is an array of 20 entries. Each entry:");
      log();
      logAboutValue(ctx.to[0]);
      log();
      log("Buffer:");
      log();
      logAboutValue(ctx.input);
      log();
      log("Built-ins:");
      logProperties(that);

      return { error, revertData, logs };
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
