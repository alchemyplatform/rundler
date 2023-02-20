import { LogTracer } from "./types";

export function main(): LogTracer {
  return { result(ctx, db) {}, fault(log, db) {} };
}
