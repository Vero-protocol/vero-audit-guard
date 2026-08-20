/**
 * Simple Abstract Interpreter for Integer Overflow Detection
 * Implements an Interval Domain for static analysis
 */

export class Interval {
  constructor(public min: bigint, public max: bigint) {}

  static fromValue(val: bigint): Interval {
    return new Interval(val, val);
  }

  add(other: Interval): Interval {
    return new Interval(this.min + other.min, this.max + other.max);
  }

  sub(other: Interval): Interval {
    return new Interval(this.min - other.max, this.max - other.min);
  }

  mul(other: Interval): Interval {
    const vals = [
      this.min * other.min,
      this.min * other.max,
      this.max * other.min,
      this.max * other.max,
    ];
    let min = vals[0];
    let max = vals[0];
    for (const v of vals) {
      if (v < min) min = v;
      if (v > max) max = v;
    }
    return new Interval(min, max);
  }

  /**
   * Check if the interval is within the bounds of a specific integer type
   */
  isWithinBounds(min: bigint, max: bigint): boolean {
    return this.min >= min && this.max <= max;
  }

  toString(): string {
    return `[${this.min}, ${this.max}]`;
  }
}

export type VariableState = Map<string, Interval>;

export class AbstractInterpreter {
  // Support for common Rust integer types
  static readonly U32_MAX = BigInt("4294967295");
  static readonly U64_MAX = BigInt("18446744073709551615");
  static readonly U128_MAX = BigInt("340282366920938463463374607431768211455");

  /**
   * Evaluates an expression given the current state
   * This is a very simplified version that handles basic assignments and operations
   */
  evaluateExpression(
    expr: string,
    state: VariableState
  ): Interval | null {
    expr = expr.trim();

    // Check if it's a numeric literal
    if (/^\d+$/.test(expr)) {
      return Interval.fromValue(BigInt(expr));
    }

    // Check if it's a variable
    if (state.has(expr)) {
      return state.get(expr)!;
    }

    // Handle basic binary operations (a + b, a - b, a * b)
    const operators = [
      { op: "+", method: "add" },
      { op: "-", method: "sub" },
      { op: "*", method: "mul" },
    ];

    for (const { op, method } of operators) {
      if (expr.includes(op)) {
        const parts = expr.split(op);
        if (parts.length === 2) {
          const left = this.evaluateExpression(parts[0], state);
          const right = this.evaluateExpression(parts[1], state);
          if (left && right) {
            return (left as any)[method](right);
          }
        }
      }
    }

    return null;
  }
}
