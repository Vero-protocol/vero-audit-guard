/**
 * Tests for abstract-interpreter.ts — interval domain + expression evaluation.
 */

import {
  AbstractInterpreter,
  Interval,
  type VariableState,
} from './abstract-interpreter';

describe('Interval', () => {
  test('fromValue creates a singleton interval', () => {
    const i = Interval.fromValue(5n);
    expect(i.min).toBe(5n);
    expect(i.max).toBe(5n);
  });

  test('add widens bounds correctly', () => {
    const a = new Interval(1n, 3n);
    const b = new Interval(2n, 4n);
    const r = a.add(b);
    expect(r.min).toBe(3n);
    expect(r.max).toBe(7n);
  });

  test('sub uses worst-case endpoints', () => {
    const a = new Interval(10n, 20n);
    const b = new Interval(1n, 5n);
    const r = a.sub(b);
    // min - maxOther .. max - minOther
    expect(r.min).toBe(5n);
    expect(r.max).toBe(19n);
  });

  test('mul considers all four endpoint products', () => {
    const a = new Interval(-2n, 3n);
    const b = new Interval(-4n, 5n);
    const r = a.mul(b);
    // products: 8, -10, -12, 15 → min -12, max 15
    expect(r.min).toBe(-12n);
    expect(r.max).toBe(15n);
  });

  test('mul of positive intervals stays positive', () => {
    const a = new Interval(2n, 3n);
    const b = new Interval(4n, 5n);
    const r = a.mul(b);
    expect(r.min).toBe(8n);
    expect(r.max).toBe(15n);
  });

  test('isWithinBounds returns true when fully inside', () => {
    const i = new Interval(0n, 100n);
    expect(i.isWithinBounds(0n, AbstractInterpreter.U32_MAX)).toBe(true);
  });

  test('isWithinBounds returns false when max exceeds bound', () => {
    const i = new Interval(0n, AbstractInterpreter.U32_MAX + 1n);
    expect(i.isWithinBounds(0n, AbstractInterpreter.U32_MAX)).toBe(false);
  });

  test('isWithinBounds returns false when min is below bound', () => {
    const i = new Interval(-1n, 10n);
    expect(i.isWithinBounds(0n, AbstractInterpreter.U32_MAX)).toBe(false);
  });

  test('toString formats as [min, max]', () => {
    expect(new Interval(1n, 2n).toString()).toBe('[1, 2]');
  });
});

describe('AbstractInterpreter type bounds', () => {
  test('U32_MAX is 2^32 - 1', () => {
    expect(AbstractInterpreter.U32_MAX).toBe(4294967295n);
  });

  test('U64_MAX is 2^64 - 1', () => {
    expect(AbstractInterpreter.U64_MAX).toBe(18446744073709551615n);
  });

  test('U128_MAX is 2^128 - 1', () => {
    expect(AbstractInterpreter.U128_MAX).toBe(
      340282366920938463463374607431768211455n,
    );
  });
});

describe('AbstractInterpreter.evaluateExpression', () => {
  let interpreter: AbstractInterpreter;
  let state: VariableState;

  beforeEach(() => {
    interpreter = new AbstractInterpreter();
    state = new Map();
  });

  test('evaluates numeric literal', () => {
    const r = interpreter.evaluateExpression('42', state);
    expect(r).not.toBeNull();
    expect(r!.min).toBe(42n);
    expect(r!.max).toBe(42n);
  });

  test('trims whitespace around literal', () => {
    const r = interpreter.evaluateExpression('  7  ', state);
    expect(r!.min).toBe(7n);
    expect(r!.max).toBe(7n);
  });

  test('resolves variable from state', () => {
    state.set('x', new Interval(10n, 20n));
    const r = interpreter.evaluateExpression('x', state);
    expect(r!.min).toBe(10n);
    expect(r!.max).toBe(20n);
  });

  test('returns null for unknown variable', () => {
    expect(interpreter.evaluateExpression('unknown', state)).toBeNull();
  });

  test('returns null for empty input', () => {
    expect(interpreter.evaluateExpression('', state)).toBeNull();
    expect(interpreter.evaluateExpression('   ', state)).toBeNull();
  });

  test('returns null for malformed expression', () => {
    expect(interpreter.evaluateExpression('1 +', state)).toBeNull();
    expect(interpreter.evaluateExpression('+ 1', state)).toBeNull();
    expect(interpreter.evaluateExpression('foo bar', state)).toBeNull();
  });

  test('adds two literals', () => {
    const r = interpreter.evaluateExpression('3 + 5', state);
    expect(r!.min).toBe(8n);
    expect(r!.max).toBe(8n);
  });

  test('subtracts two literals', () => {
    const r = interpreter.evaluateExpression('10 - 3', state);
    expect(r!.min).toBe(7n);
    expect(r!.max).toBe(7n);
  });

  test('multiplies two literals', () => {
    const r = interpreter.evaluateExpression('4 * 5', state);
    expect(r!.min).toBe(20n);
    expect(r!.max).toBe(20n);
  });

  test('adds variable and literal', () => {
    state.set('a', new Interval(1n, 2n));
    const r = interpreter.evaluateExpression('a + 3', state);
    expect(r!.min).toBe(4n);
    expect(r!.max).toBe(5n);
  });

  test('multiplies two variables (interval product)', () => {
    state.set('x', new Interval(2n, 3n));
    state.set('y', new Interval(4n, 5n));
    const r = interpreter.evaluateExpression('x * y', state);
    expect(r!.min).toBe(8n);
    expect(r!.max).toBe(15n);
  });

  test('detects potential u32 overflow via isWithinBounds', () => {
    // 4000000000 + 4000000000 exceeds U32_MAX
    const r = interpreter.evaluateExpression('4000000000 + 4000000000', state);
    expect(r).not.toBeNull();
    expect(r!.isWithinBounds(0n, AbstractInterpreter.U32_MAX)).toBe(false);
  });

  test('safe u32 addition stays within bounds', () => {
    const r = interpreter.evaluateExpression('100 + 200', state);
    expect(r!.isWithinBounds(0n, AbstractInterpreter.U32_MAX)).toBe(true);
  });

  test('large multiplication may exceed u64', () => {
    const r = interpreter.evaluateExpression(
      '18446744073709551615 * 2',
      state,
    );
    expect(r).not.toBeNull();
    expect(r!.isWithinBounds(0n, AbstractInterpreter.U64_MAX)).toBe(false);
  });

  test('returns null when one side of binary op is unknown', () => {
    expect(interpreter.evaluateExpression('x + 1', state)).toBeNull();
    expect(interpreter.evaluateExpression('1 + x', state)).toBeNull();
  });
});
