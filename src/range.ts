/**
 * Non-interactive zero-knowledge range proof by bit decomposition.
 *
 * Statement: "I know (v, r) such that C = v·G + r·H and 0 ≤ v < 2^n."
 *
 * For every bit b_i of v the prover commits C_i = b_i·G + r_i·H with Σ 2^i·r_i = r, so the verifier can
 * check Σ 2^i·C_i = C. Each C_i carries a Cramer–Damgård–Schoenmakers OR-proof that C_i commits to 0 OR 1
 * (knowledge of x with C_i = x·H, or with C_i − G = x·H), made non-interactive with Fiat–Shamir.
 *
 * Properties: honest-verifier zero knowledge (in the random-oracle model), no trusted setup, proof size
 * O(n). This is a classical, well-understood construction — it is NOT succinct like Bulletproofs or a
 * SNARK, and this implementation has not been externally audited.
 */
import {
  G, H, Point, L, mod, randomScalar, mulSecret, mulPublic, pointHex, pointFromHex, scalarHex, scalarFromHex, challenge,
  type RPoint,
} from './pedersen';

export interface BitProof { C: string; c0: string; c1: string; s0: string; s1: string }
export interface RangeProof { n: number; bits: BitProof[] }

const DOMAIN = 'VEILOPS/range/bit-or/v1';

function proveBit(bit: 0 | 1, r: bigint, Ci: RPoint, ctx: string, index: number): BitProof {
  const Y = [Ci, Ci.subtract(G)] as const; // statement b: Y[b] = r·H
  const real = bit;
  const fake = (1 - bit) as 0 | 1;
  const k = randomScalar();
  const cFake = randomScalar();
  const sFake = randomScalar();
  const A: RPoint[] = [Point.ZERO, Point.ZERO];
  A[real] = mulSecret(H, k);
  A[fake] = mulPublic(H, sFake).subtract(mulPublic(Y[fake], cFake));
  const e = challenge(DOMAIN, ctx, String(index), Ci.toBytes(), A[0]!.toBytes(), A[1]!.toBytes());
  const cReal = mod(e - cFake);
  const sReal = mod(k + cReal * r);
  const c = [0n, 0n];
  const s = [0n, 0n];
  c[real] = cReal; s[real] = sReal;
  c[fake] = cFake; s[fake] = sFake;
  return { C: pointHex(Ci), c0: scalarHex(c[0]!), c1: scalarHex(c[1]!), s0: scalarHex(s[0]!), s1: scalarHex(s[1]!) };
}

function verifyBit(bp: BitProof, ctx: string, index: number): RPoint | null {
  const Ci = pointFromHex(bp.C);
  const c0 = scalarFromHex(bp.c0), c1 = scalarFromHex(bp.c1);
  const s0 = scalarFromHex(bp.s0), s1 = scalarFromHex(bp.s1);
  const Y0 = Ci, Y1 = Ci.subtract(G);
  const A0 = mulPublic(H, s0).subtract(mulPublic(Y0, c0));
  const A1 = mulPublic(H, s1).subtract(mulPublic(Y1, c1));
  const e = challenge(DOMAIN, ctx, String(index), Ci.toBytes(), A0.toBytes(), A1.toBytes());
  return mod(c0 + c1) === e ? Ci : null;
}

/** Prove 0 ≤ value < 2^n for C = value·G + blinding·H. */
export function proveRange(value: bigint, blinding: bigint, n: number, ctx: string): RangeProof {
  if (n < 1 || n > 64) throw new Error('range: n must be 1..64');
  if (value < 0n || value >= 1n << BigInt(n)) throw new Error('range: value outside [0, 2^n)');
  const rs: bigint[] = [];
  let acc = 0n;
  for (let i = 0; i < n - 1; i++) {
    const ri = randomScalar();
    rs.push(ri);
    acc = mod(acc + (1n << BigInt(i)) * ri);
  }
  const inv = Point.Fn.inv(mod(1n << BigInt(n - 1)));
  rs.push(mod((blinding - acc) * inv));
  const bits: BitProof[] = [];
  for (let i = 0; i < n; i++) {
    const b = ((value >> BigInt(i)) & 1n) === 1n ? 1 : 0;
    const Ci = mulSecret(G, BigInt(b)).add(mulSecret(H, rs[i]!));
    bits.push(proveBit(b, rs[i]!, Ci, ctx, i));
  }
  return { n, bits };
}

/** Verify a range proof against commitment C. Never throws on malformed input; returns false. */
export function verifyRange(C: RPoint, proof: RangeProof, ctx: string): boolean {
  try {
    if (!proof || !Array.isArray(proof.bits) || proof.bits.length !== proof.n || proof.n < 1 || proof.n > 64) return false;
    let sum = Point.ZERO;
    for (let i = 0; i < proof.n; i++) {
      const Ci = verifyBit(proof.bits[i]!, ctx, i);
      if (!Ci) return false;
      sum = sum.add(mulPublic(Ci, 1n << BigInt(i)));
    }
    return sum.equals(C);
  } catch {
    return false;
  }
}

export { L };
