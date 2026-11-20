/**
 * Proof system `veilops-range-v2` — the same statement and construction as v1, re-encoded so it can be
 * verified inside a Solana program.
 *
 * Statement: C = v·G + r·H commits to an amount with 0 ≤ v ≤ maxAmount (two bit-decomposition range proofs,
 * one on C and one on D = maxAmount·G − C, each made of CDS OR-proofs per bit). Generators are unchanged.
 *
 * What changes versus v1 (status: experimental, not audited):
 *  - Fiat–Shamir uses SHA-256 (a Solana syscall) instead of SHA-512 (not available on-chain):
 *      ctxHash(tag) = SHA-256( "VEILOPS/range/v2|" ‖ ctx ‖ "|" ‖ tag )              tag ∈ {lower, upper}
 *      T            = "VEILOPS/range/v2/bit" ‖ ctxHash ‖ u32be(i) ‖ C_i ‖ A_0 ‖ A_1
 *      e            = LE( SHA-256(0x00 ‖ T) ‖ SHA-256(0x01 ‖ T) ) mod L                 (512 bits → negligible bias)
 *  - ctx = canonical JSON of {v: "veilops-range-v2", ...publicInputs}. Text fields are restricted to
 *    [A-Za-z0-9_.-]{1,64} so a program can rebuild the exact bytes without a JSON library.
 *  - Binary encoding: u8 version (2) ‖ u8 n ‖ lower bits ‖ upper bits, each bit = C_i ‖ c0 ‖ c1 ‖ s0 ‖ s1,
 *    points as 32-byte ristretto255 encodings, scalars as 32-byte little-endian integers < L.
 */
import { sha256 } from '@noble/hashes/sha2.js';
import { canonicalJson, bytesToHex, utf8ToBytes, concatBytes } from '@veilops/shared';
import { G, H, Point, L, mod, randomScalar, mulSecret, mulPublic, commit, pointHex, bytesToNumberLE, type RPoint } from './pedersen';

export const PROOF_SYSTEM_V2 = 'veilops-range-v2';
export const V2_VERSION = 2;
export const V2_BIT_BYTES = 160;
export const V2_MAX_BITS = 48;
const TEXT_FIELD = /^[A-Za-z0-9_.-]{1,64}$/;

export interface PublicInputsV2 {
  operationId: string;
  policyId: string;
  maxAmount: number;
  rangeBits: number;
  asset: string;
  category: string;
  amountCommitment: string;
}

interface BitV2 { C: RPoint; c0: bigint; c1: bigint; s0: bigint; s1: bigint }
interface RangeV2 { n: number; bits: BitV2[] }
export interface PolicyProofV2 { n: number; lower: RangeV2; upper: RangeV2 }

/* ---------------- encoding helpers ---------------- */

export function scalarToLE(s: bigint): Uint8Array {
  const out = new Uint8Array(32);
  let x = s;
  for (let i = 0; i < 32; i++) { out[i] = Number(x & 0xffn); x >>= 8n; }
  return out;
}

/** Strict: rejects values ≥ L (non-canonical scalars). */
export function scalarFromLE(b: Uint8Array): bigint {
  if (b.length !== 32) throw new Error('scalar must be 32 bytes');
  const s = bytesToNumberLE(b);
  if (s >= L) throw new Error('non-canonical scalar');
  return s;
}

const u32be = (i: number) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, i); return b; };

export function validatePublicInputsV2(pi: PublicInputsV2): void {
  for (const k of ['operationId', 'policyId', 'asset', 'category'] as const) {
    if (!TEXT_FIELD.test(pi[k])) throw new Error(`${k} must match [A-Za-z0-9_.-]{1,64}`);
  }
  if (!Number.isInteger(pi.rangeBits) || pi.rangeBits < 1 || pi.rangeBits > V2_MAX_BITS) throw new Error(`rangeBits must be 1..${V2_MAX_BITS}`);
  if (!Number.isSafeInteger(pi.maxAmount) || pi.maxAmount < 0 || pi.maxAmount >= 2 ** pi.rangeBits) throw new Error('maxAmount must be in [0, 2^rangeBits)');
  if (!/^[0-9a-f]{64}$/.test(pi.amountCommitment)) throw new Error('amountCommitment must be 64 lowercase hex chars');
}

export function transcriptContextV2(pi: PublicInputsV2): string {
  return canonicalJson({ v: PROOF_SYSTEM_V2, ...pi });
}

export function ctxHashV2(pi: PublicInputsV2, tag: 'lower' | 'upper'): Uint8Array {
  return sha256(utf8ToBytes(`VEILOPS/range/v2|${transcriptContextV2(pi)}|${tag}`));
}

export function bitChallengeV2(ctxHash: Uint8Array, index: number, Ci: RPoint, A0: RPoint, A1: RPoint): bigint {
  const T = concatBytes(utf8ToBytes('VEILOPS/range/v2/bit'), ctxHash, u32be(index), Ci.toBytes(), A0.toBytes(), A1.toBytes());
  const wide = concatBytes(sha256(concatBytes(new Uint8Array([0]), T)), sha256(concatBytes(new Uint8Array([1]), T)));
  return mod(bytesToNumberLE(wide));
}

/* ---------------- prover ---------------- */

function proveBitV2(bit: 0 | 1, r: bigint, Ci: RPoint, ctxHash: Uint8Array, index: number): BitV2 {
  const Y = [Ci, Ci.subtract(G)] as const;
  const fake = (1 - bit) as 0 | 1;
  const k = randomScalar(), cFake = randomScalar(), sFake = randomScalar();
  const A: RPoint[] = [Point.ZERO, Point.ZERO];
  A[bit] = mulSecret(H, k);
  A[fake] = mulPublic(H, sFake).subtract(mulPublic(Y[fake], cFake));
  const e = bitChallengeV2(ctxHash, index, Ci, A[0]!, A[1]!);
  const cReal = mod(e - cFake), sReal = mod(k + cReal * r);
  const c = [0n, 0n], s = [0n, 0n];
  c[bit] = cReal; s[bit] = sReal; c[fake] = cFake; s[fake] = sFake;
  return { C: Ci, c0: c[0]!, c1: c[1]!, s0: s[0]!, s1: s[1]! };
}

function proveRangeV2(value: bigint, blinding: bigint, n: number, ctxHash: Uint8Array): RangeV2 {
  if (value < 0n || value >= 1n << BigInt(n)) throw new Error('range: value outside [0, 2^n)');
  const rs: bigint[] = [];
  let acc = 0n;
  for (let i = 0; i < n - 1; i++) { const ri = randomScalar(); rs.push(ri); acc = mod(acc + (1n << BigInt(i)) * ri); }
  rs.push(mod((blinding - acc) * Point.Fn.inv(mod(1n << BigInt(n - 1)))));
  const bits: BitV2[] = [];
  for (let i = 0; i < n; i++) {
    const b = ((value >> BigInt(i)) & 1n) === 1n ? 1 : 0;
    const Ci = mulSecret(G, BigInt(b)).add(mulSecret(H, rs[i]!));
    bits.push(proveBitV2(b, rs[i]!, Ci, ctxHash, i));
  }
  return { n, bits };
}

export interface ProverOutputV2 {
  publicInputs: PublicInputsV2;
  proof: PolicyProofV2;
  proofBytes: Uint8Array;
  proofId: string;
  opening: { value: string; blinding: string };
}

export function provePolicyV2(args: Omit<PublicInputsV2, 'amountCommitment'> & { amount: number }): ProverOutputV2 {
  const { amount, ...rest } = args;
  if (!Number.isSafeInteger(amount) || amount < 0) throw new Error('amount must be a non-negative safe integer');
  if (amount > rest.maxAmount) throw new Error('amount exceeds the policy limit — a valid proof cannot be produced');
  const v = BigInt(amount), r = randomScalar();
  const publicInputs: PublicInputsV2 = { ...rest, amountCommitment: pointHex(commit(v, r)) };
  validatePublicInputsV2(publicInputs);
  const n = rest.rangeBits;
  const lower = proveRangeV2(v, r, n, ctxHashV2(publicInputs, 'lower'));
  const upper = proveRangeV2(BigInt(rest.maxAmount) - v, mod(-r), n, ctxHashV2(publicInputs, 'upper'));
  const proof: PolicyProofV2 = { n, lower, upper };
  const proofBytes = encodeProofV2(proof);
  return { publicInputs, proof, proofBytes, proofId: proofIdV2(proofBytes), opening: { value: v.toString(), blinding: bytesToHex(scalarToLE(r)) } };
}

/* ---------------- binary encoding ---------------- */

export function encodeProofV2(p: PolicyProofV2): Uint8Array {
  const out = new Uint8Array(2 + 2 * p.n * V2_BIT_BYTES);
  out[0] = V2_VERSION; out[1] = p.n;
  let o = 2;
  for (const range of [p.lower, p.upper]) {
    for (const b of range.bits) {
      out.set(b.C.toBytes(), o); out.set(scalarToLE(b.c0), o + 32); out.set(scalarToLE(b.c1), o + 64);
      out.set(scalarToLE(b.s0), o + 96); out.set(scalarToLE(b.s1), o + 128);
      o += V2_BIT_BYTES;
    }
  }
  return out;
}

export function decodeProofV2(bytes: Uint8Array): PolicyProofV2 {
  if (bytes.length < 2 || bytes[0] !== V2_VERSION) throw new Error('not a veilops-range-v2 proof');
  const n = bytes[1]!;
  if (n < 1 || n > V2_MAX_BITS || bytes.length !== 2 + 2 * n * V2_BIT_BYTES) throw new Error('bad proof length');
  const read = (start: number): RangeV2 => {
    const bits: BitV2[] = [];
    for (let i = 0; i < n; i++) {
      const o = start + i * V2_BIT_BYTES;
      bits.push({
        C: Point.fromBytes(bytes.slice(o, o + 32)),
        c0: scalarFromLE(bytes.slice(o + 32, o + 64)), c1: scalarFromLE(bytes.slice(o + 64, o + 96)),
        s0: scalarFromLE(bytes.slice(o + 96, o + 128)), s1: scalarFromLE(bytes.slice(o + 128, o + 160)),
      });
    }
    return { n, bits };
  };
  return { n, lower: read(2), upper: read(2 + n * V2_BIT_BYTES) };
}

export const proofIdV2 = (proofBytes: Uint8Array) => `prf_${bytesToHex(sha256(proofBytes)).slice(0, 20)}`;

/* ---------------- verifier ---------------- */

function verifyRangeV2(C: RPoint, range: RangeV2, ctxHash: Uint8Array): boolean {
  let sum = Point.ZERO;
  for (let i = 0; i < range.n; i++) {
    const b = range.bits[i]!;
    const A0 = mulPublic(H, b.s0).subtract(mulPublic(b.C, b.c0));
    const A1 = mulPublic(H, b.s1).subtract(mulPublic(b.C.subtract(G), b.c1));
    if (mod(b.c0 + b.c1) !== bitChallengeV2(ctxHash, i, b.C, A0, A1)) return false;
    sum = sum.add(mulPublic(b.C, 1n << BigInt(i)));
  }
  return sum.equals(C);
}

/** Verify a v2 policy proof given as bytes. Never throws; malformed input returns false. */
export function verifyPolicyV2(pi: PublicInputsV2, proofBytes: Uint8Array): boolean {
  try {
    validatePublicInputsV2(pi);
    const p = decodeProofV2(proofBytes);
    if (p.n !== pi.rangeBits) return false;
    const C = Point.fromHex(pi.amountCommitment);
    if (!verifyRangeV2(C, p.lower, ctxHashV2(pi, 'lower'))) return false;
    const D = mulPublic(G, BigInt(pi.maxAmount)).subtract(C);
    return verifyRangeV2(D, p.upper, ctxHashV2(pi, 'upper'));
  } catch {
    return false;
  }
}
