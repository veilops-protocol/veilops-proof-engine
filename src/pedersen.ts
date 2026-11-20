/**
 * Pedersen commitments over ristretto255 (RFC 9496).
 *   C = v·G + r·H
 * G is the standard base point. H is derived with RFC 9380 hash-to-curve from a public string,
 * so nobody knows log_G(H). Commitments are perfectly hiding and computationally binding.
 */
import { ristretto255, ristretto255_hasher } from '@noble/curves/ed25519.js';
import { sha512 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, randomBytes, utf8ToBytes, concatBytes } from '@veilops/shared';

export const Point = ristretto255.Point;
export type RPoint = InstanceType<typeof ristretto255.Point>;
export const Fn = ristretto255.Point.Fn;
export const L = Fn.ORDER;

export const G: RPoint = Point.BASE;
export const H: RPoint = ristretto255_hasher.hashToCurve(utf8ToBytes('VEILOPS/pedersen/H/v1'), {
  DST: 'VEILOPS-V01-CS01-with-ristretto255_XMD:SHA-512_R255MAP_RO_',
}) as RPoint;

export function bytesToNumberLE(b: Uint8Array): bigint {
  let n = 0n;
  for (let i = b.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(b[i]!);
  return n;
}

export const mod = (a: bigint) => Fn.create(a);

/** Uniform random scalar in [1, L). */
export function randomScalar(): bigint {
  for (;;) {
    const s = mod(bytesToNumberLE(randomBytes(64)));
    if (s !== 0n) return s;
  }
}

/** Constant-time multiplication for secret scalars; handles the zero scalar. */
export function mulSecret(P: RPoint, s: bigint): RPoint {
  const k = mod(s);
  return k === 0n ? Point.ZERO : P.multiply(k);
}

/** Variable-time multiplication — only for public scalars (verification). */
export function mulPublic(P: RPoint, s: bigint): RPoint {
  return P.multiplyUnsafe(mod(s));
}

export function commit(value: bigint, blinding: bigint): RPoint {
  return mulSecret(G, value).add(mulSecret(H, blinding));
}

export function verifyOpening(commitmentHex: string, value: bigint, blinding: bigint): boolean {
  try {
    return Point.fromHex(commitmentHex).equals(commit(value, blinding));
  } catch {
    return false;
  }
}

export const pointHex = (P: RPoint) => bytesToHex(P.toBytes());
export const pointFromHex = (h: string) => Point.fromHex(h);
export const scalarHex = (s: bigint) => s.toString(16).padStart(64, '0');
export function scalarFromHex(h: string): bigint {
  if (!/^[0-9a-f]{64}$/.test(h)) throw new Error('invalid scalar encoding');
  const s = BigInt('0x' + h);
  if (s >= L) throw new Error('scalar out of range');
  return s;
}

/** Fiat–Shamir challenge: SHA-512 over a domain-separated transcript, reduced mod L. */
export function challenge(domain: string, ...parts: (Uint8Array | string)[]): bigint {
  const enc = parts.map(p => {
    const b = typeof p === 'string' ? utf8ToBytes(p) : p;
    const len = new Uint8Array(4);
    new DataView(len.buffer).setUint32(0, b.length);
    return concatBytes(len, b);
  });
  return mod(bytesToNumberLE(sha512(concatBytes(utf8ToBytes(domain), ...enc))));
}

export { hexToBytes };
