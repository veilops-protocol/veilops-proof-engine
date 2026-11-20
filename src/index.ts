/**
 * @veilops/proof-engine — proof generation and verification interfaces.
 *
 * Proof system `veilops-range-v1` (status: experimental, real cryptography):
 *   Public inputs : operation id, policy id, maxAmount, rangeBits, asset, category, amount commitment C.
 *   Private inputs: amount v, blinding r.
 *   Proves        : C opens to some v with 0 ≤ v ≤ maxAmount — without revealing v.
 *   Construction  : two bit-decomposition range proofs (see ./range.ts):
 *                     v           ∈ [0, 2^n)  on C
 *                     max − v     ∈ [0, 2^n)  on D = max·G − C   (homomorphism, verifier computes D)
 *
 * Attestation (status: implemented): the operator signs the canonical public record with Ed25519, which
 * proves who published it. The signature is NOT a zero-knowledge proof and the UI never calls it one.
 */
import { ed25519 } from '@noble/curves/ed25519.js';
import { canonicalJson, contentId, bytesToHex, hexToBytes, utf8ToBytes, toBase64, fromBase64, type PublicRecord } from '@veilops/shared';
import { G, commit, randomScalar, mod, mulPublic, pointHex, pointFromHex, scalarHex, scalarFromHex } from './pedersen';
import { proveRange, verifyRange, type RangeProof } from './range';

export { commit, verifyOpening, randomScalar, pointHex, G, H } from './pedersen';
export { proveRange, verifyRange, type RangeProof, type BitProof } from './range';

export const PROOF_SYSTEM = 'veilops-range-v1';

export interface PublicInputs {
  operationId: string;
  policyId: string;
  maxAmount: number;
  rangeBits: number;
  asset: string;
  category: string;
  amountCommitment: string;
}

export interface PolicyProof { system: typeof PROOF_SYSTEM; lower: RangeProof; upper: RangeProof }

export interface ProverOutput {
  publicInputs: PublicInputs;
  proof: PolicyProof;
  proofId: string;
  /** Commitment opening — private. Share only with parties allowed to see the amount (selective disclosure). */
  opening: { value: string; blinding: string };
  timings: { proveMs: number };
}

export function transcriptContext(pi: PublicInputs): string {
  return canonicalJson({ v: PROOF_SYSTEM, ...pi });
}

const now = () => (globalThis.performance?.now?.() ?? Date.now());

/** Generate a proof that the committed amount satisfies 0 ≤ amount ≤ maxAmount. */
export function provePolicy(args: Omit<PublicInputs, 'amountCommitment'> & { amount: number }): ProverOutput {
  const { amount, ...rest } = args;
  if (!Number.isSafeInteger(amount) || amount < 0) throw new Error('amount must be a non-negative safe integer');
  if (amount > rest.maxAmount) throw new Error('amount exceeds the policy limit — a valid proof cannot be produced');
  const t0 = now();
  const v = BigInt(amount);
  const r = randomScalar();
  const C = commit(v, r);
  const publicInputs: PublicInputs = { ...rest, amountCommitment: pointHex(C) };
  const ctx = transcriptContext(publicInputs);
  const lower = proveRange(v, r, rest.rangeBits, ctx + '|lower');
  const upper = proveRange(BigInt(rest.maxAmount) - v, mod(-r), rest.rangeBits, ctx + '|upper');
  const proof: PolicyProof = { system: PROOF_SYSTEM, lower, upper };
  return { publicInputs, proof, proofId: proofIdOf(proof), opening: { value: v.toString(), blinding: scalarHex(r) }, timings: { proveMs: Math.round(now() - t0) } };
}

export interface VerifyReport {
  valid: boolean;
  checks: { name: string; passed: boolean; detail: string }[];
  verifyMs: number;
}

/** Verify a policy proof. Pure function; runs identically in the browser and on a server. */
export function verifyPolicy(pi: PublicInputs, proof: PolicyProof): VerifyReport {
  const t0 = now();
  const checks: VerifyReport['checks'] = [];
  const push = (name: string, passed: boolean, detail: string) => { checks.push({ name, passed, detail }); return passed; };
  let ok = push('system', proof?.system === PROOF_SYSTEM, `proof system is ${PROOF_SYSTEM}`);
  ok = push('bits', ok && pi.rangeBits >= 1 && pi.rangeBits <= 48 && proof.lower?.n === pi.rangeBits && proof.upper?.n === pi.rangeBits, `both range proofs use n = ${pi.rangeBits} bits`) && ok;
  ok = push('limit', ok && Number.isSafeInteger(pi.maxAmount) && pi.maxAmount >= 0 && pi.maxAmount < 2 ** pi.rangeBits, 'maxAmount < 2^n') && ok;
  let C;
  try { C = pointFromHex(pi.amountCommitment); } catch { C = null; }
  ok = push('commitment', ok && !!C, 'commitment is a valid ristretto255 point') && ok;
  const ctx = transcriptContext(pi);
  const lowerOk = ok && !!C && verifyRange(C, proof.lower, ctx + '|lower');
  ok = push('lower', lowerOk, '0 ≤ amount < 2^n (bit-decomposition OR-proofs)') && ok;
  const D = C ? mulPublic(G, BigInt(pi.maxAmount)).subtract(C) : null;
  const upperOk = ok && !!D && verifyRange(D, proof.upper, ctx + '|upper');
  ok = push('upper', upperOk, `maxAmount − amount ≥ 0, i.e. amount ≤ ${pi.maxAmount}`) && ok;
  return { valid: ok, checks, verifyMs: Math.round(now() - t0) };
}

export function proofIdOf(proof: PolicyProof): string {
  return contentId('prf', proof, 10);
}

export const encodeProof = (p: PolicyProof) => toBase64(utf8ToBytes(JSON.stringify(p)));
export const decodeProof = (b64: string): PolicyProof => JSON.parse(new TextDecoder().decode(fromBase64(b64)));

/* ---------------- Ed25519 attestation of public records ---------------- */

export interface SigningKey { secretKey: Uint8Array; publicKey: string }

export function generateSigningKey(): SigningKey {
  const secretKey = ed25519.utils.randomSecretKey();
  return { secretKey, publicKey: bytesToHex(ed25519.getPublicKey(secretKey)) };
}

export function signingKeyFromSeed(seed: Uint8Array): SigningKey {
  if (seed.length !== 32) throw new Error('Ed25519 seed must be 32 bytes');
  return { secretKey: seed, publicKey: bytesToHex(ed25519.getPublicKey(seed)) };
}

type Unsigned = Omit<PublicRecord, 'attestation'>;
const signedBytes = (r: Unsigned) => utf8ToBytes('VEILOPS/record/v1|' + canonicalJson(r));

export function attest(record: Unsigned, key: SigningKey): PublicRecord {
  const sig = ed25519.sign(signedBytes(record), key.secretKey);
  return { ...record, attestation: { publicKey: key.publicKey, signature: bytesToHex(sig) } };
}

export function verifyAttestation(record: PublicRecord): boolean {
  try {
    const { attestation, ...rest } = record;
    return ed25519.verify(hexToBytes(attestation.signature), signedBytes(rest), hexToBytes(attestation.publicKey));
  } catch {
    return false;
  }
}

export function publicInputsOf(rec: PublicRecord): PublicInputs {
  return {
    operationId: rec.operationId, policyId: rec.policy.id, maxAmount: rec.policy.maxAmount, rangeBits: rec.policy.rangeBits,
    asset: rec.asset, category: rec.category, amountCommitment: rec.amountCommitment,
  };
}

export interface RecordVerification extends VerifyReport { attestation: boolean; proofIdMatches: boolean }

/** Full verification of a published record: proof, proof id binding and operator signature. */
export function verifyRecord(rec: PublicRecord): RecordVerification {
  const t0 = now();
  let proof: PolicyProof | null = null;
  try { proof = decodeProof(rec.proof); } catch { /* malformed */ }
  const base = proof ? verifyPolicy(publicInputsOf(rec), proof) : { valid: false, checks: [{ name: 'decode', passed: false, detail: 'proof could not be decoded' }], verifyMs: 0 };
  const proofIdMatches = !!proof && proofIdOf(proof) === rec.proofId;
  const attestation = verifyAttestation(rec);
  const checks = [
    ...base.checks,
    { name: 'proofId', passed: proofIdMatches, detail: 'proof id = H(proof)' },
    { name: 'attestation', passed: attestation, detail: 'Ed25519 signature by the publishing operator' },
  ];
  return { valid: base.valid && proofIdMatches && attestation, checks, attestation, proofIdMatches, verifyMs: Math.round(now() - t0) };
}

export { scalarFromHex };
