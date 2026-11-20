# @veilops/proof-engine

**Status: range proofs experimental (real zero-knowledge cryptography, not audited). Attestation implemented.** Not published to npm.

## `veilops-range-v1`

Proves that a Pedersen commitment `C = v·G + r·H` on ristretto255 opens to an amount `0 ≤ v ≤ maxAmount` without revealing `v`.

- `H` from RFC 9380 hash-to-curve, so `log_G(H)` is unknown.
- Two bit-decomposition range proofs, each bit with a Cramer–Damgård–Schoenmakers OR-proof, made non-interactive with Fiat–Shamir over SHA-512: `v ∈ [0, 2^n)` on `C`, and `max − v ∈ [0, 2^n)` on `D = max·G − C`.
- Honest-verifier zero knowledge in the random-oracle model, no trusted setup.
- **Not succinct**: size and verification time are O(n). A 32-bit policy proof serializes to roughly 30 KB (base64).

## Ed25519 attestation

`attest(record, key)` signs `"VEILOPS/record/v1|" + canonicalJson(record)`. It proves who published a record. **It is a signature, not a zero-knowledge proof.**

## API

```ts
import { provePolicy, verifyPolicy, verifyRecord, commit, verifyOpening, proveRange, verifyRange,
         attest, verifyAttestation, generateSigningKey, signingKeyFromSeed, encodeProof, decodeProof } from '@veilops/proof-engine';

const out = provePolicy({ operationId: 'op_1', policyId: 'pol_1', maxAmount: 5000, rangeBits: 16,
                          asset: 'USDC', category: 'treasury', amount: 1200 });
verifyPolicy(out.publicInputs, out.proof).valid; // true
// out.opening = { value, blinding } — private; share only for selective disclosure
```

`verifyRecord(record)` checks the proof, the proof id binding and the attestation and returns a per-check report. Verifiers never throw on malformed input.

Math, transcript and assumptions: [docs/cryptography.md](../../docs/cryptography.md). License: Apache-2.0.
