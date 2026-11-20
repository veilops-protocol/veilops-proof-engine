<p align="center"><a href="https://veilops.tech"><img src="https://raw.githubusercontent.com/veilops-protocol/veilops/main/docs/assets/banner.png" alt="VEILOPS: Privacy is not the absence of proof. It's proof without exposure." width="100%"></a></p>

# veilops-proof-engine

Zero-knowledge range proofs and record attestation for VEILOPS.

> **Status: experimental. Real cryptography, not audited, not externally reviewed.** Not published to npm. No releases.

**Mirror of** [`veilops-protocol/veilops`](https://github.com/veilops-protocol/veilops) → `packages/proof-engine/` (see [MIRROR.md](MIRROR.md)). File issues, pull requests and **private security reports** on the monorepo.

## `veilops-range-v1`

- Pedersen commitment `C = v·G + r·H` on ristretto255 (`@noble/curves` 2.0.1); `H` derived with RFC 9380 hash-to-curve.
- Two bit-decomposition range proofs with Cramer–Damgård–Schoenmakers OR-proofs, non-interactive via Fiat–Shamir over SHA-512:
  `v ∈ [0, 2^n)` on `C` and `max − v ∈ [0, 2^n)` on `D = max·G − C`, which proves `0 ≤ v ≤ max` without revealing `v`.
- Honest-verifier zero knowledge in the random-oracle model; no trusted setup.
- **Not succinct**: O(n) proof size (a 32-bit policy proof serializes to roughly 30 KB base64) and O(n) verification.

## Ed25519 attestation

The operator signs the canonical public record. This proves who published it. **It is a signature, not a zero-knowledge proof.**

## Install

Not on npm; the entry point is TypeScript source and depends on `@veilops/shared`. Use it from the monorepo:

```bash
git clone https://github.com/veilops-protocol/veilops.git
cd veilops && npm ci && npm test
```

## Usage

```ts
import { provePolicy, verifyPolicy } from '@veilops/proof-engine';

const out = provePolicy({ operationId: 'op_1', policyId: 'pol_1', maxAmount: 5000, rangeBits: 16,
                          asset: 'USDC', category: 'treasury', amount: 1200 });
verifyPolicy(out.publicInputs, out.proof).valid; // true; out.opening stays private
```

Equations, transcript and assumptions: [docs/cryptography.md](https://github.com/veilops-protocol/veilops/blob/main/docs/cryptography.md).

License: Apache-2.0.
