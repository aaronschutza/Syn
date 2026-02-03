# Synergeia Node - Final Integrated Version

This repository contains the final, integrated version of the Synergeia blockchain node. This is a security-hardened, command-line-driven application that functions as a true decentralized node. It includes a P2P networking layer, an RPC server, a robust cryptographic pipeline for transaction validation, and the core Synergeia hybrid consensus mechanism, including the Progonos protocol for sBTC staking.

## Security Audit Findings & Enhancements
This version is the result of a simulated security audit. The following critical vulnerabilities and improvements have been addressed:

-   **Full Transaction Validation:** A stack-based scripting engine (`script.rs`) now correctly processes `OP_CHECKSIG`. The node cryptographically verifies every transaction signature before accepting it.
-   **Denial-of-Service Resistance:** The node now maintains a dedicated UTXO database, eliminating a major performance bottleneck. P2P and RPC message sizes are now limited to prevent memory exhaustion attacks.
-   **Deterministic PoS Consensus:** The Proof-of-Stake eligibility check now uses a deterministic, fixed-point arithmetic approximation instead of floating-point math, which is critical for preventing consensus failures.
-   **Signature Malleability:** Transaction signing now follows a `SIGHASH_ALL` model, committing to all inputs and outputs to prevent third-party signature malleability.

## How to Set Up and Use

### 1. Install Rust
If you don't have Rust installed, use `rustup`:
```bash
curl --proto '=https' --tlsv1.2 -sSf [https://sh.rustup.rs](https://sh.rustup.rs) | sh
source $HOME/.cargo/env