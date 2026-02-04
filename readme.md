# Synergeia Node - Final Integrated Version

This repository contains the final, integrated version of the Synergeia blockchain node. This is a security-hardened, command-line-driven application that functions as a true decentralized node. It includes a P2P networking layer, an RPC server, a robust cryptographic pipeline for transaction validation, and the core Synergeia hybrid consensus mechanism, including the Progonos protocol for sBTC staking.

## Security Audit Findings & Enhancements
This version is the result of a simulated security audit. The following critical vulnerabilities and improvements have been addressed:

-   **Full Transaction Validation:** A stack-based scripting engine (`script.rs`) now correctly processes `OP_CHECKSIG`. The node cryptographically verifies every transaction signature before accepting it.
-   **Denial-of-Service Resistance:** The node now maintains a dedicated UTXO database, eliminating a major performance bottleneck. P2P and RPC message sizes are now limited to prevent memory exhaustion attacks.
-   **Deterministic PoS Consensus:** The Proof-of-Stake eligibility check now uses a deterministic, fixed-point arithmetic approximation instead of floating-point math, which is critical for preventing consensus failures.
-   **Signature Malleability:** Transaction signing now follows a `SIGHASH_ALL` model, committing to all inputs and outputs to prevent third-party signature malleability.



Core Features Implemented

1. Hybrid Consensus & Accumulated Synergistic Work (ASW)

Whitepaper Sections: 2.1, 2.4

Mechanism: Parallel block production by PoW miners and PoS stakers.

Metric: Chain selection is based on ASW, which combines computational work (difficulty) and economic commitment (burned fees).

Implementation: * blockchain.rs: calculate_synergistic_work logic.

pos.rs & consensus.rs: Proof-of-Burn logic (OP_RETURN generation) for PoS blocks.

2. Decentralized Consensus Service ($\mathcal{F}_{DCS}$)

Whitepaper Sections: 9.12, 10.11

Mechanism: A BFT-robust oracle built directly into the blockchain. Nodes broadcast signed "beacons" containing local measurements. The network aggregates these using median/percentile functions.

Data Points:

Time: Miner timestamps.

Stake: Total network stake (preventing Merkle root attacks).

Delay: Observed block propagation latency.

Load: Transaction pool congestion.

Security: Orphan rates and reorganization depths.

Topology: Chain branching factors.

Implementation: * dcs.rs: Aggregation logic (medians/percentiles).

block.rs: Beacon and BeaconData structures.

consensus.rs: Async task for generating and broadcasting beacons.

3. Fully Autonomous LDD System

Whitepaper Sections: 3.2, 10.12, 15.3

Mechanism: A control loop that dynamically adjusts protocol parameters based on DCS data to maintain security (psi > Delta) and performance.

Adaptive Parameters:

Slot Gap ($\psi$): Adapts to consensus network delay.

Target Block Time ($\mu$): Adapts to transaction load (down to safety floor).

Burn Rate ($\beta_{burn}$): Adapts to security threat levels (Algorithmic Monetary Policy).

Adjustment Window ($N$): Adapts to threat levels to mitigate gaming.

Implementation: * blockchain.rs: LddState struct and adjust_ldd logic.

4. Burst Finality

Whitepaper Section: 13.2

Mechanism: An execution-driven finality mode for high-value transactions. Triggered by paying a high fee (secured by Proof-of-Burn), the network temporarily enters a high-velocity mode to confirm the transaction rapidly.

Implementation:

burst.rs: State machine managing burst activation and duration.

blockchain.rs: LDD parameter overrides during burst.

5. Chromo-Dynamic Finality (CDF)

Whitepaper Section: 13.5

Mechanism: A deterministic finality gadget overlay. Checkpoints are finalized when they receive a quorum of votes from three distinct "colors" (PoS) and "anti-colors" (PoW blocks), ensuring security as long as $\alpha_A < 1/2$ for both resources.

Implementation:

cdf.rs: Voting logic, color assignment, and quorum checking.

p2p.rs: Propagation of FinalityVote messages.


## How to Set Up and Use

### 1. Install Rust
If you don't have Rust installed, use `rustup`:
```bash
curl --proto '=https' --tlsv1.2 -sSf [https://sh.rustup.rs](https://sh.rustup.rs) | sh
source $HOME/.cargo/env


