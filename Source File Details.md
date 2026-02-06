# **Source File Directory**

This document provides a detailed breakdown of the source files within the src/ directory of the Synergeia node implementation. It outlines the role and responsibility of each module in the context of the overall system architecture.

## **Core Modules**

### **src/main.rs**

This file serves as the executable entry point for the Synergeia node. It orchestrates the initialization sequence by parsing command-line arguments using the clap library defined in cli.rs and loading configuration parameters from config.rs. The main function sets up the asynchronous runtime using tokio, initializes the logger, and instantiates the core components of the system: the ConsensusEngine, the persistent database via sled, the Blockchain state manager, and networking services. Depending on the mode specified (e.g., miner, staker, full node), it spawns the necessary asynchronous tasks—such as the P2P server, RPC server, and the consensus loop—and waits for a shutdown signal to gracefully terminate all processes.

### **src/lib.rs**

This file acts as the library root, declaring all the modules that comprise the Synergeia codebase. By exposing these modules publicly, it allows the binary crate (main.rs) and the integration tests to access the internal logic of the node. It structures the project into logical domains such as block, blockchain, consensus, and networking. Additionally, it conditionally compiles the tests module, which contains unit and integration tests, ensuring that testing logic remains separate from the production build artifacts.

### **src/config.rs**

This module defines the configuration hierarchy used to customize the node's behavior. It utilizes the serde library to deserialize settings from a TOML file (typically synergeia.toml) into strongly typed structs like NodeConfig, ConsensusConfig, P2PConfig, and FeeConfig. These structures govern critical parameters such as network ports, database paths, genesis block details, target block times, and adaptive difficulty settings. The module provides a centralized load function that reads the configuration file and returns a validated Config object, ensuring that the node operates with consistent settings across all subsystems.

### **src/cli.rs**

This module defines the command-line interface (CLI) for the application using the clap crate. It specifies the structure of the Cli struct and the Commands enum, which represent the various actions a user can perform, such as starting the node, creating a wallet, or sending transactions. It handles the parsing of flags and arguments—like the configuration file path, operational mode (miner/staker), and specific transaction parameters—providing a user-friendly interface for interacting with the node binary and routing user intent to the appropriate logic in main.rs or rpc.rs.

## **Blockchain & Consensus**

### **src/block.rs**

This file defines the fundamental data structures of the blockchain: Block and BlockHeader. It encapsulates the logic for constructing blocks, including the calculation of the Merkle root from a list of transactions and the serialization of block data for hashing. It also defines the Beacon and BeaconData structures used by the Decentralized Consensus Service (DCS) to attest to network conditions like time and stake. The module ensures that blocks carry all necessary metadata, such as the previous block hash, timestamp, difficulty bits, and the synergistic work value, which serves as the metric for the fork-choice rule.

### **src/blockchain.rs**

This module implements the central Blockchain struct, which maintains the authoritative state of the ledger. It manages the persistent storage of blocks and the Unspent Transaction Output (UTXO) set using the sled database. Key responsibilities include validating new blocks received from the network, handling chain reorganizations (re-orgs) when a heavier chain is discovered, and enforcing consensus rules such as the "Accumulated Synergistic Work" (ASW) metric. It integrates with the LddState to track difficulty adjustments and orchestrates updates to the ConsensusEngine and DecentralizedConsensusService (DCS) upon block acceptance.

### **src/consensus.rs**

This file implements the primary event loop that drives the consensus mechanism. It manages the timing and execution of block production for both Proof-of-Work (PoW) miners and Proof-of-Stake (PoS) validators. The loop monitors the mempool for transactions, checks for P2P messages (like new blocks or beacons), and attempts to mine new blocks when the Local Dynamic Difficulty (LDD) conditions are met. It also handles the broadcasting of locally generated beacons and CDF votes, serving as the heartbeat of the node that keeps the blockchain moving forward.

### **src/engine.rs**

The ConsensusEngine struct defined here encapsulates the high-level validation logic that governs the protocol. It acts as a coordinator between the StakingModule, GovernanceModule, and DynamicDifficultyManager. The engine provides methods to validate block proposals, check PoS eligibility against the current difficulty curve, and apply state transitions triggered by block execution. It ensures that blocks adhere to the protocol's adaptive rules, such as the dynamic target slope for fee adjustments and the specific criteria for valid VRF proofs in PoS blocks.

### **src/difficulty.rs**

This module implements the DynamicDifficultyManager, which is responsible for the Local Dynamic Difficulty (LDD) algorithm. It maintains the DifficultyState, tracking the f\_A (amplitude) parameters for both PoW and PoS. The manager implements the "snowplow curve" logic, calculating the specific difficulty target for any given time delta since the last block. It also executes the feedback control loop that adjusts these parameters based on the observed ratio of PoW to PoS blocks, ensuring the network converges to the target 50/50 resource split and 15-second block time.

### **src/pos.rs**

This file contains the cryptographic logic specific to the Proof-of-Stake consensus mechanism. It implements the is\_eligible\_to\_stake function, which evaluates a Verifiable Random Function (VRF) using the validator's secret key and the current slot data. This evaluation determines if a validator is selected as a slot leader based on their relative stake and the current LDD threshold. The module ensures that leader election is deterministic, verifiable, and resistant to grinding attacks by anchoring randomness to previous block hashes.

### **src/cdf.rs**

This module implements the Chromo-Dynamic Finality (CDF) gadget, a deterministic finality layer running on top of the probabilistic blockchain. It defines the FinalityVote structure and the FinalityGadget state machine. The gadget tracks votes from validators, categorizing them into "colors" (Red, Green, Blue) based on their VRF output. It implements the logic to determine when a checkpoint block has received a sufficient quorum of votes from all color groups and specific "anti-color" PoW blocks, at which point the block is marked as finalized and irreversible.

### **src/burst.rs**

This file manages the logic for "Burst Finality," a high-velocity block production mode triggered by high-fee transactions. The BurstFinalityManager tracks whether the network is currently in a burst state, the duration remaining in the burst, and the special parameters (like a minimal slot gap) that apply during this mode. It provides methods to detect burst triggers in new blocks and to override standard LDD parameters, allowing the network to temporarily accelerate confirmation times for premium transactions.

### **src/dcs.rs**

This module implements the Decentralized Consensus Service (DCS), an oracle-like mechanism built into the consensus layer. It aggregates signed Beacon messages broadcast by nodes to compute network-wide consensus values for metrics such as timestamp, total stake, and network delay. The DCS uses robust statistical methods (like medians and percentiles) to filter out outliers and malicious reports, providing the ConsensusEngine with reliable data to drive the autonomous adaptation of protocol parameters like the slot gap and target block time.

## **State & Storage**

### **src/storage.rs**

This module provides an abstraction layer over the sled embedded database for persistent storage requirements beyond the core blockchain. It implements the GovernanceStore for saving and retrieving proposals and votes, ensuring governance state survives node restarts. It also includes the HeaderStore, which manages the storage of Bitcoin block headers for the SPV client, allowing the node to efficiently verify cross-chain proofs without maintaining a full Bitcoin node.

### **src/stk\_module.rs**

The StakingModule manages the ledger of validator stakes. It tracks the bonding status, balances, and voting power of all addresses participating in Proof-of-Stake. It implements the logic for locking funds (via the BankModule trait), processing stake delegations, and handling unbonding periods. This module serves as the source of truth for pos.rs when determining the weight of a validator's VRF output and for governance.rs when tallying votes on proposals.

## **Transactions & Scripting**

### **src/transaction.rs**

This file defines the structure and behavior of transactions within the system. It declares Transaction, TxIn, and TxOut structs, and implements serialization and hashing logic to generate unique Transaction IDs (TXIDs). It includes the verify\_hybrid method, which orchestrates the validation of inputs using both the legacy ECDSA signature scheme and the post-quantum Dilithium signature scheme (if enforced). It also handles the creation of coinbase transactions and the calculation of signature hashes (sighash) for verification.

### **src/script.rs**

This module implements a stack-based scripting engine, conceptually similar to Bitcoin Script, for validating transaction authorization. It defines an interpreter that executes a sequence of opcodes (e.g., OP\_DUP, OP\_HASH160, OP\_CHECKSIG) found in transaction inputs and outputs. The engine manages a data stack and an alternate stack, processing logical, arithmetic, and cryptographic operations to return a boolean result indicating whether the spending conditions for a UTXO have been met.

### **src/wallet.rs**

This file manages the user's cryptographic identity and signing capabilities. It defines the Wallet struct, which holds both secp256k1 (ECDSA) and Dilithium (Post-Quantum) keypairs. The module provides functionality to creating and loading wallets from disk, generating addresses, and most importantly, signing transactions and beacons. It abstracts the complexity of producing the hybrid signatures required by the transaction.rs verification logic.

## **Networking**

### **src/p2p.rs**

This module implements the custom peer-to-peer networking protocol for Synergeia. It defines the P2PMessage enum, which covers all network communications including block propagation, transaction broadcasting, and consensus beacons. The module handles the serialization of these messages, the management of TCP connections to peers, and the implementation of the "Compact Blocks" propagation optimization. It serves as the nervous system of the node, ensuring data is efficiently synchronized across the distributed network.

### **src/peer\_manager.rs**

The PeerManager is responsible for maintaining a healthy mesh of connections. It tracks the reputation of known peers, scoring them based on their behavior (e.g., valid blocks vs. malformed messages). It implements logic to ban malicious peers, disconnect from low-performing ones, and automatically seek out new connections to maintain a target number of outbound links. This module protects the node from eclipse attacks and ensures robust connectivity.

### **src/rpc.rs**

This file implements the JSON-RPC server that allows external clients and the CLI to interact with the node. It defines handlers for various methods such as send\_transaction, get\_balance, get\_block, and submit\_proposal. The module bridges the gap between the HTTP/JSON interface and the internal Rust data structures, converting user requests into actions performed on the Blockchain or Mempool and returning responses in a standardized format.

### **src/btc\_p2p.rs**

This specialized networking module implements a partial Bitcoin P2P client. Its sole purpose is to connect to the Bitcoin network, perform the initial handshake, and download block headers. It feeds these headers into the SpvClientState, enabling the Progonos bridge to verify Bitcoin transaction inclusion proofs (SPV) without requiring the user to run a separate Bitcoin full node.

## **Governance & Interoperability**

### **src/governance.rs**

This file defines the core data structures for the on-chain governance system. It declares the Proposal struct, the ProposalState enum (Active, Passed, Failed), and the ProposalPayload enum which defines the executable actions a proposal can take (e.g., changing the block size). It acts as the data definition layer for the governance logic contained in gov\_module.rs.

### **src/gov\_module.rs**

The GovernanceModule implements the business logic for the governance system. It manages the lifecycle of proposals from submission to voting and execution. It interacts with the StakingModule to weigh votes by stake and with the ParamManager to apply parameter changes if a proposal passes. The module enforces rules regarding voting periods, quorum requirements, and execution delays, ensuring that protocol upgrades occur in a transparent and orderly manner.

### **src/progonos.rs**

This module implements the logic for "Progonos," the Bitcoin bridging mechanism. It defines the verify\_and\_mint\_sbtc workflow, which takes a Bitcoin deposit proof and issues corresponding tokens on the Synergeia chain. It uses the SpvClient to validate that the Bitcoin transaction provided in the proof is actually included in a Bitcoin block with sufficient confirmations, enabling trust-minimized interoperability.

### **src/spv.rs**

This file provides the cryptographic primitives for Simple Payment Verification (SPV). It implements the logic to parse and verify Merkle proofs against a known Merkle root. Specifically, it validates that a transaction ID exists within a specific Bitcoin block header, a critical step for the Progonos bridge to trustlessly verify deposits.

### **src/client.rs**

This module manages the SpvClientState, which is the local storage for the verified chain of Bitcoin block headers. It handles the ingestion of new headers from btc\_p2p.rs, validates their Proof-of-Work, and ensures they form a valid chain extending from the known genesis or checkpoint. It provides the "light client" view of the Bitcoin blockchain required by the Progonos module.

## **Utilities & Shared**

### **src/params.rs**

This file serves as the central registry for protocol parameters. It defines ConsensusParams and ProtocolParams structs, which contain governable constants like the block reward, target block time, and fee burn rates. The ParamManager struct provides a thread-safe interface for other modules to read these values and for the governance module to update them, ensuring that parameter changes are propagated atomically across the system.

### **src/fixed\_point.rs**

This module implements a deterministic fixed-point arithmetic library (Fixed). Since floating-point math can vary slightly across different hardware architectures, it cannot be used in consensus-critical calculations. This module provides a safe alternative for handling fractional values (like difficulty adjustments and token ratios) ensuring that every node in the network calculates exactly the same results.

### **src/crypto.rs**

This utility module provides wrappers and helper functions for cryptographic operations. It handles key generation, public key hashing (RIPEMD160 over SHA256), and address encoding (Base58Check). It centralizes the cryptographic primitives used throughout the application, ensuring consistency in how keys and addresses are handled.

### **src/sync.rs**

Currently a placeholder, this module is designated for implementing the "Initial Block Download" (IBD) or fast-sync logic. Its future role is to orchestrate the rapid downloading and verification of the blockchain history when a new node joins the network, distinct from the steady-state block propagation handled by p2p.rs.

### **src/runtime.rs**

This file defines the main asynchronous runtime loop, run\_consensus\_loop. It acts as the central message bus for the node, receiving messages from the P2P network, RPC server, and internal timers. It routes these messages to the appropriate handlers in the ConsensusEngine or Blockchain and manages the high-level flow of data within the application.

## **Testing**

### **src/tests/integration\_tests.rs**

This file contains the primary suite of integration tests. It sets up a full, ephemeral blockchain environment to test complex interactions between modules. Tests cover scenarios like node startup, mining (PoW) and staking (PoS) block production, transaction validation (including insufficient funds checks), governance voting flows, and the activation of the CDF finality gadget. It ensures that the system components work together correctly.

### **src/tests/script\_tests.rs**

This module contains unit tests specifically for the transaction scripting engine defined in script.rs. It verifies that individual opcodes (like OP\_IF, OP\_CHECKSIG, OP\_ADD) behave as expected and that scripts correctly evaluate to true or false based on the provided stack data.

### **src/tests/fixed\_point\_tests.rs**

These unit tests validate the correctness of the custom fixed-point arithmetic library in fixed\_point.rs. They check standard mathematical operations (addition, multiplication, division) to ensure they handle precision and overflow correctly, which is vital for the stability of the consensus algorithms.

### **src/tests/advanced\_feature\_tests.rs**

This suite targets the more complex, adaptive features of the protocol. It includes tests for the autonomous LDD adaptation (verifying difficulty adjusts to load), the "Burst Finality" trigger mechanism, and the economic "immune response" (dynamic burn rate) to simulated security threats. These tests validate the control-theoretic aspects of the system.