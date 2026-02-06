# **Integration Tests Documentation**

This document provides a detailed overview of the integration tests located in src/tests/integration\_tests.rs. These tests are designed to validate the core functionalities of the Synergeia blockchain node in a simulated environment.

## **Test Harness**

The tests utilize a common setup and teardown mechanism to ensure a clean environment for each test case.

* **setup\_test\_env**: Initializes a fresh blockchain instance with a unique database path and wallet file for each test. It configures the node with default parameters loaded from synergeia.toml but allows for overrides (e.g., reducing proposal\_duration\_blocks for faster testing). It returns the blockchain instance (bc\_arc), a pre-configured wallet, the node configuration, and governance configuration.  
* **cleanup\_test\_env**: Removes the temporary database directories and wallet files created during the test to prevent data persistence between runs.  
* **mine\_next\_block\_sync / mine\_next\_block**: Helper functions to simulate the mining process. They construct a valid block template, perform the Proof-of-Work (PoW) by incrementing the nonce until the difficulty target is met, and then add the block to the blockchain. Crucially, these helpers ensure that the block timestamp advances sufficiently (min\_delta) to satisfy the Local Dynamic Difficulty (LDD) slot gap requirement, preventing infinite difficulty loops during rapid test execution.  
* **get\_balance**: A utility to query the spendable balance of a given address from the blockchain's UTXO set.

## **Test Cases**

### **1\. Node Startup and Genesis (test\_0\_node\_startup\_and\_genesis)**

**Purpose:** Verifies that the node initializes correctly and the genesis block is properly established.

**Logic:**

1. Sets up the test environment.  
2. Checks that the blockchain tip is not a zero hash (indicating a genesis block exists).  
3. Retrieves the genesis block and asserts its height is 0\.  
4. Verifies that the initial coinbase transaction from the genesis block exists in the UTXO database.

### **2\. Faucet Minting and Maturity (test\_1\_faucet\_minting\_and\_maturity)**

**Purpose:** Tests the block reward mechanism and the maturity rule for coinbase transactions.

**Logic:**

1. Mines a block to the test wallet's address.  
2. Verifies the initial balance equals the coinbase reward.  
3. Mines 10 additional blocks to simulate chain growth.  
4. Mines another block to the test wallet.  
5. Mines a "maturing block" to ensure the previous coinbase rewards satisfy the coinbase\_maturity requirement.  
6. Asserts that the final balance correctly reflects the accumulated mature rewards.

### **3\. Insufficient Funds Logic (test\_2\_send\_tx\_insufficient\_funds)**

**Purpose:** Ensures that the transaction validation logic correctly rejects transactions attempting to spend more than the available balance.

**Logic:**

1. Mines a block to fund the sender's wallet.  
2. Calculates a send amount that exceeds the available balance (balance \- fee \+ 1).  
3. Attempts to create a transaction with this excessive amount.  
4. Asserts that the transaction creation fails with an "Insufficient funds" error.

### **4\. Hybrid PoW/PoS Chain and LDD (test\_3\_mixed\_pow\_pos\_chain\_and\_ldd)**

**Purpose:** Validates the hybrid consensus engine, ensuring both Proof-of-Work (PoW) and Proof-of-Stake (PoS) blocks can be produced and accepted, and that the LDD mechanism adjusts difficulty.

**Logic:**

1. Initializes LDD parameters (f\_a\_pow, f\_a\_pos).  
2. Funds a staker wallet and bootstraps the total stake.  
3. Simulates a mining loop for 20 blocks where both PoW and PoS workers compete.  
   * **PoS Worker:** Checks eligibility (pos::is\_eligible\_to\_stake) and produces a PoS block if eligible.  
   * **PoW Worker:** Performs hash calculations to meet the difficulty target.  
4. Uses tokio::select\! to add whichever block is found first (PoW or PoS) to the chain.  
5. Asserts that at least one block of each type (PoW and PoS) was produced during the run, confirming the hybrid nature of the chain.

### **5\. Governance Voting and Execution (test\_4\_governance\_voting\_and\_execution)**

**Purpose:** Tests the on-chain governance system, from proposal creation to voting and execution.

**Logic:**

1. Sets up a staker with voting power.  
2. Creates a governance proposal to update the target\_block\_time to 1 second.  
3. Casts a "Yes" vote with the staker's full weight.  
4. Mines blocks until the proposal's voting period ends (end\_block).  
5. Triggers update\_and\_execute\_proposals to tally votes and execute passed proposals.  
6. Asserts that the proposal state is Executed and that the target\_block\_time in the consensus parameters has been updated to 1\.

### **6\. CDF Irreversibility Enforcement (test\_5\_cdf\_irreversibility\_enforcement)**

**Purpose:** Verifies the Chromo-Dynamic Finality (CDF) gadget, ensuring that finalized checkpoints cannot be reverted by deep reorganizations.

**Logic:**

1. Mines a block to establish a checkpoint tip.  
2. Simulates the CDF gadget activation by injecting votes for the checkpoint from three distinct "colors" (Red, Green, Blue).  
3. Checks if finality is reached (check\_finality) and updates last\_finalized\_checkpoint.  
4. Attempts to add a "fork block" that builds from the genesis block (a deep reorg), bypassing the finalized checkpoint.  
5. Asserts that adding this fork block fails with an "Irreversibility Violation" error, confirming the finality gadget's protection.

### **7\. Dynamic Slope Adjustment (test\_dynamic\_slope\_adjustment)**

**Purpose:** Tests the EIP-1559-like dynamic adjustment of the fee slope based on block size.

**Logic:**

1. Initializes a consensus engine with dynamic slope enabled.  
2. Captures the initial max\_slope\_change\_per\_block.  
3. Simulates a block with a size greater than the target size.  
4. Calls adjust\_target\_slope.  
5. Asserts that the slope parameter has changed, reflecting the system's response to network load.

### **Tutorial Tests**

The file also contains several unit tests prefixed with test\_...\_tutorial (e.g., test\_sbtc\_defi\_tutorial, test\_fungible\_token\_tutorial). These serve as examples or mini-integration tests for higher-level application logic that might be built on top of the Synergeia primitives, such as simple DeFi contracts, token standards, and oracle patterns.