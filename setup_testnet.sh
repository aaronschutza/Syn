#!/bin/bash

# Configuration
NUM_MINERS=16
NUM_STAKERS=16
BASE_P2P_PORT=10000
BASE_RPC_PORT=20000
PROJECT_ROOT=$(pwd)
TESTNET_DIR="$PROJECT_ROOT/local_testnet"
SYNERGEIA_BINARY="cargo run --"

# --- Cleanup and Setup ---
echo "Cleaning up previous testnet environment..."
rm -rf "$TESTNET_DIR"
pkill -f "synergeia --config"

echo "Creating new testnet directory..."
mkdir -p "$TESTNET_DIR"

# --- Build the project ---
echo "Building the Synergeia project..."
cargo build
if [ $? -ne 0 ]; then
    echo "Error: Cargo build failed. Please fix any compilation errors before running this script."
    exit 1
fi

# --- Generate Miner Configurations and Wallets ---
echo "Generating configurations for $NUM_MINERS miners..."
MINER_P2P_ADDRESSES=()
for i in $(seq 1 $NUM_MINERS); do
    NODE_DIR="$TESTNET_DIR/miner$i"
    mkdir -p "$NODE_DIR"

    P2P_PORT=$((BASE_P2P_PORT + i))
    RPC_PORT=$((BASE_RPC_PORT + i))
    MINER_P2P_ADDRESSES+=("127.0.0.1:$P2P_PORT")

    # Create config from miner.toml template
    sed -e "s/rpc_port = 8332/rpc_port = $RPC_PORT/" \
        -e "s/p2p_port = 8333/p2p_port = $P2P_PORT/" \
        -e "s|db_path = \"miner.db\"|db_path = \"$NODE_DIR/miner.db\"|" \
        -e "s|wallet_file = \"miner-wallet.dat\"|wallet_file = \"$NODE_DIR/wallet.dat\"|" \
        -e "s/bootstrap_nodes = \\[]/bootstrap_nodes = []/" \
        "$PROJECT_ROOT/miner.toml" > "$NODE_DIR/config.toml"

    # Create wallet and capture address
    echo "Creating wallet for miner$i..."
    $SYNERGEIA_BINARY --config "$NODE_DIR/config.toml" create-wallet > "$NODE_DIR/wallet.info"
    ADDRESS=$(grep "Address:" "$NODE_DIR/wallet.info" | awk '{print $2}')
    echo "$ADDRESS" > "$NODE_DIR/address.txt"
done

# --- Generate Staker Configurations and Wallets ---
echo "Generating configurations for $NUM_STAKERS stakers..."
STAKER_ADDRESSES=()
BOOTSTRAP_NODES_STR="["
for addr in "${MINER_P2P_ADDRESSES[@]}"; do
    BOOTSTRAP_NODES_STR+="\"$addr\","
done
BOOTSTRAP_NODES_STR="${BOOTSTRAP_NODES_STR%,}]" # Remove trailing comma and add closing bracket

for i in $(seq 1 $NUM_STAKERS); do
    NODE_DIR="$TESTNET_DIR/staker$i"
    mkdir -p "$NODE_DIR"

    P2P_PORT=$((BASE_P2P_PORT + NUM_MINERS + i))
    RPC_PORT=$((BASE_RPC_PORT + NUM_MINERS + i))

    # Create config from staker.toml template
    sed -e "s/rpc_port = 9332/rpc_port = $RPC_PORT/" \
        -e "s/p2p_port = 9333/p2p_port = $P2P_PORT/" \
        -e "s|db_path = \"staker.db\"|db_path = \"$NODE_DIR/staker.db\"|" \
        -e "s|wallet_file = \"staker-wallet.dat\"|wallet_file = \"$NODE_DIR/wallet.dat\"|" \
        -e "s|bootstrap_nodes =.*|bootstrap_nodes = $BOOTSTRAP_NODES_STR|" \
        "$PROJECT_ROOT/staker.toml" > "$NODE_DIR/config.toml"

    # Create wallet and capture address
    echo "Creating wallet for staker$i..."
    $SYNERGEIA_BINARY --config "$NODE_DIR/config.toml" create-wallet > "$NODE_DIR/wallet.info"
    ADDRESS=$(grep "Address:" "$NODE_DIR/wallet.info" | awk '{print $2}')
    echo "$ADDRESS" > "$NODE_DIR/address.txt"
    STAKER_ADDRESSES+=($ADDRESS)
done

# --- Generate Start Script ---
echo "Generating start_testnet.sh..."
cat << EOF > ./start_testnet.sh
#!/bin/bash
PROJECT_ROOT=\$(pwd)
TESTNET_DIR="\$PROJECT_ROOT/local_testnet"
SYNERGEIA_BINARY="cargo run --"

echo "Starting $NUM_MINERS miners..."
for i in \$(seq 1 $NUM_MINERS); do
    NODE_DIR="\$TESTNET_DIR/miner\$i"
    ADDRESS=\$(cat "\$NODE_DIR/address.txt")
    echo "Starting miner\$i, mining to \$ADDRESS..."
    nohup \$SYNERGEIA_BINARY --config "\$NODE_DIR/config.toml" start-node --mode miner --mine-to-address "\$ADDRESS" > "\$NODE_DIR/output.log" 2>&1 &
done

echo "Waiting for miners to produce blocks and funds to mature..."
sleep 20 # Wait for some blocks to be mined

echo "Funding stakers..."
MINER1_CONFIG="\$TESTNET_DIR/miner1/config.toml"
STAKE_AMOUNT=100000 # Amount of SYN to stake
TX_FEE=1000       # As per consensus.fee_per_transaction
TOTAL_SEND_AMOUNT=\$((STAKE_AMOUNT + TX_FEE))

for i in \$(seq 1 $NUM_STAKERS); do
    STAKER_NODE_DIR="\$TESTNET_DIR/staker\$i"
    STAKER_ADDRESS=\$(cat "\$STAKER_NODE_DIR/address.txt")
    
    echo "Sending \$TOTAL_SEND_AMOUNT SYN from miner1 to staker\$i (\$STAKER_ADDRESS)..."
    \$SYNERGEIA_BINARY --config "\$MINER1_CONFIG" send --to "\$STAKER_ADDRESS" --amount \$TOTAL_SEND_AMOUNT
    
    echo "Configuring stake for staker\$i..."
    \$SYNERGEIA_BINARY --config "\$STAKER_NODE_DIR/config.toml" stake --asset SYN --amount \$STAKE_AMOUNT

    sleep 1 # Small delay between transactions
done

echo "Waiting for funding transactions to be confirmed..."
sleep 15

echo "Starting $NUM_STAKERS stakers..."
for i in \$(seq 1 $NUM_STAKERS); do
    NODE_DIR="\$TESTNET_DIR/staker\$i"
    echo "Starting staker\$i..."
    nohup \$SYNERGEIA_BINARY --config "\$NODE_DIR/config.toml" start-node --mode staker > "\$NODE_DIR/output.log" 2>&1 &
done

echo "Testnet is starting up. You can view logs in the 'local_testnet' directory."
EOF

# --- Generate Stop Script ---
echo "Generating stop_testnet.sh..."
cat << EOF > ./stop_testnet.sh
#!/bin/bash
echo "Stopping all Synergeia nodes..."
pkill -f "synergeia --config"
echo "All nodes stopped."
EOF

echo "Setup complete!"
echo "Run './start_testnet.sh' to start the local testnet."
echo "Run './stop_testnet.sh' to stop the local testnet."