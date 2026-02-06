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
    # Also setting coinbase_maturity = 1 for faster testing
    sed -e "s/rpc_port = 8332/rpc_port = $RPC_PORT/" \
        -e "s/p2p_port = 8333/p2p_port = $P2P_PORT/" \
        -e "s|db_path = \"miner.db\"|db_path = \"$NODE_DIR/miner.db\"|" \
        -e "s|wallet_file = \"miner-wallet.dat\"|wallet_file = \"$NODE_DIR/wallet.dat\"|" \
        -e "s/bootstrap_nodes = \\[]/bootstrap_nodes = []/" \
        -e "s/coinbase_maturity = [0-9]*/coinbase_maturity = 1/" \
        "$PROJECT_ROOT/miner.toml" > "$NODE_DIR/config.toml"

    # Create wallet and capture address
    echo "Creating wallet for miner$i..."
    $SYNERGEIA_BINARY --config "$NODE_DIR/config.toml" create-wallet > "$NODE_DIR/wallet.info"
    ADDRESS=$(grep "Address:" "$NODE_DIR/wallet.info" | awk '{print $2}')
    echo "$ADDRESS" > "$NODE_DIR/address.txt"
done

# --- Generate Staker Configurations and Wallets ---
echo "Generating configurations for $NUM_STAKERS stakers..."
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
        -e "s/coinbase_maturity = [0-9]*/coinbase_maturity = 1/" \
        "$PROJECT_ROOT/staker.toml" > "$NODE_DIR/config.toml"

    # Create wallet and capture address
    echo "Creating wallet for staker$i..."
    $SYNERGEIA_BINARY --config "$NODE_DIR/config.toml" create-wallet > "$NODE_DIR/wallet.info"
    ADDRESS=$(grep "Address:" "$NODE_DIR/wallet.info" | awk '{print $2}')
    echo "$ADDRESS" > "$NODE_DIR/address.txt"
done

# --- Generate Start Script ---
echo "Generating start_testnet.sh..."
cat << EOF > ./start_testnet.sh
#!/bin/bash
PROJECT_ROOT=\$(pwd)
TESTNET_DIR="\$PROJECT_ROOT/local_testnet"
SYNERGEIA_BINARY="cargo run --"
MINER1_RPC_PORT=20001

# Function to get chain height via RPC using curl
# Returns -1 on failure or the height integer
get_chain_height() {
    local port=\$1
    local response=\$(curl -s -m 2 -X POST -H "Content-Type: application/json" -d '{"jsonrpc": "2.0", "method": "print_chain", "params": [], "id": 1}' http://127.0.0.1:\$port)
    # Simple parsing to get the height value (assuming format "height": 123)
    local height=\$(echo "\$response" | grep -o '"height":[0-9]*' | cut -d':' -f2)
    if [[ -n "\$height" ]]; then
        echo "\$height"
    else
        echo "-1"
    fi
}

echo "Starting $NUM_MINERS miners..."
for i in \$(seq 1 $NUM_MINERS); do
    NODE_DIR="\$TESTNET_DIR/miner\$i"
    ADDRESS=\$(cat "\$NODE_DIR/address.txt")
    echo "Starting miner\$i, mining to \$ADDRESS..."
    nohup \$SYNERGEIA_BINARY --config "\$NODE_DIR/config.toml" start-node --mode miner --mine-to-address "\$ADDRESS" > "\$NODE_DIR/node.log" 2>&1 &
done

echo "Waiting for Miner 1 RPC (Port \$MINER1_RPC_PORT)..."
MAX_RETRIES=30
count=0
while [ \$count -lt \$MAX_RETRIES ]; do
    HEIGHT=\$(get_chain_height \$MINER1_RPC_PORT)
    if [ "\$HEIGHT" -ge "0" ]; then
        break
    fi
    sleep 2
    count=\$((count+1))
done

if [ \$count -eq \$MAX_RETRIES ]; then
    echo "Timeout waiting for Miner 1 to start."
    exit 1
fi

echo "Sequentially funding stakers via Miner 1..."
MINER1_CONFIG="\$TESTNET_DIR/miner1/config.toml"
FAUCET_AMOUNT=100000

for i in \$(seq 1 $NUM_STAKERS); do
    STAKER_NODE_DIR="\$TESTNET_DIR/staker\$i"
    STAKER_ADDRESS=\$(cat "\$STAKER_NODE_DIR/address.txt")
    
    echo "Funding Staker \$i (\$STAKER_ADDRESS)..."
    
    ATTEMPTS=0
    while [ \$ATTEMPTS -lt 5 ]; do
        # Try faucet
        RESULT=\$(\$SYNERGEIA_BINARY --config "\$MINER1_CONFIG" faucet --address "\$STAKER_ADDRESS" --amount \$FAUCET_AMOUNT 2>&1)
        
        # Check if output contains "TXID"
        if [[ "\$RESULT" == *"TXID"* ]]; then
            echo "Success: \$RESULT"
            break
        fi
        
        echo "Mempool full or error, waiting for block..."
        CURRENT_H=\$(get_chain_height \$MINER1_RPC_PORT)
        
        # Wait for height to increase
        WAITER=0
        while [ \$WAITER -lt 30 ]; do
            NEW_H=\$(get_chain_height \$MINER1_RPC_PORT)
            if [ "\$NEW_H" -gt "\$CURRENT_H" ]; then
                break
            fi
            sleep 1
            WAITER=\$((WAITER+1))
        done
        
        ATTEMPTS=\$((ATTEMPTS+1))
    done

    # Small wait for propagation
    sleep 1
done

echo "Waiting for funding transactions to confirm..."
sleep 15

echo "Starting $NUM_STAKERS stakers..."
for i in \$(seq 1 $NUM_STAKERS); do
    NODE_DIR="\$TESTNET_DIR/staker\$i"
    echo "Starting staker\$i..."
    nohup \$SYNERGEIA_BINARY --config "\$NODE_DIR/config.toml" start-node --mode staker > "\$NODE_DIR/node.log" 2>&1 &
done

echo "Configuring on-chain stake for stakers..."
for i in \$(seq 1 $NUM_STAKERS); do
    NODE_DIR="\$TESTNET_DIR/staker\$i"
    STAKER_PORT=$((BASE_RPC_PORT + NUM_MINERS))
    STAKER_PORT=\$((STAKER_PORT + i))
    
    # Wait for RPC with 90s timeout
    WAITED=0
    while [ \$WAITED -lt 90 ]; do
        H=\$(get_chain_height \$STAKER_PORT)
        if [ "\$H" -ge "0" ]; then
            break
        fi
        sleep 2
        WAITED=\$((WAITED+2))
    done
    
    if [ "\$H" -ge "0" ]; then
        \$SYNERGEIA_BINARY --config "\$NODE_DIR/config.toml" stake --asset SYN --amount 100000
        echo "Staker \$i configured."
    else
        echo "Error: Staker \$i RPC on port \$STAKER_PORT not responding."
    fi
done

echo "Testnet active. Total: 32 nodes."
echo "Logs are located in local_testnet/minerX/node.log or stakerX/node.log"
EOF

chmod +x ./start_testnet.sh

# --- Generate Stop Script ---
echo "Generating stop_testnet.sh..."
cat << EOF > ./stop_testnet.sh
#!/bin/bash
echo "Stopping all Synergeia nodes..."
pkill -f "synergeia-node"
pkill -f "cargo run"
echo "All nodes stopped."
EOF
chmod +x ./stop_testnet.sh

echo "Setup complete!"
echo "Run './start_testnet.sh' to start the local testnet."
echo "Run './stop_testnet.sh' to stop the local testnet."