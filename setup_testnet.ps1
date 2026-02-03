#Requires -Version 5.1

# --- Configuration ---
$numMiners = 16
$numStakers = 16
$baseP2pPort = 10000
$baseRpcPort = 20000
$projectRoot = $PSScriptRoot
$testnetDir = Join-Path -Path $projectRoot -ChildPath "local_testnet"
$synergeiaBinary = "cargo"

# --- Cleanup and Setup ---
Write-Host "Cleaning up previous testnet environment..."
if (Test-Path $testnetDir) {
    Remove-Item -Path $testnetDir -Recurse -Force
}
Get-Process | Where-Object { $_.ProcessName -eq "cargo" -and ($_.CommandLine -like "*synergeia*" -or $_.CommandLine -like "*syn*") } | Stop-Process -Force -ErrorAction SilentlyContinue

Write-Host "Creating new testnet directory..."
New-Item -Path $testnetDir -ItemType Directory | Out-Null

# --- Build the project ---
Write-Host "Building the Synergeia project with the latest fixes..."
& $synergeiaBinary build
if ($LASTEXITCODE -ne 0) {
    Write-Error "Cargo build failed. Please fix any compilation errors before running this script."
    exit 1
}

# --- Generate Miner Configurations and Wallets ---
Write-Host "Generating configurations for $numMiners miners..."
$minerP2pAddresses = @()
for ($i = 1; $i -le $numMiners; $i++) {
    $nodeDir = Join-Path -Path $testnetDir -ChildPath "miner$i"
    New-Item -Path $nodeDir -ItemType Directory | Out-Null

    $p2pPort = $baseP2pPort + $i
    $rpcPort = $baseRpcPort + $i
    $minerP2pAddresses += "`"127.0.0.1:$p2pPort`""

    $configContent = Get-Content -Path (Join-Path -Path $projectRoot -ChildPath "miner.toml") -Raw
    $configContent = $configContent -replace 'rpc_port = 8332', "rpc_port = $rpcPort"
    $configContent = $configContent -replace 'p2p_port = 8333', "p2p_port = $p2pPort"
    $configContent = $configContent -replace 'db_path = "miner.db"', "db_path = `"$($nodeDir -replace '\\', '/')/miner.db`""
    $configContent = $configContent -replace 'wallet_file = "miner-wallet.dat"', "wallet_file = `"$($nodeDir -replace '\\', '/')/wallet.dat`""
    $configContent = $configContent -replace 'bootstrap_nodes = \[\]', 'bootstrap_nodes = []'
    $configContent = $configContent -replace 'coinbase_maturity = 100', 'coinbase_maturity = 1'
    Set-Content -Path (Join-Path -Path $nodeDir -ChildPath "config.toml") -Value $configContent

    Write-Host "Creating wallet for miner$i..."
    $configFile = Join-Path -Path $nodeDir -ChildPath "config.toml"
    $walletInfo = & $synergeiaBinary run -- --config "$configFile" create-wallet
    $address = ($walletInfo | Select-String -Pattern "Address:").Line.Split(' ')[1]
    Set-Content -Path (Join-Path -Path $nodeDir -ChildPath "address.txt") -Value $address
}

# --- Generate Staker Configurations and Wallets ---
Write-Host "Generating configurations for $numStakers stakers..."
$stakerAddresses = @()
$bootstrapNodesStr = "[" + ($minerP2pAddresses -join ',') + "]"

for ($i = 1; $i -le $numStakers; $i++) {
    $nodeDir = Join-Path -Path $testnetDir -ChildPath "staker$i"
    New-Item -Path $nodeDir -ItemType Directory | Out-Null

    $p2pPort = $baseP2pPort + $numMiners + $i
    $rpcPort = $baseRpcPort + $numMiners + $i

    $configContent = Get-Content -Path (Join-Path -Path $projectRoot -ChildPath "staker.toml") -Raw
    $configContent = $configContent -replace 'rpc_port = 9332', "rpc_port = $rpcPort"
    $configContent = $configContent -replace 'p2p_port = 9333', "p2p_port = $p2pPort"
    $configContent = $configContent -replace 'db_path = "staker.db"', "db_path = `"$($nodeDir -replace '\\', '/')/staker.db`""
    $configContent = $configContent -replace 'wallet_file = "staker-wallet.dat"', "wallet_file = `"$($nodeDir -replace '\\', '/')/wallet.dat`""
    $configContent = $configContent -replace 'bootstrap_nodes =.*', "bootstrap_nodes = $bootstrapNodesStr"
    $configContent = $configContent -replace 'coinbase_maturity = 100', 'coinbase_maturity = 1'
    Set-Content -Path (Join-Path -Path $nodeDir -ChildPath "config.toml") -Value $configContent

    Write-Host "Creating wallet for staker$i..."
    $configFile = Join-Path -Path $nodeDir -ChildPath "config.toml"
    $walletInfo = & $synergeiaBinary run -- --config "$configFile" create-wallet
    $address = ($walletInfo | Select-String -Pattern "Address:").Line.Split(' ')[1]
    Set-Content -Path (Join-Path -Path $nodeDir -ChildPath "address.txt") -Value $address
    $stakerAddresses += $address
}

# --- Generate Start Script ---
Write-Host "Generating start_testnet.ps1..."
$startScriptContent = @'
#!/usr/bin/env powershell
$projectRoot = $PSScriptRoot
$testnetDir = Join-Path -Path $projectRoot -ChildPath "local_testnet"
$synergeiaBinary = "cargo"
$numMiners = __NUM_MINERS__
$numStakers = __NUM_STAKERS__

# --- Helper Function to Get Chain Info ---
function Get-ChainInfo {
    param($configFile)
    $chainInfoJson = & $synergeiaBinary run -- --config $configFile print-chain | ConvertFrom-Json
    return $chainInfoJson
}

# --- Start Miners ---
Write-Host "Starting all miners..."
# Start miner1 in a new, visible window for monitoring
$miner1NodeDir = Join-Path -Path $testnetDir -ChildPath "miner1"
$miner1Address = Get-Content -Path (Join-Path -Path $miner1NodeDir -ChildPath "address.txt")
$miner1ConfigFile = Join-Path -Path $miner1NodeDir -ChildPath "config.toml"
$miner1Command = "$synergeiaBinary run -- --config `"$miner1ConfigFile`" start-node --mode miner --mine-to-address `"$miner1Address`""
Start-Process powershell -ArgumentList "-NoProfile -Command `"$miner1Command`""

# Start other miners in the background
for ($i = 2; $i -le $numMiners; $i++) {
    $nodeDir = Join-Path -Path $testnetDir -ChildPath "miner$i"
    $address = Get-Content -Path (Join-Path -Path $nodeDir -ChildPath "address.txt")
    $configFile = Join-Path -Path $nodeDir -ChildPath "config.toml"
    $logFile = Join-Path -Path $nodeDir -ChildPath "output.log"
    $command = "($synergeiaBinary run -- --config `"$configFile`" start-node --mode miner --mine-to-address `"$address`") *>&1 | Out-File -FilePath `"$logFile`" -Encoding utf8"
    Start-Process powershell -ArgumentList "-NoProfile -Command `"$command`"" -WindowStyle Hidden
}

# --- Wait for Miner1 RPC ---
$miner1RpcPort = 20001
Write-Host "Waiting for miner1's RPC server on port $miner1RpcPort..."
$timeout = 120
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
while ($stopwatch.Elapsed.TotalSeconds -lt $timeout) {
    try {
        $socket = New-Object System.Net.Sockets.TcpClient("127.0.0.1", $miner1RpcPort)
        if ($socket.Connected) {
            $socket.Close()
            Write-Host "Miner1 RPC is responsive."
            break
        }
    } catch {
        Start-Sleep -Seconds 2
    }
}
if ($stopwatch.Elapsed.TotalSeconds -ge $timeout) {
    Write-Error "Timeout waiting for miner1 RPC server."
    & (Join-Path -Path $projectRoot -ChildPath "stop_testnet.ps1")
    exit 1
}

# --- Sequentially Fund Stakers and Confirm via Block Height ---
Write-Host "Funding stakers sequentially and waiting for confirmation..."
$stakeAmount = 100000

for ($i = 1; $i -le $numStakers; $i++) {
    $stakerNodeDir = Join-Path -Path $testnetDir -ChildPath "staker$i"
    $stakerAddress = Get-Content -Path (Join-Path -Path $stakerNodeDir -ChildPath "address.txt")

    # Get current block height *before* sending the transaction
    $initialHeight = (Get-ChainInfo -configFile $miner1ConfigFile).height
    Write-Host "Current block height: $initialHeight. Funding staker$i..."

    # Fund the staker
    & $synergeiaBinary run -- --config "$miner1ConfigFile" faucet "$stakerAddress" $stakeAmount

    # Wait for the next block to be mined
    Write-Host "Waiting for transaction to be confirmed..."
    $fundingConfirmed = $false
    $fundingStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    while ($fundingStopwatch.Elapsed.TotalSeconds -lt $timeout) {
        $newHeight = (Get-ChainInfo -configFile $miner1ConfigFile).height
        if ($newHeight -gt $initialHeight) {
            Write-Host "Block $newHeight found! Transaction confirmed."
            $fundingConfirmed = $true
            break
        }
        Write-Host -NoNewline "."
        Start-Sleep -Seconds 5
    }
    Write-Host "" # Newline

    if (-not $fundingConfirmed) {
        Write-Error "Timeout waiting for funding transaction for staker$i to be confirmed."
        & (Join-Path -Path $projectRoot -ChildPath "stop_testnet.ps1")
        exit 1
    }

    # Configure the stake for the now-funded staker
    Write-Host "Configuring stake for staker$i..."
    $stakerConfig = Join-Path -Path $stakerNodeDir -ChildPath "config.toml"
    & $synergeiaBinary run -- --config "$stakerConfig" stake "SYN" $stakeAmount
}

Write-Host "All stakers funded and configured."
Start-Sleep -Seconds 5

# --- Start Stakers ---
Write-Host "Starting $numStakers stakers..."
for ($i = 1; $i -le $numStakers; $i++) {
    $nodeDir = Join-Path -Path $testnetDir -ChildPath "staker$i"
    $configFile = Join-Path -Path $nodeDir -ChildPath "config.toml"
    $logFile = Join-Path -Path $nodeDir -ChildPath "output.log"
    $command = "($synergeiaBinary run -- --config `"$configFile`" start-node --mode staker) *>&1 | Out-File -FilePath `"$logFile`" -Encoding utf8"
    Start-Process powershell -ArgumentList "-NoProfile -Command `"$command`"" -WindowStyle Hidden
}

Write-Host "Testnet is fully operational. You can monitor chain growth in the visible miner1 window."
'@
$startScriptContent = $startScriptContent -replace '__NUM_MINERS__', $numMiners
$startScriptContent = $startScriptContent -replace '__NUM_STAKERS__', $numStakers
Set-Content -Path (Join-Path -Path $projectRoot -ChildPath "start_testnet.ps1") -Value $startScriptContent

# --- Generate Stop Script ---
Write-Host "Generating stop_testnet.ps1..."
$stopScriptContent = @'
#!/usr/bin/env powershell
Write-Host "Stopping all Synergeia nodes..."
Get-Process | Where-Object { $_.ProcessName -eq "cargo" -and ($_.CommandLine -like "*synergeia*" -or $_.CommandLine -like "*syn*") } | Stop-Process -Force
Write-Host "All nodes stopped."
'@
Set-Content -Path (Join-Path -Path $projectRoot -ChildPath "stop_testnet.ps1") -Value $stopScriptContent

Write-Host "Setup complete!"
Write-Host "Run './start_testnet.ps1' to start the local testnet."
Write-Host "Run './stop_testnet.ps1' to stop the local testnet."
