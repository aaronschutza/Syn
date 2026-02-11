#Requires -Version 5.1

# --- Configuration ---
$numMiners = 15
$numStakers = 1
$baseP2pPort = 10000
$baseRpcPort = 20000
$projectRoot = $PSScriptRoot
$testnetDir = Join-Path -Path $projectRoot -ChildPath "local_testnet"
$synergeiaBinary = "cargo"
$binaryPath = Join-Path -Path $projectRoot -ChildPath "target\debug\synergeia-node.exe"

# --- Cleanup and Setup ---
Write-Host "Cleaning up previous testnet environment..."
if (Test-Path $testnetDir) {
    Remove-Item -Path $testnetDir -Recurse -Force
}

Write-Host "Terminating existing Synergeia processes..."
Get-Process | Where-Object { 
    ($_.ProcessName -eq "cargo") -or 
    ($_.ProcessName -eq "synergeia-node") -or 
    ($_.CommandLine -like "*synergeia*") 
} | Stop-Process -Force -ErrorAction SilentlyContinue
Get-Job | Remove-Job -Force -ErrorAction SilentlyContinue

Write-Host "Creating new testnet directory..."
New-Item -Path $testnetDir -ItemType Directory | Out-Null

# --- Build the project ---
Write-Host "Building the Synergeia project..."
& $synergeiaBinary build
if ($LASTEXITCODE -ne 0) {
    Write-Error "Cargo build failed. Fix compilation errors before running."
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
    $dbPath = ($nodeDir + "/miner.db").Replace('\', '/')
    $walletPath = ($nodeDir + "/wallet.dat").Replace('\', '/')
    # Everyone connects to Miner 1
    $bootstrapStr = if ($i -eq 1) { "[]" } else { "[$($minerP2pAddresses[0])]" }

    $configContent = Get-Content -Path (Join-Path -Path $projectRoot -ChildPath "miner.toml") -Raw
    $configContent = $configContent -replace 'rpc_port = \d+', "rpc_port = $rpcPort"
    $configContent = $configContent -replace 'p2p_port = \d+', "p2p_port = $p2pPort"
    $configContent = $configContent -replace 'db_path = ".*"', "db_path = `"$dbPath`""
    $configContent = $configContent -replace 'wallet_file = ".*"', "wallet_file = `"$walletPath`""
    $configContent = $configContent -replace 'bootstrap_nodes = .*', "bootstrap_nodes = $bootstrapStr"
    $configContent = $configContent -replace 'coinbase_maturity = \d+', 'coinbase_maturity = 1'
    $configContent = $configContent -replace 'reconnect_delay_secs = \d+', 'reconnect_delay_secs = 5'
    
    $nodeConfigFile = Join-Path -Path $nodeDir -ChildPath "config.toml"
    Set-Content -Path $nodeConfigFile -Value $configContent
    
    $walletInfo = & $binaryPath --config "$nodeConfigFile" create-wallet
    $capturedAddr = ($walletInfo | Select-String -Pattern "Address:").Line.Split(' ')[1]
    Set-Content (Join-Path -Path $nodeDir -ChildPath "address.txt") -Value $capturedAddr
}

# --- Generate Staker Configurations and Wallets ---
Write-Host "Generating configurations for $numStakers stakers..."
$bootstrapNodesStr = "[" + $minerP2pAddresses[0] + "]" 

for ($i = 1; $i -le $numStakers; $i++) {
    $nodeDir = Join-Path -Path $testnetDir -ChildPath "staker$i"
    New-Item -Path $nodeDir -ItemType Directory | Out-Null
    $p2pPort = $baseP2pPort + $numMiners + $i
    $rpcPort = $baseRpcPort + $numMiners + $i
    $dbPath = ($nodeDir + "/staker.db").Replace('\', '/')
    $walletPath = ($nodeDir + "/wallet.dat").Replace('\', '/')

    $configContent = Get-Content -Path (Join-Path -Path $projectRoot -ChildPath "staker.toml") -Raw
    $configContent = $configContent -replace 'rpc_port = \d+', "rpc_port = $rpcPort"
    $configContent = $configContent -replace 'p2p_port = \d+', "p2p_port = $p2pPort"
    $configContent = $configContent -replace 'db_path = ".*"', "db_path = `"$dbPath`""
    $configContent = $configContent -replace 'wallet_file = ".*"', "wallet_file = `"$walletPath`""
    $configContent = $configContent -replace 'bootstrap_nodes =.*', "bootstrap_nodes = $bootstrapNodesStr"
    $configContent = $configContent -replace 'coinbase_maturity = \d+', 'coinbase_maturity = 1'
    $configContent = $configContent -replace 'reconnect_delay_secs = \d+', 'reconnect_delay_secs = 5'
    
    $nodeConfigFile = Join-Path -Path $nodeDir -ChildPath "config.toml"
    Set-Content -Path $nodeConfigFile -Value $configContent
    $walletInfo = & $binaryPath --config "$nodeConfigFile" create-wallet
    $capturedAddr = ($walletInfo | Select-String -Pattern "Address:").Line.Split(' ')[1]
    Set-Content (Join-Path -Path $nodeDir -ChildPath "address.txt") -Value $capturedAddr
}

# --- Generate Start Script with Interleaved Bootstrapping ---
Write-Host "Generating start_testnet.ps1..."
$startScriptContent = @'
#!/usr/bin/env powershell
$projectRoot = $PSScriptRoot
$testnetDir = Join-Path -Path $projectRoot -ChildPath "local_testnet"
$nodeBin = "__BINARY_PATH__"
$numMiners = __NUM_MINERS__
$numStakers = __NUM_STAKERS__

function Get-ChainHeight {
    param($port)
    try {
        $body = @{ jsonrpc = "2.0"; method = "print_chain"; params = @(); id = 1 } | ConvertTo-Json
        $res = Invoke-RestMethod -Uri "http://127.0.0.1:$port" -Method Post -Body $body -ContentType "application/json"
        return $res.result.height
    } catch { return -1 }
}

function Wait-For-RPC {
    param($port, $name, $timeout = 60)
    Write-Host "Waiting for $name RPC on port $port..."
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    while ($sw.Elapsed.TotalSeconds -lt $timeout) {
        if ((Get-ChainHeight -port $port) -ge 0) { return $true }
        Start-Sleep -Seconds 2
    }
    Write-Error "Timeout waiting for $name RPC."
    return $false
}

function Wait-For-Block {
    param($port, $currentHeight)
    Write-Host "Waiting for a new block on port $port (Current: $currentHeight)..."
    while ((Get-ChainHeight -port $port) -le $currentHeight) {
        Start-Sleep -Seconds 3
    }
}

# 1. START BOOTSTRAP MINER 1
Write-Host "`n[PHASE 1] Instantiating Bootstrap Miner 1..." -ForegroundColor Cyan
$m1Dir = Join-Path -Path $testnetDir -ChildPath "miner1"
$m1Addr = Get-Content -Path (Join-Path -Path $m1Dir -ChildPath "address.txt")
$m1Conf = Join-Path -Path $m1Dir -ChildPath "config.toml"
$m1Cmd = "Set-Location '$m1Dir'; & '$nodeBin' --config '$m1Conf' start-node --mode miner --mine-to-address '$m1Addr' 2>&1 | Tee-Object -FilePath 'node.log'"
Start-Process powershell -ArgumentList "-NoExit", "-Command", "$m1Cmd"

if (!(Wait-For-RPC -port 20001 -name "Miner 1")) { exit 1 }

# Wait for block 2 so Miner 1 has mature spendable funds (maturity=1)
Write-Host "Waiting for Miner 1 to mine initial blocks..."
Wait-For-Block -port 20001 -currentHeight 1

# 2. START BOOTSTRAP STAKER 1
Write-Host "`n[PHASE 2] Instantiating Bootstrap Staker 1..." -ForegroundColor Cyan
$s1Dir = Join-Path -Path $testnetDir -ChildPath "staker1"
$s1Addr = Get-Content -Path (Join-Path -Path $s1Dir -ChildPath "address.txt")
$s1Conf = Join-Path -Path $s1Dir -ChildPath "config.toml"

# Fund Staker 1 via Miner 1
# NOTE: Miner 1 sends 100,000 coins. Staker 1 will stake 90,000 of them.
$h = Get-ChainHeight -port 20001
$res = & "$nodeBin" --config "$m1Conf" send --to "$s1Addr" --amount 100000 2>&1
Write-Host "Sending funds to Staker 1... TXID: $res"
Wait-For-Block -port 20001 -currentHeight $h

# Start Staker 1
$s1Cmd = "Set-Location '$s1Dir'; & '$nodeBin' --config '$s1Conf' start-node --mode staker 2>&1 | Tee-Object -FilePath 'node.log'"
Start-Process powershell -ArgumentList "-NoExit", "-Command", "$s1Cmd"

$s1Rpc = 20000 + $numMiners + 1
if (Wait-For-RPC -port $s1Rpc -name "Staker 1") {
    Write-Host "Registering stake for Staker 1..."
    & "$nodeBin" --config "$s1Conf" stake --asset SYN --amount 90000 | Out-Null
    Write-Host "Staker 1 configured. Waiting for stake confirmation..."
    
    # Wait for the stake tx to be mined into a block
    $h = Get-ChainHeight -port 20001
    Wait-For-Block -port 20001 -currentHeight $h
    
    Write-Host "Staker 1 is now active." -ForegroundColor Green
}

# 3. INTERLEAVED BACKGROUND EXPANSION
Write-Host "`n[PHASE 3] Expanding Testnet..." -ForegroundColor Cyan
$maxCount = [math]::Max($numMiners, $numStakers)

for ($i = 2; $i -le $maxCount; $i++) {
    
    # Start Miner i
    if ($i -le $numMiners) {
        $mDir = Join-Path -Path $testnetDir -ChildPath "miner$i"
        $mAddr = Get-Content -Path (Join-Path -Path $mDir -ChildPath "address.txt")
        $mConf = Join-Path -Path $mDir -ChildPath "config.toml"
        $mRpc = 20000 + $i
        
        Write-Host ">>> Starting Miner $i..."
        Start-Job -Name "Miner$i" -ScriptBlock { 
            param($d, $c, $a, $b) 
            Set-Location $d
            & $b --config $c start-node --mode miner --mine-to-address $a 2>&1 | Out-File "node.log"
        } -ArgumentList $mDir, $mConf, $mAddr, $nodeBin
    }

    # Start Staker i
    if ($i -le $numStakers) {
        $sDir = Join-Path -Path $testnetDir -ChildPath "staker$i"
        $sAddr = Get-Content -Path (Join-Path -Path $sDir -ChildPath "address.txt")
        $sConf = Join-Path -Path $sDir -ChildPath "config.toml"
        $sRpc = 20000 + $numMiners + $i
        
        Write-Host ">>> Funding Staker $i..."
        # Funding from Miner 1 again (Miner 1 is the faucet)
        & "$nodeBin" --config "$m1Conf" send --to "$sAddr" --amount 100000 2>&1 | Out-Null
        
        Write-Host ">>> Starting Staker $i..."
        Start-Job -Name "Staker$i" -ScriptBlock { 
            param($d, $c, $b) 
            Set-Location $d
            & $b --config $c start-node --mode staker 2>&1 | Out-File "node.log"
        } -ArgumentList $sDir, $sConf, $nodeBin

        # We don't wait for RPC here to speed up launch, but we attempt stake blindly
        # (It will fail until RPC is up, but user can manually stake later or script can be improved)
        # For robustness, we just launch the process here.
    }
    
    Start-Sleep -Seconds 2
}

Write-Host "`nTestnet setup complete. Total nodes: $((($numMiners + $numStakers)))" -ForegroundColor Green
Write-Host "NOTE: Miners 2-$numMiners and Stakers 2-$numStakers are running in background jobs."
'@
$startScriptContent = $startScriptContent -replace '__BINARY_PATH__', $binaryPath.Replace('\', '\\')
$startScriptContent = $startScriptContent -replace '__NUM_MINERS__', $numMiners
$startScriptContent = $startScriptContent -replace '__NUM_STAKERS__', $numStakers
Set-Content -Path (Join-Path -Path $projectRoot -ChildPath "start_testnet.ps1") -Value $startScriptContent

$stopScriptContent = @'
#!/usr/bin/env powershell
Get-Job | Stop-Job -ErrorAction SilentlyContinue
Get-Job | Remove-Job -Force -ErrorAction SilentlyContinue
Get-Process | Where-Object { ($_.ProcessName -eq "cargo") -or ($_.ProcessName -eq "synergeia-node") -or ($_.CommandLine -like "*synergeia*") } | Stop-Process -Force -ErrorAction SilentlyContinue
Write-Host "Stopped all testnet nodes."
'@
Set-Content -Path (Join-Path -Path $projectRoot -ChildPath "stop_testnet.ps1") -Value $stopScriptContent
Write-Host "Done. Run '.\start_testnet.ps1' to begin interleaved bootstrap."