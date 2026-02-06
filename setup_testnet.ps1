#Requires -Version 5.1

# --- Configuration ---
$numMiners = 16
$numStakers = 16
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
    $bootstrapStr = if ($i -eq 1) { "[]" } else { "[$($minerP2pAddresses[0])]" }

    $configContent = Get-Content -Path (Join-Path -Path $projectRoot -ChildPath "miner.toml") -Raw
    $configContent = $configContent -replace 'rpc_port = \d+', "rpc_port = $rpcPort"
    $configContent = $configContent -replace 'p2p_port = \d+', "p2p_port = $p2pPort"
    $configContent = $configContent -replace 'db_path = ".*"', "db_path = `"$dbPath`""
    $configContent = $configContent -replace 'wallet_file = ".*"', "wallet_file = `"$walletPath`""
    $configContent = $configContent -replace 'bootstrap_nodes = .*', "bootstrap_nodes = $bootstrapStr"
    $configContent = $configContent -replace 'coinbase_maturity = \d+', 'coinbase_maturity = 1'
    
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
    
    $nodeConfigFile = Join-Path -Path $nodeDir -ChildPath "config.toml"
    Set-Content -Path $nodeConfigFile -Value $configContent
    $walletInfo = & $binaryPath --config "$nodeConfigFile" create-wallet
    $capturedAddr = ($walletInfo | Select-String -Pattern "Address:").Line.Split(' ')[1]
    Set-Content (Join-Path -Path $nodeDir -ChildPath "address.txt") -Value $capturedAddr
}

# --- Generate Start Script ---
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

Write-Host "Starting Miner 1 (Bootstrap Node) in a new window..."
$miner1NodeDir = Join-Path -Path $testnetDir -ChildPath "miner1"
$miner1Address = Get-Content -Path (Join-Path -Path $miner1NodeDir -ChildPath "address.txt")
$miner1ConfigFile = Join-Path -Path $miner1NodeDir -ChildPath "config.toml"

# Construct the command for Miner 1 to run in a separate visible window
# We use Tee-Object to display logs live in the window AND save them to node.log
# Removed -Encoding UTF8 for compatibility with PowerShell 5.1
$miner1Cmd = "Set-Location '$miner1NodeDir'; & '$nodeBin' --config '$miner1ConfigFile' start-node --mode miner --mine-to-address '$miner1Address' 2>&1 | Tee-Object -FilePath 'node.log'"

Start-Process powershell -ArgumentList "-NoExit", "-Command", "$miner1Cmd"

Write-Host "Waiting for Miner 1 RPC (Port 20001)..."
$timeout = 60
$sw = [System.Diagnostics.Stopwatch]::StartNew()
while ($sw.Elapsed.TotalSeconds -lt $timeout) {
    if ((Get-ChainHeight -port 20001) -ge 0) { break }
    Start-Sleep -Seconds 2
}

Write-Host "Starting remaining miners..."
for ($i = 2; $i -le $numMiners; $i++) {
    $dir = Join-Path -Path $testnetDir -ChildPath "miner$i"
    $addr = Get-Content -Path (Join-Path -Path $dir -ChildPath "address.txt")
    $conf = Join-Path -Path $dir -ChildPath "config.toml"
    # Background jobs for all other miners
    Start-Job -Name "Miner$i" -ScriptBlock { 
        param($d, $c, $a, $b) 
        Set-Location $d
        # Redirect stderr to stdout using 2>&1
        & $b --config $c start-node --mode miner --mine-to-address $a 2>&1 | Out-File "node.log"
    } -ArgumentList $dir, $conf, $addr, $nodeBin
}

Write-Host "Sequentially funding stakers via Miner 1..."
for ($i = 1; $i -le $numStakers; $i++) {
    $stakerDir = Join-Path -Path $testnetDir -ChildPath "staker$i"
    $stakerAddr = Get-Content -Path (Join-Path -Path $stakerDir -ChildPath "address.txt")
    
    $h = Get-ChainHeight -port 20001
    Write-Host "Funding Staker $i ($stakerAddr)..."
    
    $attempts = 0
    while ($attempts -lt 5) {
        $result = & $nodeBin --config "$miner1ConfigFile" faucet --address "$stakerAddr" --amount 100000 2>&1
        if ($result -like "*TXID*") { break }
        Write-Host "Mempool full, waiting for block..."
        while ((Get-ChainHeight -port 20001) -le $h) { Start-Sleep -Seconds 5 }
        $h = Get-ChainHeight -port 20001
        $attempts++
    }

    Write-Host "Waiting for confirmation block..."
    while ((Get-ChainHeight -port 20001) -le $h) { Start-Sleep -Seconds 3 }
}

Write-Host "Starting staker nodes..."
for ($i = 1; $i -le $numStakers; $i++) {
    $dir = Join-Path -Path $testnetDir -ChildPath "staker$i"
    $conf = Join-Path -Path $dir -ChildPath "config.toml"
    # Background jobs for stakers
    Start-Job -Name "Staker$i" -ScriptBlock { 
        param($d, $c, $b) 
        Set-Location $d
        # Redirect stderr to stdout using 2>&1
        & $b --config $c start-node --mode staker 2>&1 | Out-File "node.log"
    } -ArgumentList $dir, $conf, $nodeBin
}

Write-Host "Configuring on-chain stake for stakers..."
for ($i = 1; $i -le $numStakers; $i++) {
    $dir = Join-Path -Path $testnetDir -ChildPath "staker$i"
    $conf = Join-Path -Path $dir -ChildPath "config.toml"
    $port = 20000 + $numMiners + $i
    
    # Wait for RPC
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    while ($sw.Elapsed.TotalSeconds -lt 90) {
        if ((Get-ChainHeight -port $port) -ge 0) { break }
        Start-Sleep -Seconds 2
    }

    if ((Get-ChainHeight -port $port) -ge 0) {
        & $nodeBin --config $conf stake --asset SYN --amount 100000
        Write-Host "Staker $i configured."
    } else {
        Write-Error "Staker $i RPC on port $port not responding."
    }
}

Write-Host "Testnet active. Total: 32 nodes."
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
Write-Host "Stopped."
'@
Set-Content -Path (Join-Path -Path $projectRoot -ChildPath "stop_testnet.ps1") -Value $stopScriptContent
Write-Host "Done. Run '.\start_testnet.ps1'."