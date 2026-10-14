# Sequential experiment driver for the live-CTI thesis implementation.
#   powershell -File run_all.ps1                        # both datasets
#   powershell -File run_all.ps1 -Datasets cicids2017   # one dataset
# Start detached:  Start-Process powershell -ArgumentList '-File','run_all.ps1' -WindowStyle Hidden
param(
    [string[]]$Datasets = @('unsw_nb15', 'cicids2017')
)
$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$py   = Join-Path $root '.venv\Scripts\python.exe'
$log  = Join-Path $root 'logs\run_all.log'
$common = @('--max-rows', '400000', '--n-estimators', '200')

function Step($name, $script, $argList) {
    $line = "=== $name === $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Add-Content -Path $log -Value ""
    Add-Content -Path $log -Value $line
    Write-Host $line
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    & $py (Join-Path $root "scripts\$script") @argList 2>&1 | Add-Content -Path $log
    $sw.Stop()
    $done = "--- $name finished in $([math]::Round($sw.Elapsed.TotalMinutes,1)) min (exit $LASTEXITCODE) ---"
    Add-Content -Path $log -Value $done
    Write-Host $done
}

# Self-contained suites (no dataset, no network). A failure means the result
# tables this run would produce are not trustworthy, so stop immediately.
function Gate($name, $rel) {
    $line = "=== $name === $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Add-Content -Path $log -Value ""
    Add-Content -Path $log -Value $line
    Write-Host $line
    & $py (Join-Path $root $rel) 2>&1 | Add-Content -Path $log
    if ($null -ne $LASTEXITCODE -and $LASTEXITCODE -ne 0) {
        $fail = "--- $name FAILED (exit $LASTEXITCODE); aborting before any experiment ---"
        Add-Content -Path $log -Value $fail
        Write-Host $fail
        exit $LASTEXITCODE
    }
    $ok = "--- $name passed ---"
    Add-Content -Path $log -Value $ok
    Write-Host $ok
}

Set-Content -Path $log -Value "run_all started $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host "run_all: datasets = $($Datasets -join ', ')"

Gate 'verify-leakage'   'tests\test_leakage.py'
Gate 'verify-hardening' 'deploy\test_hardening.py'

Step 'feeds-poll' 'run_collect_feeds.py' @()

foreach ($ds in $Datasets) {
    Step "E1-$ds" 'run_e1_baseline.py' (@('--dataset', $ds, '--no-poll', '--with-cti') + $common)
    Step "E2-$ds" 'run_e2_ablation.py' (@('--dataset', $ds, '--no-poll') + $common)
    Step "E3-$ds" 'run_e3_freshness.py' (@('--dataset', $ds, '--no-poll') + $common)
    Step "E4-$ds" 'run_e4_explainability.py' (@('--dataset', $ds, '--no-poll', '--alerts', '400') + $common)
    Step "E5-$ds" 'run_e5_latency.py' (@('--dataset', $ds, '--no-poll') + $common)
}

if ($Datasets -contains 'unsw_nb15' -and $Datasets -contains 'cicids2017') {
    Step 'E6-cross' 'run_e6_crossdataset.py' (@('--no-poll') + $common)
}

Step 'figures' 'make_figures.py' @()
Step 'dashboard' 'build_dashboard.py' @()
Add-Content -Path $log -Value "ALL DONE $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host "ALL DONE $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
