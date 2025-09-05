[CmdletBinding()]
param(
  [int]$MaxWaitSeconds = 300,
  [string]$LogPath = "$env:TEMP\List-Running-Applications-script.log",
  [string]$ARLog   = 'C:\Program Files (x86)\ossec-agent\active-response\active-responses.log'
)

$ErrorActionPreference = 'Stop'

$ScriptName = "List-Running-Applications"
$HostName   = $env:COMPUTERNAME
$LogMaxKB   = 100
$LogKeep    = 5
$RunStart   = Get-Date

function Write-Log {
  param([string]$Message,[ValidateSet('INFO','WARN','ERROR','DEBUG')]$Level='INFO')
  $ts = Get-Date -Format "yyyy-MM-dd HH:mm:sszzz"
  $line = "[$ts][$Level] $Message"
  switch ($Level) {
    'ERROR' { Write-Host $line -ForegroundColor Red }
    'WARN'  { Write-Host $line -ForegroundColor Yellow }
    default { Write-Host $line }
  }
  try { Add-Content -Path $LogPath -Value $line -ErrorAction SilentlyContinue } catch {}
}

function Rotate-Log {
  if (Test-Path $LogPath -PathType Leaf) {
    $sizeKB = [math]::Floor((Get-Item $LogPath).Length / 1KB)
    if ($sizeKB -gt $LogMaxKB) {
      for ($i = $LogKeep - 1; $i -ge 1; $i--) {
        $src = "$LogPath.$i"
        $dst = "$LogPath." + ($i + 1)
        if (Test-Path $src) { Move-Item -Force $src $dst -ErrorAction SilentlyContinue }
      }
      Move-Item -Force $LogPath "$LogPath.1" -ErrorAction SilentlyContinue
    }
  }
}
function New-ArJsonLine {
  param([hashtable]$Fields)
  $std = [ordered]@{
    timestamp      = (Get-Date).ToUniversalTime().ToString("o")
    host           = $HostName
    action         = $ScriptName
    copilot_action = $true
  }
  ($std + $Fields) | ConvertTo-Json -Compress
}

function Commit-NDJSON {
  param([string[]]$Lines)
  if (-not $Lines -or $Lines.Count -eq 0) {
    $Lines = @( New-ArJsonLine @{ status = "no_results"; message = "no entries" } )
  }
  $tmp = [System.IO.Path]::GetTempFileName()
  try {
    [System.IO.File]::WriteAllLines($tmp, $Lines, [System.Text.Encoding]::ASCII)
    try {
      Move-Item -Force -Path $tmp -Destination $ARLog
    } catch {
      Write-Log "Primary move to $ARLog failed; trying .new" "WARN"
      Move-Item -Force -Path $tmp -Destination "$ARLog.new"
    }
  } finally {
    if (Test-Path $tmp) { Remove-Item -Force $tmp -ErrorAction SilentlyContinue }
  }

  foreach ($p in @($ARLog, "$ARLog.new")) {
    if (Test-Path $p) {
      $fi   = Get-Item $p
      $head = Get-Content -Path $p -TotalCount 1 -ErrorAction SilentlyContinue
      if (-not $head) { $head = "<empty>" }
      $verify = "VERIFY: path={0} size={1}B first_line={2}" -f $fi.FullName, $fi.Length, $head
      Write-Log $verify "INFO"
    }
  }
}

Rotate-Log
Write-Log "=== SCRIPT START : $ScriptName (host=$HostName) ===" "INFO"

try {
  Write-Log "Querying running processes (with ExecutablePath)..." "INFO"

  $procs = Get-CimInstance Win32_Process |
           Where-Object { $_.ExecutablePath -and $_.Name } |
           Select-Object Name, ProcessId, ExecutablePath |
           Sort-Object Name

  $lines = @()
  $lines += New-ArJsonLine @{
    item  = "summary"
    count = ($procs | Measure-Object).Count
  }

  # One NDJSON line per process
  foreach ($p in $procs) {
    $lines += New-ArJsonLine @{
      item = "process"
      name = "$($p.Name)"
      pid  = [int]$p.ProcessId
      path = "$($p.ExecutablePath)"
    }
  }

  Commit-NDJSON -Lines $lines
}
catch {
  Write-Log $_.Exception.Message 'ERROR'
  Commit-NDJSON -Lines @(
    New-ArJsonLine @{
      status = 'error'
      error  = "$($_.Exception.Message)"
    }
  )
}
finally {
  $dur = [int](New-TimeSpan -Start $RunStart -End (Get-Date)).TotalSeconds
  Write-Log "=== SCRIPT END : duration ${dur}s ===" "INFO"
}
