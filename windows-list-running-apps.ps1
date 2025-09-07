[CmdletBinding()]
param(
  [int]$MaxWaitSeconds = 300,
  [string]$LogPath = "$env:TEMP\List-Running-Applications-script.log",
  [string]$ARLog   = 'C:\Program Files (x86)\ossec-agent\active-response\active-responses.log'
)

$ErrorActionPreference = 'Stop'

$ScriptName = "list_running_applications"
$HostName   = $env:COMPUTERNAME
$LogMaxKB   = 100
$LogKeep    = 5
$RunStart   = Get-Date

function Write-Log {
  param([string]$Message,[ValidateSet('INFO','WARN','ERROR','DEBUG')]$Level='INFO')
  $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
  $line = "[$ts][$Level] $Message"
  switch ($Level) {
    'ERROR' { Write-Host $line -ForegroundColor Red }
    'WARN'  { Write-Host $line -ForegroundColor Yellow }
    default { Write-Host $line }
  }
  try { Add-Content -Path $LogPath -Value $line -Encoding utf8 -ErrorAction SilentlyContinue } catch {}
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
    timestamp      = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    host           = $HostName
    action         = $ScriptName
    copilot_action = $true
  }
  ($std + $Fields) | ConvertTo-Json -Compress
}

function Commit-NDJSON {
  param([string[]]$Lines,[string]$Path=$ARLog)
  if (-not $Lines -or $Lines.Count -eq 0) {
    $Lines = @( New-ArJsonLine @{ item = 'summary'; status = 'no_results'; description = 'no entries' } )
  }
  $tmp = [System.IO.Path]::Combine($env:TEMP, "arlog_{0}.tmp" -f ([guid]::NewGuid().ToString('N')))
  try {
    $payload = ($Lines -join [Environment]::NewLine) + [Environment]::NewLine
    [System.IO.File]::WriteAllText($tmp, $payload, [System.Text.Encoding]::ASCII)
    try {
      Move-Item -Force -Path $tmp -Destination $Path
    } catch {
      Write-Log "Primary move to $Path failed; writing to .new" "WARN"
      Move-Item -Force -Path $tmp -Destination ($Path + '.new')
    }
  } finally {
    if (Test-Path $tmp) { Remove-Item -Force $tmp -ErrorAction SilentlyContinue }
  }
}

Rotate-Log
Write-Log "=== SCRIPT START : $ScriptName (host=$HostName) ===" "INFO"

try {
  Write-Log "Querying running processes (CIM Win32_Process, with ExecutablePath)..." "INFO"

  $queryStart = Get-Date
  $procs = Get-CimInstance Win32_Process -ErrorAction Stop |
           Where-Object { $_.ExecutablePath -and $_.Name } |
           Select-Object Name, ProcessId, ExecutablePath |
           Sort-Object Name
  $queryMs = [math]::Round(((Get-Date) - $queryStart).TotalMilliseconds)

  $count = ($procs | Measure-Object).Count

  $lines = @()

  $lines += New-ArJsonLine @{
    item         = 'verify_source'
    description  = 'Enumerated processes via CIM Win32_Process'
    provider     = 'WMI/CIM'
    class        = 'Win32_Process'
    filter       = 'ExecutablePath IS NOT NULL'
    duration_ms  = $queryMs
  }

  $summary = New-ArJsonLine @{
    item        = 'summary'
    description = 'Run summary and counts'
    process_count = $count
    duration_s  = [math]::Round(((Get-Date) - $RunStart).TotalSeconds, 1)
  }
  $lines = ,$summary + $lines

  foreach ($p in $procs) {
    $lines += New-ArJsonLine @{
      item = 'process'
      name = "$($p.Name)"
      pid  = [int]$p.ProcessId
      path = "$($p.ExecutablePath)"
    }
  }

  Commit-NDJSON -Lines $lines -Path $ARLog
  Write-Log ("Wrote {0} NDJSON line(s) to {1}" -f $lines.Count, $ARLog) 'INFO'
}
catch {
  Write-Log $_.Exception.Message 'ERROR'
  Commit-NDJSON -Lines @(
    New-ArJsonLine @{
      item        = 'error'
      description = 'Unhandled exception'
      error       = "$($_.Exception.Message)"
    }
  ) -Path $ARLog
}
finally {
  $dur = [int](New-TimeSpan -Start $RunStart -End (Get-Date)).TotalSeconds
  Write-Log "=== SCRIPT END : duration ${dur}s ===" "INFO"
}
