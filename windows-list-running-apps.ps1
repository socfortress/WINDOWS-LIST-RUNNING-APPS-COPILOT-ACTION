[CmdletBinding()]
param(
  [int]$MaxWaitSeconds = 300,
  [string]$LogPath = "$env:TEMP\ListRunningApps-script.log",
  [string]$ARLog   = 'C:\Program Files (x86)\ossec-agent\active-response\active-responses.log'
)

$ErrorActionPreference='Stop'
$HostName=$env:COMPUTERNAME
$LogMaxKB=100
$LogKeep=5
$runStart=Get-Date

function Write-Log {
  param([string]$Message,[ValidateSet('INFO','WARN','ERROR','DEBUG')]$Level='INFO')
  $ts=(Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
  $line="[$ts][$Level] $Message"
  switch($Level){
    'ERROR'{Write-Host $line -ForegroundColor Red}
    'WARN' {Write-Host $line -ForegroundColor Yellow}
    'DEBUG'{if($PSCmdlet.MyInvocation.BoundParameters.ContainsKey('Verbose')){Write-Verbose $line}}
    default{Write-Host $line}
  }
  Add-Content -Path $LogPath -Value $line
}

function Rotate-Log {
  if(Test-Path $LogPath -PathType Leaf){
    if((Get-Item $LogPath).Length/1KB -gt $LogMaxKB){
      for($i=$LogKeep-1;$i -ge 0;$i--){
        $old="$LogPath.$i";$new="$LogPath."+($i+1)
        if(Test-Path $old){Rename-Item $old $new -Force}
      }
      Rename-Item $LogPath "$LogPath.1" -Force
    }
  }
}

Rotate-Log
Write-Log "=== SCRIPT START : List Running Applications ==="

try{
  Write-Log "Querying running processes..." 'INFO'
  $processes = Get-CimInstance Win32_Process |
               Where-Object { $_.ExecutablePath -and $_.Name -ne "" } |
               Select-Object Name, ProcessId, ExecutablePath |
               Sort-Object Name

  if(-not $processes){
    Write-Log "No user-level applications found running." 'WARN'
  } else {
    Write-Log "Found $($processes.Count) running applications." 'INFO'
    foreach($proc in $processes){
      Write-Log "[$($proc.ProcessId)] $($proc.Name) => $($proc.ExecutablePath)" 'DEBUG'
    }
  }

  # Build NDJSON: summary first, then one line per app (no arrays)
  $ts = (Get-Date).ToString('o')
  $lines = @()

  $lines += ([pscustomobject]@{
    timestamp      = $ts
    host           = $HostName
    action         = 'list_running_apps_summary'
    count          = ($processes | Measure-Object).Count
    copilot_action = $true
  } | ConvertTo-Json -Compress -Depth 3)

  foreach($p in $processes){
    $lines += ([pscustomobject]@{
      timestamp      = $ts
      host           = $HostName
      action         = 'list_running_apps'
      name           = $p.Name
      pid            = $p.ProcessId
      path           = $p.ExecutablePath
      copilot_action = $true
    } | ConvertTo-Json -Compress -Depth 3)
  }

  $ndjson   = [string]::Join("`n", $lines)
  $tempFile = "$env:TEMP\arlog.tmp"
  Set-Content -Path $tempFile -Value $ndjson -Encoding ascii -Force

  $recordCount = $lines.Count
  try{
    # Atomic overwrite
    Move-Item -Path $tempFile -Destination $ARLog -Force
    Write-Log "Wrote $recordCount NDJSON record(s) to $ARLog" 'INFO'
  }catch{
    # .new fallback if locked
    Move-Item -Path $tempFile -Destination "$ARLog.new" -Force
    Write-Log "ARLog locked; wrote to $($ARLog).new" 'WARN'
  }
}
catch{
  Write-Log $_.Exception.Message 'ERROR'
  $err=[pscustomobject]@{
    timestamp      = (Get-Date).ToString('o')
    host           = $HostName
    action         = 'list_running_apps'
    status         = 'error'
    error          = $_.Exception.Message
    copilot_action = $true
  }
  $ndjson = ($err | ConvertTo-Json -Compress -Depth 3)
  $tempFile="$env:TEMP\arlog.tmp"
  Set-Content -Path $tempFile -Value $ndjson -Encoding ascii -Force
  try{
    Move-Item -Path $tempFile -Destination $ARLog -Force
    Write-Log "Error JSON written to $ARLog" 'INFO'
  }catch{
    Move-Item -Path $tempFile -Destination "$ARLog.new" -Force
    Write-Log "ARLog locked; wrote error to $($ARLog).new" 'WARN'
  }
}
finally{
  $dur=[int]((Get-Date)-$runStart).TotalSeconds
  Write-Log "=== SCRIPT END : duration ${dur}s ==="
}
