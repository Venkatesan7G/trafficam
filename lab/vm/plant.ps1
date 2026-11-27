# trafficam VM lab, Windows: run attack-SHAPED traffic and write a labels file.
#
# Nothing here is malware. Each scenario makes the same kind of network
# traffic as a real attack (calling home, uploading data, random DNS names,
# a port scan), aimed at the sink VM you control (sink.py). Run it ONLY in a
# lab VM, and point -Sink and -ScanNet at your own lab network.
#
#   .\plant.ps1 -Sink 192.168.56.20 all
#   .\plant.ps1 -Sink 192.168.56.20 beacon exfil
#
# Scenarios: beacon exfil dga dns-tunnel scan dropper
# Then, as Administrator:
#   .\trafficam.exe attacks -data C:\ProgramData\trafficam -labels labels.jsonl
param(
  [Parameter(Mandatory = $true)][string]$Sink,
  [string]$ScanNet = ($Sink -replace '\.\d+$', ''),
  [int]$BeaconMin = 120,
  [int]$ExfilMB = 300,
  [string]$TunnelDomain = "example.com",
  [string]$Labels = "labels.jsonl",
  [Parameter(ValueFromRemainingArguments = $true)][string[]]$Scenarios
)
$ErrorActionPreference = "Continue"
function Now { (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ") }
function Label($id, $kind, $prog, $hostname, $start, $what) {
  $o = [ordered]@{ id = $id; kind = $kind; program = $prog; host = $hostname; start = $start; end = (Now); what = $what }
  ($o | ConvertTo-Json -Compress) | Add-Content -Encoding ascii $Labels
  Write-Host "  done: $id (label written to $Labels)"
}
function RandName($n) { -join ((1..$n) | ForEach-Object { [char[]]"abcdefghijklmnopqrstuvwxyz0123456789" | Get-Random }) }

function Beacon {
  $s = Now; Write-Host "beacon: powershell calls http://${Sink}:8080 every ~60 s for $BeaconMin min"
  $end = (Get-Date).AddMinutes($BeaconMin)
  while ((Get-Date) -lt $end) {
    try { Invoke-WebRequest -UseBasicParsing -TimeoutSec 5 "http://${Sink}:8080/ping?id=$(Get-Random)" | Out-Null } catch {}
    Start-Sleep -Seconds (55 + (Get-Random -Maximum 10))
  }
  Label beacon beacon powershell $Sink $s "powershell beacons to the sink every ~60 s"
}
function Exfil {
  $s = Now; Write-Host "exfil: powershell uploads $ExfilMB MB to http://${Sink}:8443"
  $buf = New-Object byte[] (50MB); (New-Object Random).NextBytes($buf)
  for ($i = 0; $i -lt [math]::Max(1, [int]($ExfilMB / 50)); $i++) {
    try { Invoke-WebRequest -UseBasicParsing -Method Post -Body $buf -TimeoutSec 120 "http://${Sink}:8443/upload" | Out-Null } catch {}
  }
  Label exfil exfil powershell $Sink $s "powershell uploads $ExfilMB MB to the sink"
}
function Dga {
  $s = Now; Write-Host "dga: powershell looks up 200 random .com names, then calls the sink"
  for ($i = 0; $i -lt 200; $i++) {
    try { [System.Net.Dns]::GetHostAddresses((RandName (12 + (Get-Random -Maximum 8))) + ".com") | Out-Null } catch {}
    Start-Sleep -Milliseconds 300
  }
  try { Invoke-WebRequest -UseBasicParsing -TimeoutSec 5 "http://${Sink}:8080/hello" | Out-Null } catch {}
  Label dga dga powershell "" $s "200 random-looking lookups, then a call home"
}
function DnsTunnel {
  $s = Now; Write-Host "dns-tunnel: powershell sends 1000 long random names under $TunnelDomain"
  for ($i = 0; $i -lt 1000; $i++) {
    try { [System.Net.Dns]::GetHostAddresses((RandName 48) + "." + $TunnelDomain) | Out-Null } catch {}
    Start-Sleep -Milliseconds 200
  }
  Label dns-tunnel dns-tunnel powershell $TunnelDomain $s "1000 long encoded DNS names under one domain"
}
function Scan {
  $s = Now; Write-Host "scan: powershell tries $ScanNet.1-254 on ports 22, 445, 3389"
  foreach ($i in 1..254) { foreach ($p in 22, 445, 3389) {
    $c = New-Object System.Net.Sockets.TcpClient
    try { $c.ConnectAsync("$ScanNet.$i", $p).Wait(300) | Out-Null } catch {} finally { $c.Close() }
  } }
  Label scan scan powershell "$ScanNet." $s "TCP connect scan of the lab /24"
}
function Dropper {
  $s = Now; $d = Join-Path $env:TEMP ("cache" + (Get-Random)); New-Item -ItemType Directory $d | Out-Null
  Copy-Item "$env:SystemRoot\System32\curl.exe" "$d\svchelper.exe"
  Write-Host "dropper: a copy of curl named svchelper.exe in $d calls the sink every 3 min for 30 min"
  foreach ($i in 1..10) { & "$d\svchelper.exe" -s -o NUL "http://${Sink}:8080/check"; Start-Sleep -Seconds 180 }
  Remove-Item -Recurse -Force $d
  Label dropper new-program svchelper $Sink $s "new program in a temp folder calls home"
}
function Run($x) {
  switch ($x) {
    "beacon" { Beacon } "exfil" { Exfil } "dga" { Dga } "dns-tunnel" { DnsTunnel } "scan" { Scan } "dropper" { Dropper }
    "all" { foreach ($y in "beacon", "exfil", "dga", "dns-tunnel", "scan", "dropper") { Run $y; Start-Sleep -Seconds 600 } }
    default { Write-Host "unknown scenario $x"; exit 2 }
  }
}
if (-not $Scenarios) { Write-Host "name one or more scenarios, or all"; exit 2 }
foreach ($x in $Scenarios) { Run $x }
