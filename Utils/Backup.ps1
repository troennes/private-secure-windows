# Backs up current local policy

[CmdletBinding()]
param(
    [string]$LgpoPath = "..\Tools",
    [string]$OutputDir = "C:\tmp\"
)

$IsAdmin = [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")
if (-not $IsAdmin){
    throw "Script not run as admin"
}

if (-not (Test-Path -Path "$LgpoPath\LGPO.exe")){
    throw  "LGPO.exe not found. Exiting"
}

if (-not (Test-Path -Path $OutputDir)){
    Write-Warning "Output path not found. Creating it"
    mkdir $OutputDir
}

Start-Process -FilePath "$LgpoPath\LGPO.exe" -NoNewWindow -Wait -ArgumentList "/b $OutputDir"