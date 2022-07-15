# Build registry.pol from LGPO text file

[CmdletBinding()]
param(
    [string]$GpoPath = "..\GPOs\BasicPrivacy\Version 21H2_Win10\Enterprise\GPO",
    [string]$LgpoPath = "..\Tools"  
)

if (-not (Test-Path -Path "$LgpoPath\LGPO.exe")){
    Write-Error "LGPO.exe not found. Exiting"
}

if (-not (Test-Path -Path $GpoPath)){
    Write-Error "GPO folder not found. Exiting"
}
Start-Process -FilePath "$LgpoPath\LGPO.exe" -NoNewWindow -Wait `
    -ArgumentList "/r `"$GpoPath\Machine\machine.txt`" /w `"$GpoPath\Machine\registry.pol`"" 

Start-Process -FilePath "$LgpoPath\LGPO.exe" -NoNewWindow -Wait `
    -ArgumentList "/r `"$GpoPath\User\user.txt`" /w `"$GpoPath\User\registry.pol`""