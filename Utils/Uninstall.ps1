# Removes ALL custom local group policy settings, and returns system to default

$IsAdmin = [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")
if (-not $IsAdmin){
    throw "Script is not running with administrative privileges"
}

Remove-Item -Path "$env:WinDir\System32\GroupPolicyUsers\*" -Recurse -Force
Remove-Item -Path "$env:WinDir\System32\GroupPolicy\*" -Recurse -Force

secedit /configure /cfg "$env:windir\inf\defltbase.inf" /db "defltbase.sdb" /verbose

gpupdate /force

Write-Host "Done. Please reboot your device to apply all settings"