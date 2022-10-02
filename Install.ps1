<#
.SYNOPSIS
Applies a Windows privacy and security configuration baseline to local group policy.

.DESCRIPTION
Applies a Windows privacy and security configuration baseline to local group policy.

Execute this script with one of these options to install the corresponding baseline:
 -Level Basic             - [default] Basic security and privacy
 -Level HighSecurity      - High security settings (assumes basic security setting are in place)
Advanced use and more granular control: 
 -Level BasicSecurity         - Basic security, with no privacy settings added
 -Level BasicPrivacy          - Basic privacy, with no security settings added
 -Level HighSecurityBitlocker - A subset of high security settings: Disk encryption settings
 -Level HighSecurityCredGuard - A subset of high security settings: Virtualization-based security settings
 -Level HighSecurityComputer  - A subset of high security settings: Computer settings
 -Level HighSecurityDomain    - A subset of high security settings: Domain computer settings
 -Level ExtremePrivacy        - [experimental] Privacy settings that degrade security and usability

REQUIREMENTS:

* PowerShell execution policy must be configured to allow script execution; for example,
  with a command such as the following:
  Set-ExecutionPolicy RemoteSigned

* LGPO.exe must be in the Tools subdirectory. LGPO.exe is part of
  the Security Compliance Toolkit and can be downloaded from this URL:
  https://www.microsoft.com/download/details.aspx?id=55319

.PARAMETER Level
Select level of security and privacy settings. "Basic" is the default level

#>

[CmdletBinding()]
param(
    [ValidateSet("Basic","BasicSecurity","BasicPrivacy","HighSecurity","HighSecurityCredGuard", `
        "HighSecurityComputer","HighSecurityDomain","HighSecurityBitlocker","ExtremePrivacy")]
    [string]$Level,
    [string]$LgpoPath = ".\Tools"
)

function Warn([string]$Msg){
    $Resp = $Host.UI.PromptForChoice("Warning",$Msg,@("&Yes","&No"),1)
    if ($Resp -eq 1){
        exit
    } 
}

# Check if supported Windows build
# Windows 11 22H2 - 22621
# Windows 11 21H2 - 22000
# Windows 10 21H2 - 19044
# Windows 10 21H1 - 19043
$OSVersion = [environment]::OSVersion
if (-not $OSVersion.Version.Build -in @(19043,19044,22000,22621)){
    $Msg = "Unsupported version of Windows detected. Some settings might not work as intended. " `
    + "Do you want to continue?"
    Warn $Msg
}

$IsAdmin = [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")
if (-not $IsAdmin){
    throw "Script is not running with administrative privileges. Failed to apply policies"
}

if ((Get-WmiObject Win32_OperatingSystem).ProductType -eq 2){
    throw "Execution of this local-policy script is not supported on domain controllers. Exiting."
}

if (-not $Level){
    $Msg = "Selecting default level: Basic`r`n" `
    + "This will apply basic privacy and security settings. " `
    + "Do you want to continue?"
    Warn $Msg
    $Level = "Basic"
}


############# Start copied code from Microsoft Windows Security Baseline #############

# Get location of this script
$rootDir = [System.IO.Path]::GetDirectoryName($MyInvocation.MyCommand.Path)

# Verify availability of LGPO.exe; if not in path, but in Tools subdirectory, add Tools subdirectory to the path.
$origPath = ""
if ($null -eq (Get-Command LGPO.exe -ErrorAction Ignore)){
    if (Test-Path -Path $rootDir\Tools\LGPO.exe)    {
        $origPath = $env:Path
        $env:Path = "$rootDir\Tools;" + $origPath
        Write-Verbose $env:Path
        Write-Verbose (Get-Command LGPO.exe)
    } else {
$lgpoErr = @"

  ============================================================================================
    LGPO.exe must be in the Tools subdirectory or somewhere in the Path. LGPO.exe is part of
    the Security Compliance Toolkit and can be downloaded from this URL:
    https://www.microsoft.com/download/details.aspx?id=55319
  ============================================================================================
"@
        Write-Error $lgpoErr
        return
    }
}

# All log output in Unicode
$OutputEncodingPrevious = $OutputEncoding
$OutputEncoding = [System.Text.ASCIIEncoding]::Unicode

Push-Location $rootDir

# Log file full path
$logfile = [System.IO.Path]::Combine($rootDir, "PrivateSecureWindows-" + [datetime]::Now.ToString("yyyyMMdd-HHmm-ss") + ".log")
Write-Host "Logging to $logfile ..." -ForegroundColor Cyan
$MyInvocation.MyCommand.Name + ", " + [datetime]::Now.ToString() | Out-File -LiteralPath $logfile

# Functions to simplify logging and reporting progress to the display
$dline = "=================================================================================================="
$sline = "--------------------------------------------------------------------------------------------------"
function Log([string] $line){
    $line | Out-File -LiteralPath $logfile -Append
}
function LogA([string[]] $lines){
    $lines | foreach { Log $_ }
}
function ShowProgress([string] $line){
    Write-Host $line -ForegroundColor Cyan
}
function ShowProgressA([string[]] $lines){
    $lines | foreach { ShowProgress $_ }
}
function LogAndShowProgress([string] $line){
    Log $line
    ShowProgress $line
}
function LogAndShowProgressA([string[]] $lines){
    $lines | foreach { LogAndShowProgress $_ }
}
# Wrapper to run LGPO.exe so that both stdout and stderr are redirected and
# PowerShell doesn't complain about content going to stderr.
function RunLGPO([string] $lgpoParams){
    ShowProgress "Running LGPO.exe $lgpoParams"
    LogA (cmd.exe /c "LGPO.exe $lgpoParams 2>&1")
}

############# End copied code from Microsoft Windows Security Baseline ################
Log $dline

$BasicPrivacy = ".\GPOs\BasicPrivacy\Version 21H2_Win10\Enterprise\GPO"
$BasicSecBitlocker = ".\GPOs\BasicSecBitlocker\{283903C7-6FA6-4078-92A2-25C026324F68}\DomainSysvol\GPO"
$BasicSecComputer = ".\GPOs\BasicSecComputer\{70CF3C23-9F4D-4E50-8D2A-DEAD79D5A724}\DomainSysvol\GPO"
$BasicSecDefender = ".\GPOs\BasicSecDefender\{72D1AD12-B481-44E3-9529-AC7C658508B2}\DomainSysvol\GPO"
$BasicSecDomain = ".\GPOs\BasicSecDomain\{14144BB4-26AC-4A90-B4E1-BE99F58A4FFF}\DomainSysvol\GPO"
$BasicSecUser = ".\GPOs\BasicSecUser\{065B86DC-5229-4FC1-A8C2-BF989FDAEEB4}\DomainSysvol\GPO"
$HighSecBitlocker = ".\GPOs\HighSecBitlocker\{98ECD203-A3B2-4419-B1F0-E5A68F4044CB}\DomainSysvol\GPO"
$HighSecComputer = ".\GPOs\HighSecComputer\{FB5B4EEE-3202-4D88-B70D-B0EDE21699D3}\DomainSysvol\GPO"
$HighSecCredGuard = ".\GPOs\HighSecCredGuard\{1C44F912-2A2E-444E-81E9-005FDB9018FC}\DomainSysvol\GPO"
$HighSecDomain = ".\GPOs\HighSecDomain\{0CC6A02E-2EFE-4774-B3C7-209B1C102367}\DomainSysvol\GPO"
$ExtremePrivacy = ".\GPOs\ExtremePrivacy\Version 21H2_Win10\Enterprise\GPO"

# Extra settings for other versions of Windows
$DeltaW11_21H2BasicPrivacy = ".\GPOs\Deltas\W11_21H2\BasicPrivacy.txt"
$DeltaW11_21H2BasicSecurity = ".\GPOs\Deltas\W11_21H2\BasicSecurity.txt"
$DeltaW11_22H2BasicSecComputer = ".\GPOs\Deltas\W11_22H2\BasicSecComputer.txt"
$DeltaW11_22H2BasicSecDomain = ".\GPOs\Deltas\W11_22H2\BasicSecDomain\GptTmpl.inf"
$DeltaW11_22H2HighSecComputer = ".\GPOs\Deltas\W11_22H2\HighSecComputer.txt"
$DeltaW11_22H2HighSecCredGuard = ".\GPOs\Deltas\W11_22H2\HighSecCredGuard.txt"

# Determine which GPOs to import
$GPOs = @()
$Deltas = @()

if ($Level -in @("Basic","BasicSecurity")){
    $GPOs += $BasicSecBitlocker
    $GPOs += $BasicSecComputer
    $GPOs += $BasicSecDefender
    $GPOs += $BasicSecDomain
    $GPOs += $BasicSecUser

    if ($OSVersion.Version.Build -in @(22000,22621)){
        $Deltas += $DeltaW11_21H2BasicSecurity
    }
	
	if ($OSVersion.Version.Build -eq 22621){
        $Deltas += $DeltaW11_22H2BasicSecComputer
		$AddW11_22H2BasicSecDomain = $true
    }

    # Warn against self-lockout if user is connected remotely on a public network
    if ("Public" -in (Get-NetConnectionProfile).NetworkCategory){
        $Msg = 'You are on a "Public" network profile and are about to apply settings that ' `
        + 'closes all inbound network connections. If you are remotely connected, you might ' `
        + 'lose access. Consider changing the network to "Private" profile before proceeding. ' `
        + 'Do you want to continue?'
        Warn $Msg
    }
} 

if ($Level -in @("HighSecurity")){
    $GPOs += $HighSecBitlocker
    $GPOs += $HighSecComputer
    $GPOs += $HighSecCredGuard
    $GPOs += $HighSecDomain
	
	if ($OSVersion.Version.Build -eq 22621){
        $Deltas += $DeltaW11_22H2HighSecComputer
		$Deltas += $DeltaW11_22H2HighSecCredGuard
    }
}

if ($Level -in @("HighSecurityBitlocker")){ $GPOs += $HighSecBitlocker }
if ($Level -in @("HighSecurityDomain"))   { $GPOs += $HighSecDomain }
if ($Level -in @("HighSecurityComputer")) { 
	$GPOs += $HighSecComputer 
	if ($OSVersion.Version.Build -eq 22621){
        $Deltas += $DeltaW11_22H2HighSecComputer
    }
}
if ($Level -in @("HighSecurityCredGuard")){ 
	$GPOs += $HighSecCredGuard 
	if ($OSVersion.Version.Build -eq 22621){
		$Deltas += $DeltaW11_22H2HighSecCredGuard
    }
}


if ($Level -in @("Basic","BasicPrivacy")){
    $GPOs += $BasicPrivacy

    if ($OSVersion.Version.Build -in @(22000,22621)){
        $Deltas += $DeltaW11_21H2BasicPrivacy
    }

    LogAndShowProgress "Removing preinstalled apps"
    # This cannot be done with GPO/Registry, but is a part of the restricted traffic baseline:
    # https://docs.microsoft.com/en-us/windows/privacy/manage-connections-from-windows-operating-system-components-to-microsoft-services#17-preinstalled-apps
    Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -Like "Microsoft.BingNews"} | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
    Get-AppxPackage Microsoft.BingNews | Remove-AppxPackage
    Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -Like "Microsoft.BingWeather"} | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
    Get-AppxPackage Microsoft.BingWeather | Remove-AppxPackage
    Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -Like "Microsoft.BingFinance"} | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
    Get-AppxPackage Microsoft.BingFinance | Remove-AppxPackage
    Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -Like "Microsoft.BingSports"} | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
    Get-AppxPackage Microsoft.BingSports | Remove-AppxPackage
    Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -Like "*.Twitter"} | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
    Get-AppxPackage *.Twitter | Remove-AppxPackage
    Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -Like "Microsoft.XboxApp"} | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
    Get-AppxPackage Microsoft.XboxApp | Remove-AppxPackage
    Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -Like "Microsoft.Office.Sway"} | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
    Get-AppxPackage Microsoft.Office.Sway | Remove-AppxPackage
    Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -Like "Microsoft.Office.OneNote"} | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
    Get-AppxPackage Microsoft.Office.OneNote | Remove-AppxPackage
    Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -Like "Microsoft.MicrosoftOfficeHub"} | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
    Get-AppxPackage Microsoft.MicrosoftOfficeHub | Remove-AppxPackage
    Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -Like "Microsoft.SkypeApp"} | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
    Get-AppxPackage Microsoft.SkypeApp | Remove-AppxPackage
    Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -Like "Microsoft.MicrosoftStickyNotes"} | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
    Get-AppxPackage Microsoft.MicrosoftStickyNotes | Remove-AppxPackage
    Log $dline
}

LogAndShowProgress "Copying Custom Administrative Templates"
# todo: use templates for Windows 11 22H2 on newer systems
Copy-Item -Force -Path .\Templates\*.admx -Destination "$Env:Systemroot\PolicyDefinitions"
Copy-Item -Force -Path .\Templates\en-US\*.adml -Destination "$Env:Systemroot\PolicyDefinitions\en-US"
Log $dline

LogAndShowProgress "Configuring Client Side Extensions"
RunLGPO "/v /e mitigation /e audit /e zone /e DGVBS /e DGCI" 
Log $dline

if ($Level -in @("Basic","High","BasicSecurityOnly","BasicSecurityComputerOnly")){
    LogAndShowProgress "Disabling Xbox scheduled task" $Logfile
    LogA (SCHTASKS.EXE /Change /TN \Microsoft\XblGameSave\XblGameSaveTask /DISABLE)
    Log $dline
}

foreach ($g in $GPOs){
    LogAndShowProgress "Applying GPO: $g"
    RunLGPO "/v /g `"$g`""
    Log $dline
}

foreach ($d in $Deltas){
    LogAndShowProgress "Applying GPO: $d"
    RunLGPO "/v /t `"$d`""
    Log $dline
}

if ($AddW11_22H2BasicSecDomain){
    LogAndShowProgress "Applying GPO: $DeltaW11_22H2BasicSecDomain"
	RunLGPO "v /s `"$DeltaW11_22H2BasicSecDomain`""
	Log $dline
}

# Experimental / untested
if ($Level -eq "ExtremePrivacy"){

    $Msg = 'You are about to implement privacy settings that reduces security and usability. ' `
    + 'Please review the machine.txt and GptTmpl.inf files, and only continue if you know what you are doing. ' `
    + 'Do you want to continue?'
    Warn $Msg

    LogAndShowProgress "Applying extreme privacy GPO's"
    RunLGPO "/v /t `"$ExtremePrivacy\Machine\machine.txt`""
    RunLGPO "/v /s `"$ExtremePrivacy\Machine\GptTmpl.inf`""
    RunLGPO "/v /t `"$ExtremePrivacy\User\user.txt`""
    Log $dline
}

# Restore original path if modified
if ($origPath.Length -gt 0)
{
    $env:Path = $origPath
}
# Restore original output encoding
$OutputEncoding = $OutputEncodingPrevious

# Restore original directory location
Pop-Location

LogAndShowProgress "Done. Please reboot your device to apply all settings"
