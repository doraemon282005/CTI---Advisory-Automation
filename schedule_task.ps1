<#
.SYNOPSIS
    Registers a daily Windows Scheduled Task to execute the Application Advisory Surveillance pipeline
    every morning at 5:00 AM from the CTI Adversary API Codebase directory.
#>

$TaskName = "CTI_Application_Advisory_Surveillance"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$BatPath = Join-Path $ScriptDir "run_daily.bat"

Write-Host "Configuring Windows Scheduled Task: $TaskName" -ForegroundColor Cyan
Write-Host "Working Directory: $ScriptDir"
Write-Host "Target Script:     $BatPath"

$Action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c `"$BatPath`"" -WorkingDirectory $ScriptDir
$Trigger = New-ScheduledTaskTrigger -Daily -At "05:00AM"
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

try {
    $existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Host "Existing task found. Updating..." -ForegroundColor Yellow
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    }

    Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Settings $Settings -Description "Daily morning security advisory ingestion and vulnerability tracking for applications"
    Write-Host "`n[SUCCESS] Task '$TaskName' has been successfully registered!" -ForegroundColor Green
    Write-Host "It will trigger every morning at 05:00 AM so the sheets are ready before your workday starts." -ForegroundColor Green
}
catch {
    Write-Host "`n[Notice] Administrator privileges may be required to register system-level tasks." -ForegroundColor Yellow
    Write-Host "Error details: $_"
    Write-Host "You can also run run_daily.bat manually at any time."
}
