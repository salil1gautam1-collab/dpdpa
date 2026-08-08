<#
    DPDPA Sentinel — Active Directory / GPO read-only collector
    ----------------------------------------------------------------
    Run this on a domain-joined machine as a user with READ access to AD
    (a standard Domain User can read most of this). It performs READ-ONLY
    queries and prints a JSON blob to the console. Copy that JSON and paste
    it into the AD / GPO connector in your DPDPA Sentinel workspace.

    It changes NOTHING. Review the script before running — that is the point
    of shipping it in source form.

    Requires the ActiveDirectory and GroupPolicy modules (RSAT).
#>

$ErrorActionPreference = 'SilentlyContinue'

$pp = Get-ADDefaultDomainPasswordPolicy
$staleDate = (Get-Date).AddDays(-90)
$stale = (Get-ADUser -Filter {Enabled -eq $true} -Properties LastLogonDate |
          Where-Object { $_.LastLogonDate -and $_.LastLogonDate -lt $staleDate }).Count
$totalUsers = (Get-ADUser -Filter {Enabled -eq $true}).Count

$priv = @{}
foreach ($g in 'Domain Admins','Enterprise Admins','Schema Admins') {
    $m = (Get-ADGroupMember -Identity $g -Recursive | Measure-Object).Count
    if ($m -ne $null) { $priv[$g] = $m }
}

# Best-effort GPO signal — parse all-GPO report for common hardening settings
$gpoXml = ''
try { $gpoXml = (Get-GPOReport -All -ReportType Xml) } catch {}
$gpo = @{
    screenLockConfigured  = [bool]($gpoXml -match 'ScreenSaverIsSecure|InactivityTimeoutSecs|ScreenSaveTimeOut')
    auditPolicyConfigured = [bool]($gpoXml -match 'AuditPolicy|Audit Policy|SubcategoryName')
    usbStorageBlocked     = [bool]($gpoXml -match 'USBSTOR|RemovableStorageDevices')
}

$out = [ordered]@{
    passwordPolicy = [ordered]@{
        minLength         = [int]$pp.MinPasswordLength
        complexity        = [bool]$pp.ComplexityEnabled
        lockoutThreshold  = [int]$pp.LockoutThreshold
        maxPasswordAgeDays = [int]$pp.MaxPasswordAge.Days
    }
    totalUsers       = $totalUsers
    privilegedGroups = $priv
    staleAccounts    = $stale
    gpo              = $gpo
    collectedAtUtc   = (Get-Date).ToUniversalTime().ToString('o')
}

$out | ConvertTo-Json -Depth 5
