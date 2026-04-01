[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [string]$UserPrincipalName,

    [string]$TenantFilter,

    [bool]$MustChange = $true,

    [string]$EnvPath = (Join-Path $PSScriptRoot '..' '.env')
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

. (Join-Path $PSScriptRoot 'cipp.ps1')

function Get-FirstPropertyValue {
    param(
        [Parameter(Mandatory = $true)]
        $Object,

        [Parameter(Mandatory = $true)]
        [string[]]$Names
    )

    foreach ($name in $Names) {
        $prop = $Object.PSObject.Properties[$name]
        if (-not $prop) { continue }
        $value = $prop.Value
        if ($null -eq $value) { continue }
        $s = "$value".Trim()
        if (-not [string]::IsNullOrWhiteSpace($s)) {
            return $value
        }
    }
    return $null
}

if ([string]::IsNullOrWhiteSpace($TenantFilter)) {
    $parts = $UserPrincipalName.Split('@', 2, [System.StringSplitOptions]::RemoveEmptyEntries)
    if ($parts.Count -ne 2 -or [string]::IsNullOrWhiteSpace($parts[1])) {
        throw "Unable to infer tenantFilter from UPN '$UserPrincipalName'. Pass -TenantFilter explicitly."
    }
    $TenantFilter = $parts[1]
}

$usersResult = Invoke-CippApi -Path '/api/ListUsers' -Method GET -EnvPath $EnvPath -Query @{ tenantFilter = $TenantFilter }
$users = if ($usersResult -is [System.Array]) { $usersResult } elseif ($usersResult.value -is [System.Array]) { $usersResult.value } else { @($usersResult) }

$matches = $users | Where-Object {
    $_.userPrincipalName -eq $UserPrincipalName -or
    $_.mail -eq $UserPrincipalName -or
    ($_.proxyAddresses -contains "SMTP:$UserPrincipalName") -or
    ($_.proxyAddresses -contains "smtp:$UserPrincipalName")
}

if (-not $matches -or $matches.Count -eq 0) {
    throw "User not found via CIPP ListUsers in tenantFilter '$TenantFilter': $UserPrincipalName"
}
if ($matches.Count -gt 1) {
    throw "Multiple users matched '$UserPrincipalName' in tenantFilter '$TenantFilter'. Refine the search."
}

$user = $matches | Select-Object -First 1
$displayName = Get-FirstPropertyValue -Object $user -Names @('displayName', 'name')
$userId = Get-FirstPropertyValue -Object $user -Names @('id', 'userId', 'UserID')

$target = if ($displayName) { "$UserPrincipalName ($displayName)" } else { $UserPrincipalName }
$action = "Reset password via CIPP ExecResetPass (MustChange=$MustChange, tenantFilter=$TenantFilter)"

if (-not $PSCmdlet.ShouldProcess($target, $action)) {
    return
}

$resetQuery = @{
    tenantFilter = $TenantFilter
    Id           = $UserPrincipalName
    MustChange   = $MustChange
}
if ($displayName) {
    $resetQuery['DisplayName'] = $displayName
}

$resetResult = Invoke-CippApi -Path '/api/ExecResetPass' -Method POST -EnvPath $EnvPath -Query $resetQuery

function Get-LinkCandidates {
    param(
        [Parameter(Mandatory = $true)]
        $Object,

        [string]$Path = ''
    )

    $results = @()
    if ($null -eq $Object) { return $results }

    $urlRegex = [regex]'https?://\S+'
    $hostPathRegex = [regex]'\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?::\d+)?/\S+'

    if ($Object -is [string]) {
        $s = $Object
        $m = $urlRegex.Match($s)
        if ($m.Success) {
            $results += [pscustomobject]@{ Path = $Path; Value = $m.Value }
            return $results
        }

        $m2 = $hostPathRegex.Match($s)
        if ($m2.Success) {
            $results += [pscustomobject]@{ Path = $Path; Value = $m2.Value }
            return $results
        }

        return $results
    }

    if ($Object -is [System.Collections.IEnumerable] -and -not ($Object -is [string])) {
        $idx = 0
        foreach ($item in $Object) {
            $childPath = if ([string]::IsNullOrWhiteSpace($Path)) { "[$idx]" } else { "$Path[$idx]" }
            $results += Get-LinkCandidates -Object $item -Path $childPath
            $idx += 1
        }
        return $results
    }

    foreach ($p in $Object.PSObject.Properties) {
        $childPath = if ([string]::IsNullOrWhiteSpace($Path)) { $p.Name } else { "$Path.$($p.Name)" }
        $results += Get-LinkCandidates -Object $p.Value -Path $childPath
    }

    return $results
}

function Select-BestLink {
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.IEnumerable]$Candidates
    )

    $scored = foreach ($c in $Candidates) {
        $v = "$($c.Value)"
        if ([string]::IsNullOrWhiteSpace($v)) { continue }
        $value = $v.Trim().TrimEnd(')', ']', '}', '"', '''', '.', ',', ';')
        $score = 0
        if ($value -match '^(?i)https?://') { $score += 10 }
        if ("$($c.Path)" -match '(?i)secret') { $score += 4 }
        if ("$($c.Path)" -match '(?i)link|url') { $score += 4 }
        if ($value -match '(?i)/p/') { $score += 2 }
        [pscustomobject]@{
            Score = $score
            Value = $value
            Path  = $c.Path
        }
    }

    if (-not $scored) { return $null }
    $best = $scored | Sort-Object -Property Score -Descending | Select-Object -First 1
    if (-not $best) { return $null }
    return $best.Value
}

$candidates = Get-LinkCandidates -Object $resetResult -Path 'Response'
$secretLink = Select-BestLink -Candidates $candidates

if ($secretLink) {
    if ($secretLink -notmatch '^(?i)https?://') {
        $secretLink = "https://$secretLink"
    }
    Write-Output $secretLink
    return
}

Write-Warning 'Password reset completed, but no secret/password link was detected in the API response. CIPP may be generating the Password Pusher link in the GUI instead of returning it via the API.'
Write-Output "UPN: $UserPrincipalName"
if ($userId) { Write-Output "UserId: $userId" }
