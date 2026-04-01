[CmdletBinding()]
param(
    [string]$EnvPath = (Join-Path $PSScriptRoot '..' '.env'),
    [switch]$Json
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

function Format-CippTenantLine {
    param(
        [Parameter(Mandatory = $true)]
        $Tenant
    )

    $display = Get-FirstPropertyValue -Object $Tenant -Names @('displayName', 'tenantName', 'name', 'customerName')
    $domain = Get-FirstPropertyValue -Object $Tenant -Names @('defaultDomainName', 'domain', 'defaultDomain', 'tenantDomain')
    $tenantId = Get-FirstPropertyValue -Object $Tenant -Names @('tenantId', 'customerTenantId', 'tenant')

    $parts = @()
    if ($display) { $parts += "$display".Trim() }
    if ($domain) { $parts += "$domain".Trim() }

    $line = if ($parts.Count -gt 0) { $parts -join ' — ' } else { ($Tenant | ConvertTo-Json -Compress -Depth 5) }
    if ($tenantId) { $line = "$line ($("$tenantId".Trim()))" }
    return $line
}

$tenants = Get-CippTenants -EnvPath $EnvPath
function Get-CippTenantSortKey {
    param(
        [Parameter(Mandatory = $true)]
        $Tenant
    )

    $display = Get-FirstPropertyValue -Object $Tenant -Names @('displayName', 'tenantName', 'name', 'customerName')
    $domain = Get-FirstPropertyValue -Object $Tenant -Names @('defaultDomainName', 'domain', 'defaultDomain', 'tenantDomain')

    $key = "$display $domain".Trim()
    return $key.ToLowerInvariant()
}

$tenants = @($tenants) | Sort-Object { Get-CippTenantSortKey -Tenant $_ }

if ($Json) {
    $tenants | ConvertTo-Json -Depth 20
    exit 0
}

Write-Output "Tenants found: $($tenants.Count)"
foreach ($t in $tenants) {
    Write-Output ("- " + (Format-CippTenantLine -Tenant $t))
}
