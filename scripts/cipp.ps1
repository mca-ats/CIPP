$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Read-DotEnv {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $result = @{}
    if (-not (Test-Path -LiteralPath $Path)) {
        return $result
    }

    foreach ($raw in Get-Content -LiteralPath $Path) {
        $line = $raw.Trim()
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        if ($line.StartsWith('#')) { continue }
        if ($line.StartsWith('export ')) { $line = $line.Substring(7).TrimStart() }

        $match = [regex]::Match($line, '^(?<key>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?<value>.*)$')
        if (-not $match.Success) { continue }

        $key = $match.Groups['key'].Value
        $value = $match.Groups['value'].Value.Trim()
        if ($value.Length -ge 2) {
            $first = $value.Substring(0, 1)
            $last = $value.Substring($value.Length - 1, 1)
            if (($first -eq "'" -and $last -eq "'") -or ($first -eq '"' -and $last -eq '"')) {
                $value = $value.Substring(1, $value.Length - 2)
            }
        }

        $result[$key] = $value
    }

    return $result
}

function Get-CippConfig {
    [CmdletBinding()]
    param(
        [string]$EnvPath = (Join-Path $PSScriptRoot '..' '.env')
    )

    $fileEnv = Read-DotEnv -Path $EnvPath

    function Get-ConfigValue([string]$Name) {
        if ($fileEnv.ContainsKey($Name) -and -not [string]::IsNullOrWhiteSpace($fileEnv[$Name])) {
            return $fileEnv[$Name]
        }
        if (Test-Path -Path "Env:$Name") {
            return (Get-Item -Path "Env:$Name").Value
        }
        return $null
    }

    $apiUrl = Get-ConfigValue -Name 'CIPP_API_URL'
    $tokenUrl = Get-ConfigValue -Name 'CIPP_TOKEN_URL'
    $tenantId = Get-ConfigValue -Name 'CIPP_TENANT_ID'
    $clientId = Get-ConfigValue -Name 'CIPP_CLIENT_ID'
    $clientSecret = Get-ConfigValue -Name 'CIPP_API_Secret'

    $missing = @()
    if ([string]::IsNullOrWhiteSpace($apiUrl)) { $missing += 'CIPP_API_URL' }
    if ([string]::IsNullOrWhiteSpace($clientId)) { $missing += 'CIPP_CLIENT_ID' }
    if ([string]::IsNullOrWhiteSpace($clientSecret)) { $missing += 'CIPP_API_Secret' }
    if ([string]::IsNullOrWhiteSpace($tokenUrl) -and [string]::IsNullOrWhiteSpace($tenantId)) { $missing += 'CIPP_TOKEN_URL (or CIPP_TENANT_ID)' }

    if ($missing.Count -gt 0) {
        throw "Missing required CIPP config: $($missing -join ', ')"
    }

    [pscustomobject]@{
        ApiUrl       = $apiUrl
        TokenUrl     = $tokenUrl
        TenantId     = $tenantId
        ClientId     = $clientId
        ClientSecret = $clientSecret
        EnvPath      = $EnvPath
    }
}

function Get-CippAccessToken {
    [CmdletBinding()]
    param(
        [string]$EnvPath = (Join-Path $PSScriptRoot '..' '.env')
    )

    $config = Get-CippConfig -EnvPath $EnvPath

    $tokenUrl = $config.TokenUrl
    if ([string]::IsNullOrWhiteSpace($tokenUrl)) {
        $tokenUrl = "https://login.microsoftonline.com/$($config.TenantId)/oauth2/v2.0/token"
    }

    $body = @{
        client_id     = $config.ClientId
        client_secret = $config.ClientSecret
        scope         = "api://$($config.ClientId)/.default"
        grant_type    = 'client_credentials'
    }

    Write-Verbose "Requesting access token from $tokenUrl"
    try {
        $token = Invoke-RestMethod -Uri $tokenUrl -Method Post -Body $body -ContentType 'application/x-www-form-urlencoded'
    } catch {
        throw "Token request failed: $($_.Exception.Message)"
    }

    if (-not $token -or [string]::IsNullOrWhiteSpace($token.access_token)) {
        throw 'Token response missing access_token'
    }

    return $token.access_token
}

function ConvertTo-CippQueryString {
    [CmdletBinding()]
    param(
        [hashtable]$Query
    )

    if (-not $Query -or $Query.Count -eq 0) {
        return ''
    }

    function Normalize-QueryValue($Value) {
        if ($null -eq $Value) { return $null }
        if ($Value -is [bool]) { return $(if ($Value) { 'true' } else { 'false' }) }
        return "$Value"
    }

    $pairs = @()
    foreach ($key in $Query.Keys) {
        $rawValue = $Query[$key]
        if ($null -eq $rawValue) { continue }

        if ($rawValue -is [System.Collections.IEnumerable] -and -not ($rawValue -is [string])) {
            foreach ($item in $rawValue) {
                $normalized = Normalize-QueryValue -Value $item
                if ($null -eq $normalized) { continue }
                $pairs += "$([System.Net.WebUtility]::UrlEncode($key))=$([System.Net.WebUtility]::UrlEncode($normalized))"
            }
            continue
        }

        $normalized = Normalize-QueryValue -Value $rawValue
        if ($null -eq $normalized) { continue }
        $pairs += "$([System.Net.WebUtility]::UrlEncode($key))=$([System.Net.WebUtility]::UrlEncode($normalized))"
    }

    return ($pairs -join '&')
}

function Invoke-CippApi {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [ValidateSet('GET', 'POST', 'PUT', 'PATCH', 'DELETE')]
        [string]$Method = 'GET',

        [string]$EnvPath = (Join-Path $PSScriptRoot '..' '.env'),

        [string]$AccessToken,

        [hashtable]$Headers,

        [hashtable]$Query,

        $Body
    )

    $config = Get-CippConfig -EnvPath $EnvPath
    if ([string]::IsNullOrWhiteSpace($AccessToken)) {
        $AccessToken = Get-CippAccessToken -EnvPath $EnvPath
    }

    $uri = "$($config.ApiUrl.TrimEnd('/'))/$($Path.TrimStart('/'))"
    $qs = ConvertTo-CippQueryString -Query $Query
    if (-not [string]::IsNullOrWhiteSpace($qs)) {
        if ($uri.Contains('?')) {
            $uri = "${uri}&$qs"
        } else {
            $uri = "${uri}?$qs"
        }
    }
    $requestHeaders = @{
        Authorization = "Bearer $AccessToken"
        Accept        = 'application/json'
    }
    if ($Headers) {
        foreach ($k in $Headers.Keys) {
            $requestHeaders[$k] = $Headers[$k]
        }
    }

    $params = @{
        Uri     = $uri
        Method  = $Method
        Headers = $requestHeaders
    }

    if ($null -ne $Body -and $Method -ne 'GET') {
        if ($Body -is [string]) {
            $params['Body'] = $Body
            $params['ContentType'] = 'application/json'
        } else {
            $params['Body'] = ($Body | ConvertTo-Json -Depth 20)
            $params['ContentType'] = 'application/json'
        }
    }

    Write-Verbose "$Method $uri"
    try {
        return Invoke-RestMethod @params
    } catch {
        throw "CIPP API call failed ($Method $Path): $($_.Exception.Message)"
    }
}

function Get-CippTenants {
    [CmdletBinding()]
    param(
        [string]$EnvPath = (Join-Path $PSScriptRoot '..' '.env'),
        [string]$AccessToken
    )

    $result = Invoke-CippApi -Path '/api/ListTenants' -Method GET -EnvPath $EnvPath -AccessToken $AccessToken

    if ($null -eq $result) { return @() }
    if ($result -is [System.Array]) { return $result }

    $valueProp = $result.PSObject.Properties['value']
    if ($valueProp -and $valueProp.Value -is [System.Array]) {
        return $valueProp.Value
    }

    return @($result)
}
