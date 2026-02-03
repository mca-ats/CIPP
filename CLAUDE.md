# cipp

## Overview
The goal of this project is to connect to the CIPP API and be able to manage tenants programatically. 

## Commands
```pwsh
# Build/run commands go here
```

## Code Style
- Style preferences that differ from defaults
- Patterns to follow

## Notes
Connection example:
$CIPPAPIUrl = "$CIPP_API_URL"
$ApplicationId = "$CIPP_CLIENT_ID"
$ApplicationSecret = "CIPP_API_Secret"
$TenantId = "$CIPP_TENANT_ID"

$AuthBody = @{
    client_id     = $ApplicationId
    client_secret = $ApplicationSecret
    scope         = "api://$($ApplicationId)/.default"
    grant_type    = 'client_credentials'
}
$token = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" -Method POST -Body $AuthBody

$AuthHeader = @{ Authorization = "Bearer $($token.access_token)" }
Invoke-RestMethod -Uri "$CIPPAPIUrl/api/ListLogs" -Method GET -Headers $AuthHeader -ContentType "application/json"


