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
### PowerShell
Scripts read `./.env` by default.

List accessible tenants:
```pwsh
pwsh scripts/list_tenants.ps1
```

Reset a user password (prints secret link if returned):
```pwsh
pwsh scripts/reset_password.ps1 -UserPrincipalName michael@novumdives.com -WhatIf
pwsh scripts/reset_password.ps1 -UserPrincipalName michael@novumdives.com
```

Reusable API helper:
```pwsh
. scripts/cipp.ps1
$token = Get-CippAccessToken
Invoke-CippApi -Path '/api/ListLogs' -AccessToken $token
```
