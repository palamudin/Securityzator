[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $TenantId,

    [Parameter(Mandatory = $true)]
    [string] $ClientId,

    [Parameter(Mandatory = $true)]
    [string] $ClientSecret
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Set-StrictMode -Version Latest

function Get-AccessToken {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Scope
    )

    $body = @{
        client_id = $ClientId
        client_secret = $ClientSecret
        scope = $Scope
        grant_type = 'client_credentials'
    }

    (Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" -Body $body).access_token
}

function ConvertFrom-JwtPayload {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Token
    )

    $payload = $Token.Split('.')[1].Replace('-', '+').Replace('_', '/')

    switch ($payload.Length % 4) {
        2 { $payload += '==' }
        3 { $payload += '=' }
    }

    [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload)) | ConvertFrom-Json
}

$graphToken = Get-AccessToken -Scope 'https://graph.microsoft.com/.default'
$teamsToken = Get-AccessToken -Scope '48ac35b8-9aa8-4d74-927d-1f4a14a0b239/.default'

$graphPayload = ConvertFrom-JwtPayload -Token $graphToken
$teamsPayload = ConvertFrom-JwtPayload -Token $teamsToken

Import-Module MicrosoftTeams -MinimumVersion 4.7.1 -ErrorAction Stop
Connect-MicrosoftTeams -AccessTokens @($graphToken, $teamsToken) -ErrorAction Stop | Out-Null

try {
    $policy = Get-CsTeamsMeetingPolicy -Identity 'Global' -ErrorAction Stop
    [pscustomobject]@{
        success = $true
        graphRoles = @($graphPayload.roles)
        teamsAudience = $teamsPayload.aud
        policy = [pscustomobject]@{
            identity = $policy.Identity
            autoAdmittedUsers = $policy.AutoAdmittedUsers
            designatedPresenterRoleMode = $policy.DesignatedPresenterRoleMode
            allowAnonymousUsersToJoinMeeting = $policy.AllowAnonymousUsersToJoinMeeting
            allowAnonymousUsersToStartMeeting = $policy.AllowAnonymousUsersToStartMeeting
        }
    } | ConvertTo-Json -Depth 6
}
catch {
    [pscustomobject]@{
        success = $false
        graphRoles = @($graphPayload.roles)
        teamsAudience = $teamsPayload.aud
        error = [pscustomobject]@{
            message = $_.Exception.Message
            type = $_.Exception.GetType().FullName
            details = $_ | Out-String
        }
    } | ConvertTo-Json -Depth 6
}
finally {
    Disconnect-MicrosoftTeams -ErrorAction SilentlyContinue | Out-Null
}
