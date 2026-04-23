using System.Text.Json;
using System.Text.RegularExpressions;
using Securityzator.Infrastructure.Automation;
using Securityzator.Infrastructure.Graph;

namespace Securityzator.Infrastructure.Teams;

public sealed class TeamsMeetingPolicyAutomationClient
{
    private const string TeamsAdminApiScope = "48ac35b8-9aa8-4d74-927d-1f4a14a0b239/.default";
    private readonly WindowsPowerShellRunner _powerShellRunner;
    private readonly GraphAccessTokenService _tokenService;

    public TeamsMeetingPolicyAutomationClient(
        WindowsPowerShellRunner powerShellRunner,
        GraphAccessTokenService tokenService)
    {
        _powerShellRunner = powerShellRunner;
        _tokenService = tokenService;
    }

    public async Task<TeamsMeetingPolicyBaselineResult> ApplyGlobalMeetingHardeningBaselineAsync(
        string tenantId,
        string clientId,
        string clientSecret,
        CancellationToken cancellationToken = default)
    {
        var graphAccessToken = await _tokenService.AcquireApplicationTokenForScopeAsync(
            tenantId,
            clientId,
            clientSecret,
            "https://graph.microsoft.com/.default",
            cancellationToken);
        var teamsAccessToken = await _tokenService.AcquireApplicationTokenForScopeAsync(
            tenantId,
            clientId,
            clientSecret,
            TeamsAdminApiScope,
            cancellationToken);
        var graphRoles = ExtractRoles(graphAccessToken);

        var script = BuildApplyBaselineScript(graphAccessToken, teamsAccessToken);
        var result = await _powerShellRunner.ExecuteScriptAsync(script, cancellationToken);

        if (!result.Succeeded)
        {
            throw new InvalidOperationException(
                NormalizeProbeFailure(BuildPowerShellErrorMessage(result), graphRoles));
        }

        var payloadText = ExtractJsonPayload(result.StandardOutput);

        try
        {
            var payload = JsonSerializer.Deserialize<TeamsMeetingPolicyBaselinePayload>(
                payloadText,
                new JsonSerializerOptions(JsonSerializerDefaults.Web));

            if (payload is null)
            {
                throw new InvalidOperationException("Teams automation returned an empty payload.");
            }

            if (!payload.Success)
            {
                throw new InvalidOperationException(
                    NormalizeProbeFailure(
                        payload.ErrorMessage ?? "Teams meeting automation failed without returning a reason.",
                        graphRoles));
            }

            if (payload.After is null)
            {
                throw new InvalidOperationException("Teams automation returned an empty payload.");
            }

            return new TeamsMeetingPolicyBaselineResult(
                payload.AlreadyCompliant,
                payload.After.Identity,
                payload.Before,
                payload.After);
        }
        catch (JsonException ex)
        {
            throw new InvalidOperationException(
                $"Teams automation returned an unreadable payload. {ex.Message}",
                ex);
        }
    }

    public async Task<TeamsMeetingPolicyProbeResult> ProbeGlobalMeetingPolicyReadAsync(
        string tenantId,
        string clientId,
        string clientSecret,
        CancellationToken cancellationToken = default)
    {
        var graphAccessToken = await _tokenService.AcquireApplicationTokenForScopeAsync(
            tenantId,
            clientId,
            clientSecret,
            "https://graph.microsoft.com/.default",
            cancellationToken);
        var teamsAccessToken = await _tokenService.AcquireApplicationTokenForScopeAsync(
            tenantId,
            clientId,
            clientSecret,
            TeamsAdminApiScope,
            cancellationToken);

        var graphRoles = ExtractRoles(graphAccessToken);

        if (!graphRoles.Contains("Organization.Read.All", StringComparer.OrdinalIgnoreCase))
        {
            return new TeamsMeetingPolicyProbeResult(
                false,
                "Teams PowerShell app-based auth needs Microsoft Graph application permission Organization.Read.All before Securityzator can validate or change meeting policies.");
        }

        var script = BuildProbeReadScript(graphAccessToken, teamsAccessToken);
        var result = await _powerShellRunner.ExecuteScriptAsync(script, cancellationToken);

        if (!result.Succeeded)
        {
            return new TeamsMeetingPolicyProbeResult(
                false,
                NormalizeProbeFailure(BuildPowerShellErrorMessage(result), graphRoles));
        }

        var payloadText = ExtractJsonPayload(result.StandardOutput);

        try
        {
            var payload = JsonSerializer.Deserialize<TeamsMeetingPolicyProbePayload>(
                payloadText,
                new JsonSerializerOptions(JsonSerializerDefaults.Web));

            if (payload is null)
            {
                throw new InvalidOperationException("Teams automation returned an empty probe payload.");
            }

            if (payload.Success)
            {
                return new TeamsMeetingPolicyProbeResult(
                    true,
                    $"Teams meeting policy automation is ready. Securityzator can read the '{payload.PolicyIdentity ?? "Global"}' meeting policy on this tenant.");
            }

            return new TeamsMeetingPolicyProbeResult(
                false,
                NormalizeProbeFailure(payload.ErrorMessage ?? "The Teams probe failed without returning an error message.", graphRoles));
        }
        catch (JsonException ex)
        {
            throw new InvalidOperationException(
                $"Teams probe returned an unreadable payload. {ex.Message}",
                ex);
        }
    }

    private static string BuildApplyBaselineScript(
        string graphAccessToken,
        string teamsAccessToken)
    {
        return $$"""
                 $ErrorActionPreference = 'Stop'
                 $ProgressPreference = 'SilentlyContinue'
                 Set-StrictMode -Version Latest

                 if (-not (Get-Module -ListAvailable -Name MicrosoftTeams)) {
                     throw "The MicrosoftTeams PowerShell module is not installed on this host. Install version 4.7.1 or later before queueing the Teams meeting hardening baseline."
                 }

                 Import-Module MicrosoftTeams -MinimumVersion 4.7.1 -ErrorAction Stop

                 function Get-MeetingPolicySnapshot {
                     param([string] $Identity)

                     $policy = Get-CsTeamsMeetingPolicy -Identity $Identity -ErrorAction Stop

                     return [ordered]@{
                         identity = [string]$policy.Identity
                         autoAdmittedUsers = [string]$policy.AutoAdmittedUsers
                         designatedPresenterRoleMode = [string]$policy.DesignatedPresenterRoleMode
                         allowAnonymousUsersToJoinMeeting = [bool]$policy.AllowAnonymousUsersToJoinMeeting
                         allowAnonymousUsersToStartMeeting = [bool]$policy.AllowAnonymousUsersToStartMeeting
                         allowPstnUsersToBypassLobby = [bool]$policy.AllowPSTNUsersToBypassLobby
                         allowExternalParticipantGiveRequestControl = [bool]$policy.AllowExternalParticipantGiveRequestControl
                     }
                 }

                 Connect-MicrosoftTeams -AccessTokens @('{{EscapePowerShellSingleQuotedString(graphAccessToken)}}', '{{EscapePowerShellSingleQuotedString(teamsAccessToken)}}') -ErrorAction Stop | Out-Null

                 try {
                     try {
                         $before = Get-MeetingPolicySnapshot -Identity 'Global'
                         $alreadyCompliant =
                             $before.autoAdmittedUsers -eq 'InvitedUsers' -and
                             $before.designatedPresenterRoleMode -eq 'OrganizerOnlyUserOverride' -and
                             $before.allowAnonymousUsersToJoinMeeting -eq $false -and
                             $before.allowAnonymousUsersToStartMeeting -eq $false -and
                             $before.allowPstnUsersToBypassLobby -eq $false -and
                             $before.allowExternalParticipantGiveRequestControl -eq $false

                         if (-not $alreadyCompliant) {
                             Set-CsTeamsMeetingPolicy `
                                 -Identity 'Global' `
                                 -AutoAdmittedUsers 'InvitedUsers' `
                                 -DesignatedPresenterRoleMode 'OrganizerOnlyUserOverride' `
                                 -AllowAnonymousUsersToJoinMeeting $false `
                                 -AllowAnonymousUsersToStartMeeting $false `
                                 -AllowPSTNUsersToBypassLobby $false `
                                 -AllowExternalParticipantGiveRequestControl $false `
                                 -ErrorAction Stop | Out-Null
                         }

                         $after = Get-MeetingPolicySnapshot -Identity 'Global'

                         [ordered]@{
                             success = $true
                             alreadyCompliant = $alreadyCompliant
                             before = $before
                             after = $after
                         } | ConvertTo-Json -Depth 5 -Compress
                     }
                     catch {
                         [ordered]@{
                             success = $false
                             errorMessage = $_.Exception.Message
                         } | ConvertTo-Json -Depth 5 -Compress
                     }
                 }
                 finally {
                     Disconnect-MicrosoftTeams -ErrorAction SilentlyContinue | Out-Null
                 }
                 """;
    }

    private static string BuildProbeReadScript(
        string graphAccessToken,
        string teamsAccessToken)
    {
        return $$"""
                 $ErrorActionPreference = 'Stop'
                 $ProgressPreference = 'SilentlyContinue'
                 Set-StrictMode -Version Latest

                 if (-not (Get-Module -ListAvailable -Name MicrosoftTeams)) {
                     throw "The MicrosoftTeams PowerShell module is not installed on this host. Install version 4.7.1 or later before validating Teams meeting automation."
                 }

                 Import-Module MicrosoftTeams -MinimumVersion 4.7.1 -ErrorAction Stop
                 Connect-MicrosoftTeams -AccessTokens @('{{EscapePowerShellSingleQuotedString(graphAccessToken)}}', '{{EscapePowerShellSingleQuotedString(teamsAccessToken)}}') -ErrorAction Stop | Out-Null

                 try {
                     try {
                         $policy = Get-CsTeamsMeetingPolicy -Identity 'Global' -ErrorAction Stop

                         [ordered]@{
                             success = $true
                             policyIdentity = [string]$policy.Identity
                         } | ConvertTo-Json -Compress
                     }
                     catch {
                         [ordered]@{
                             success = $false
                             errorMessage = $_.Exception.Message
                         } | ConvertTo-Json -Compress
                     }
                 }
                 finally {
                     Disconnect-MicrosoftTeams -ErrorAction SilentlyContinue | Out-Null
                 }
                 """;
    }

    private static string ExtractJsonPayload(string standardOutput)
    {
        var lines = standardOutput
            .ReplaceLineEndings("\n")
            .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        var payload = lines.LastOrDefault(line => line.StartsWith('{') && line.EndsWith('}'));

        if (string.IsNullOrWhiteSpace(payload))
        {
            throw new InvalidOperationException("Teams automation completed without returning a JSON payload.");
        }

        return payload;
    }

    private static string BuildPowerShellErrorMessage(PowerShellExecutionResult result)
    {
        var errorText = SanitizePowerShellOutput(result.StandardError);
        var outputText = SanitizePowerShellOutput(result.StandardOutput);
        var details = !string.IsNullOrWhiteSpace(errorText)
            ? errorText
            : outputText;
        var normalized = string.IsNullOrWhiteSpace(details)
            ? $"The PowerShell process exited with code {result.ExitCode}."
            : details.Trim().ReplaceLineEndings(" ");

        return normalized.Length <= 400 ? normalized : normalized[..400];
    }

    private static string SanitizePowerShellOutput(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        var normalized = value.ReplaceLineEndings("\n");
        if (normalized.Contains("<Objs Version=\"1.1.0.1\"", StringComparison.Ordinal))
        {
            normalized = Regex.Replace(normalized, "<[^>]+>", " ");
            normalized = System.Net.WebUtility.HtmlDecode(normalized);
        }

        var lines = normalized
            .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(line => !line.StartsWith("#< CLIXML", StringComparison.OrdinalIgnoreCase)
                           && !line.Contains("Preparing modules for first use.", StringComparison.OrdinalIgnoreCase))
            .ToArray();

        return string.Join(" ", lines);
    }

    private static string[] ExtractRoles(string accessToken)
    {
        var tokenParts = accessToken.Split('.');

        if (tokenParts.Length < 2)
        {
            return Array.Empty<string>();
        }

        var payload = tokenParts[1]
            .Replace('-', '+')
            .Replace('_', '/');

        switch (payload.Length % 4)
        {
            case 2:
                payload += "==";
                break;
            case 3:
                payload += "=";
                break;
        }

        try
        {
            var payloadBytes = Convert.FromBase64String(payload);
            using var document = JsonDocument.Parse(payloadBytes);

            if (!document.RootElement.TryGetProperty("roles", out var rolesElement)
                || rolesElement.ValueKind != JsonValueKind.Array)
            {
                return Array.Empty<string>();
            }

            return rolesElement
                .EnumerateArray()
                .Select(static role => role.GetString())
                .Where(static role => !string.IsNullOrWhiteSpace(role))
                .Cast<string>()
                .ToArray();
        }
        catch
        {
            return Array.Empty<string>();
        }
    }

    private static string NormalizeProbeFailure(
        string message,
        IReadOnlyCollection<string> graphRoles)
    {
        if (string.IsNullOrWhiteSpace(message))
        {
            return "Teams meeting policy automation failed without returning a reason.";
        }

        var normalized = message.Trim().ReplaceLineEndings(" ");
        var hasOrganizationRead =
            graphRoles.Contains("Organization.Read.All", StringComparer.OrdinalIgnoreCase);

        if (normalized.Contains("Access Denied", StringComparison.OrdinalIgnoreCase))
        {
            if (!hasOrganizationRead)
            {
                return "Teams meeting automation is blocked because the app token does not include Microsoft Graph Organization.Read.All.";
            }

            return "Teams meeting automation reached the tenant but Get-CsTeamsMeetingPolicy returned Access Denied. The service principal likely still needs a Microsoft Entra admin role assignment such as Teams Administrator.";
        }

        return normalized.Length <= 320 ? normalized : normalized[..320];
    }

    private static string EscapePowerShellSingleQuotedString(string value)
    {
        return value.Replace("'", "''", StringComparison.Ordinal);
    }

    public sealed record TeamsMeetingPolicyBaselineResult(
        bool AlreadyCompliant,
        string PolicyIdentity,
        TeamsMeetingPolicySnapshot? Before,
        TeamsMeetingPolicySnapshot After);

    public sealed record TeamsMeetingPolicyProbeResult(
        bool Succeeded,
        string Message);

    public sealed record TeamsMeetingPolicySnapshot(
        string Identity,
        string AutoAdmittedUsers,
        string DesignatedPresenterRoleMode,
        bool AllowAnonymousUsersToJoinMeeting,
        bool AllowAnonymousUsersToStartMeeting,
        bool AllowPstnUsersToBypassLobby,
        bool AllowExternalParticipantGiveRequestControl);

    private sealed record TeamsMeetingPolicyBaselinePayload(
        bool Success,
        bool AlreadyCompliant,
        TeamsMeetingPolicySnapshot? Before,
        TeamsMeetingPolicySnapshot? After,
        string? ErrorMessage);

    private sealed record TeamsMeetingPolicyProbePayload(
        bool Success,
        string? PolicyIdentity,
        string? ErrorMessage);
}
