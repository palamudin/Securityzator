using System.Text.Json;
using System.Text.RegularExpressions;
using Securityzator.Infrastructure.Automation;

namespace Securityzator.Infrastructure.Exchange;

public sealed class DefenderForOfficeAutomationClient
{
    private const string AntiPhishPolicyName = "SS-AUTO | Anti-phish baseline";
    private const string AntiPhishRuleName = "SS-AUTO | Anti-phish baseline";
    private const string ExchangeMailboxBaselineName = "SS-AUTO | Exchange collaboration baseline";
    private const string SafeLinksPolicyName = "SS-AUTO | Safe Links baseline";
    private const string SafeLinksRuleName = "SS-AUTO | Safe Links baseline";
    private const string SafeAttachmentPolicyName = "SS-AUTO | Safe Attachments baseline";
    private const string SafeAttachmentRuleName = "SS-AUTO | Safe Attachments baseline";
    private const string SpamFilterPolicyName = "SS-AUTO | Spam baseline";
    private const string SpamFilterRuleName = "SS-AUTO | Spam baseline";
    private const string MalwareFilterPolicyName = "SS-AUTO | Anti-malware baseline";
    private const string MalwareFilterRuleName = "SS-AUTO | Anti-malware baseline";
    private const string OutboundSpamFilterPolicyName = "SS-AUTO | Outbound forwarding baseline";
    private const string OutboundSpamFilterRuleName = "SS-AUTO | Outbound forwarding baseline";
    private const uint OutboundExternalRecipientLimit = 500;
    private const uint OutboundInternalRecipientLimit = 1000;
    private const uint OutboundDailyRecipientLimit = 1000;
    private readonly WindowsPowerShellRunner _powerShellRunner;

    public DefenderForOfficeAutomationClient(WindowsPowerShellRunner powerShellRunner)
    {
        _powerShellRunner = powerShellRunner;
    }

    public async Task<DefenderForOfficeBaselineResult> ApplySafeLinksAndAttachmentsBaselineAsync(
        string tenantId,
        string clientId,
        string certificateThumbprint,
        string certificateStoreLocation,
        string certificateStoreName,
        CancellationToken cancellationToken = default)
    {
        var script = BuildApplyBaselineScript(
            tenantId,
            clientId,
            certificateThumbprint,
            certificateStoreLocation,
            certificateStoreName);
        var result = await _powerShellRunner.ExecuteScriptAsync(script, cancellationToken);

        if (!result.Succeeded)
        {
            throw new InvalidOperationException(BuildPowerShellErrorMessage(result));
        }

        var payloadText = ExtractJsonPayload(result.StandardOutput);

        try
        {
            var payload = JsonSerializer.Deserialize<DefenderForOfficeBaselinePayload>(
                payloadText,
                new JsonSerializerOptions(JsonSerializerDefaults.Web));

            if (payload is null)
            {
                throw new InvalidOperationException("Defender for Office automation returned an empty payload.");
            }

            if (!payload.Success)
            {
                throw new InvalidOperationException(
                    NormalizeFailureMessage(payload.ErrorMessage ?? "Defender for Office automation failed without returning a reason."));
            }

            if (payload.GlobalProtection is null
                || payload.SafeLinks is null
                || payload.SafeAttachments is null)
            {
                throw new InvalidOperationException("Defender for Office automation returned an incomplete payload.");
            }

            return new DefenderForOfficeBaselineResult(
                payload.AlreadyCompliant,
                payload.GlobalProtection,
                payload.SafeLinks,
                payload.SafeAttachments,
                payload.Notes ?? Array.Empty<string>());
        }
        catch (JsonException ex)
        {
            throw new InvalidOperationException(
                $"Defender for Office automation returned an unreadable payload. {ex.Message}",
                ex);
        }
    }

    public async Task<DefenderForOfficeAntiPhishBaselineResult> ApplyAntiPhishBaselineAsync(
        string tenantId,
        string clientId,
        string certificateThumbprint,
        string certificateStoreLocation,
        string certificateStoreName,
        IReadOnlyList<string> protectedUsersToProtect,
        CancellationToken cancellationToken = default)
    {
        var script = BuildApplyAntiPhishBaselineScript(
            tenantId,
            clientId,
            certificateThumbprint,
            certificateStoreLocation,
            certificateStoreName,
            protectedUsersToProtect);
        var result = await _powerShellRunner.ExecuteScriptAsync(script, cancellationToken);

        if (!result.Succeeded)
        {
            throw new InvalidOperationException(BuildPowerShellErrorMessage(result));
        }

        var payloadText = ExtractJsonPayload(result.StandardOutput);

        try
        {
            var payload = JsonSerializer.Deserialize<DefenderForOfficeAntiPhishBaselinePayload>(
                payloadText,
                new JsonSerializerOptions(JsonSerializerDefaults.Web));

            if (payload is null)
            {
                throw new InvalidOperationException("Defender for Office anti-phish automation returned an empty payload.");
            }

            if (!payload.Success)
            {
                throw new InvalidOperationException(
                    NormalizeFailureMessage(payload.ErrorMessage ?? "Defender for Office anti-phish automation failed without returning a reason."));
            }

            if (payload.AntiPhish is null)
            {
                throw new InvalidOperationException("Defender for Office anti-phish automation returned an incomplete payload.");
            }

            return new DefenderForOfficeAntiPhishBaselineResult(
                payload.AlreadyCompliant,
                payload.NeedsManualFollowUp,
                payload.AntiPhish,
                payload.Notes ?? Array.Empty<string>());
        }
        catch (JsonException ex)
        {
            throw new InvalidOperationException(
                $"Defender for Office anti-phish automation returned an unreadable payload. {ex.Message}",
                ex);
        }
    }

    public async Task<DefenderForOfficeExchangeMailboxBaselineResult> ApplyExchangeCollaborationMailboxBaselineAsync(
        string tenantId,
        string clientId,
        string certificateThumbprint,
        string certificateStoreLocation,
        string certificateStoreName,
        CancellationToken cancellationToken = default)
    {
        var script = BuildApplyExchangeCollaborationMailboxBaselineScript(
            tenantId,
            clientId,
            certificateThumbprint,
            certificateStoreLocation,
            certificateStoreName);
        var result = await _powerShellRunner.ExecuteScriptAsync(script, cancellationToken);

        if (!result.Succeeded)
        {
            throw new InvalidOperationException(BuildPowerShellErrorMessage(result));
        }

        var payloadText = ExtractJsonPayload(result.StandardOutput);

        try
        {
            var payload = JsonSerializer.Deserialize<DefenderForOfficeExchangeMailboxBaselinePayload>(
                payloadText,
                new JsonSerializerOptions(JsonSerializerDefaults.Web));

            if (payload is null)
            {
                throw new InvalidOperationException("Exchange collaboration and mailbox automation returned an empty payload.");
            }

            if (!payload.Success)
            {
                throw new InvalidOperationException(
                    NormalizeFailureMessage(payload.ErrorMessage ?? "Exchange collaboration and mailbox automation failed without returning a reason."));
            }

            if (payload.Organization is null
                || payload.OwaMailboxPolicy is null
                || payload.SharingPolicy is null)
            {
                throw new InvalidOperationException("Exchange collaboration and mailbox automation returned an incomplete payload.");
            }

            return new DefenderForOfficeExchangeMailboxBaselineResult(
                payload.AlreadyCompliant,
                payload.NeedsManualFollowUp,
                payload.Organization,
                payload.OwaMailboxPolicy,
                payload.SharingPolicy,
                payload.Notes ?? Array.Empty<string>());
        }
        catch (JsonException ex)
        {
            throw new InvalidOperationException(
                $"Exchange collaboration and mailbox automation returned an unreadable payload. {ex.Message}",
                ex);
        }
    }

    public async Task<DefenderForOfficeSpamAndForwardingBaselineResult> ApplySpamAndForwardingBaselineAsync(
        string tenantId,
        string clientId,
        string certificateThumbprint,
        string certificateStoreLocation,
        string certificateStoreName,
        CancellationToken cancellationToken = default)
    {
        var script = BuildApplySpamAndForwardingBaselineScript(
            tenantId,
            clientId,
            certificateThumbprint,
            certificateStoreLocation,
            certificateStoreName);
        var result = await _powerShellRunner.ExecuteScriptAsync(script, cancellationToken);

        if (!result.Succeeded)
        {
            throw new InvalidOperationException(BuildPowerShellErrorMessage(result));
        }

        var payloadText = ExtractJsonPayload(result.StandardOutput);

        try
        {
            var payload = JsonSerializer.Deserialize<DefenderForOfficeSpamAndForwardingBaselinePayload>(
                payloadText,
                new JsonSerializerOptions(JsonSerializerDefaults.Web));

            if (payload is null)
            {
                throw new InvalidOperationException("Defender for Office spam and forwarding automation returned an empty payload.");
            }

            if (!payload.Success)
            {
                throw new InvalidOperationException(
                    NormalizeFailureMessage(payload.ErrorMessage ?? "Defender for Office spam and forwarding automation failed without returning a reason."));
            }

            if (payload.InboundSpam is null
                || payload.OutboundSpam is null
                || payload.ConnectionFilter is null)
            {
                throw new InvalidOperationException("Defender for Office spam and forwarding automation returned an incomplete payload.");
            }

            return new DefenderForOfficeSpamAndForwardingBaselineResult(
                payload.AlreadyCompliant,
                payload.NeedsManualFollowUp,
                payload.InboundSpam,
                payload.OutboundSpam,
                payload.ConnectionFilter,
                payload.Notes ?? Array.Empty<string>());
        }
        catch (JsonException ex)
        {
            throw new InvalidOperationException(
                $"Defender for Office spam and forwarding automation returned an unreadable payload. {ex.Message}",
                ex);
        }
    }

    public async Task<DefenderForOfficeAntiMalwareBaselineResult> ApplyAntiMalwareBaselineAsync(
        string tenantId,
        string clientId,
        string certificateThumbprint,
        string certificateStoreLocation,
        string certificateStoreName,
        CancellationToken cancellationToken = default)
    {
        var script = BuildApplyAntiMalwareBaselineScript(
            tenantId,
            clientId,
            certificateThumbprint,
            certificateStoreLocation,
            certificateStoreName);
        var result = await _powerShellRunner.ExecuteScriptAsync(script, cancellationToken);

        if (!result.Succeeded)
        {
            throw new InvalidOperationException(BuildPowerShellErrorMessage(result));
        }

        var payloadText = ExtractJsonPayload(result.StandardOutput);

        try
        {
            var payload = JsonSerializer.Deserialize<DefenderForOfficeAntiMalwareBaselinePayload>(
                payloadText,
                new JsonSerializerOptions(JsonSerializerDefaults.Web));

            if (payload is null)
            {
                throw new InvalidOperationException("Defender for Office anti-malware automation returned an empty payload.");
            }

            if (!payload.Success)
            {
                throw new InvalidOperationException(
                    NormalizeFailureMessage(payload.ErrorMessage ?? "Defender for Office anti-malware automation failed without returning a reason."));
            }

            if (payload.AntiMalware is null)
            {
                throw new InvalidOperationException("Defender for Office anti-malware automation returned an incomplete payload.");
            }

            return new DefenderForOfficeAntiMalwareBaselineResult(
                payload.AlreadyCompliant,
                payload.NeedsManualFollowUp,
                payload.AntiMalware,
                payload.Notes ?? Array.Empty<string>());
        }
        catch (JsonException ex)
        {
            var payloadPreview = payloadText.Length <= 600
                ? payloadText
                : payloadText[..600];
            throw new InvalidOperationException(
                $"Defender for Office anti-malware automation returned an unreadable payload. {ex.Message} Payload: {payloadPreview}",
                ex);
        }
    }

    private static string BuildApplyAntiPhishBaselineScript(
        string tenantId,
        string clientId,
        string certificateThumbprint,
        string certificateStoreLocation,
        string certificateStoreName,
        IReadOnlyList<string> protectedUsersToProtect)
    {
        var protectedUsersLiteral = BuildPowerShellStringArrayLiteral(protectedUsersToProtect);

        return $$"""
                 $ErrorActionPreference = 'Stop'
                 $ProgressPreference = 'SilentlyContinue'
                 Set-StrictMode -Version Latest

                 $antiPhishPolicyName = '{{EscapePowerShellSingleQuotedString(AntiPhishPolicyName)}}'
                 $antiPhishRuleName = '{{EscapePowerShellSingleQuotedString(AntiPhishRuleName)}}'
                 $protectedUsersToProtect = {{protectedUsersLiteral}}

                 if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
                     throw 'The ExchangeOnlineManagement PowerShell module is not installed on this host. Install it before queueing the Defender for Office anti-phish baseline.'
                 }

                 function Get-FirstOrDefault {
                     param([object[]] $Items)

                     if ($null -eq $Items) {
                         return $null
                     }

                     return @($Items | Select-Object -First 1)[0]
                 }

                 function Get-OptionalPropertyValue {
                     param(
                         [object] $InputObject,
                         [string] $PropertyName
                     )

                     if ($null -eq $InputObject) {
                         return $null
                     }

                     $property = $InputObject.PSObject.Properties[$PropertyName]
                     if ($null -eq $property) {
                         return $null
                     }

                     return $property.Value
                 }

                 function Convert-ToStringArray {
                     param([object] $Values)

                     if ($null -eq $Values) {
                         return @()
                     }

                     return @($Values | ForEach-Object { [string] $_ } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
                 }

                 function Test-StringArrayEquals {
                     param(
                         [string[]] $Left,
                         [string[]] $Right
                     )

                     $leftValue = (@($Left | Sort-Object -Unique) -join '|')
                     $rightValue = (@($Right | Sort-Object -Unique) -join '|')

                     return $leftValue -eq $rightValue
                 }

                 function Get-CommandParameterNames {
                     param([string] $CommandName)

                     return @(
                         (Get-Command $CommandName -ErrorAction Stop).Parameters.Keys |
                             ForEach-Object { [string] $_ } |
                             Sort-Object -Unique
                     )
                 }

                 function Test-ParameterSupported {
                     param(
                         [string[]] $ParameterNames,
                         [string] $ParameterName
                     )

                     return @($ParameterNames) -contains $ParameterName
                 }

                 function Get-AntiPhishCapabilities {
                     $policyParameterNames = @(
                         (Get-CommandParameterNames -CommandName 'Set-AntiPhishPolicy') +
                         (Get-CommandParameterNames -CommandName 'New-AntiPhishPolicy') |
                             Sort-Object -Unique
                     )

                     return [ordered]@{
                         policyParameterNames = $policyParameterNames
                         supportsEnableMailboxIntelligence = Test-ParameterSupported -ParameterNames $policyParameterNames -ParameterName 'EnableMailboxIntelligence'
                         supportsEnableMailboxIntelligenceProtection = Test-ParameterSupported -ParameterNames $policyParameterNames -ParameterName 'EnableMailboxIntelligenceProtection'
                         supportsMailboxIntelligenceProtectionAction = Test-ParameterSupported -ParameterNames $policyParameterNames -ParameterName 'MailboxIntelligenceProtectionAction'
                         supportsImpersonationProtectionState = Test-ParameterSupported -ParameterNames $policyParameterNames -ParameterName 'ImpersonationProtectionState'
                         supportsEnableOrganizationDomainsProtection = Test-ParameterSupported -ParameterNames $policyParameterNames -ParameterName 'EnableOrganizationDomainsProtection'
                         supportsPhishThresholdLevel = Test-ParameterSupported -ParameterNames $policyParameterNames -ParameterName 'PhishThresholdLevel'
                         supportsEnableSimilarDomainsSafetyTips = Test-ParameterSupported -ParameterNames $policyParameterNames -ParameterName 'EnableSimilarDomainsSafetyTips'
                         supportsEnableSimilarUsersSafetyTips = Test-ParameterSupported -ParameterNames $policyParameterNames -ParameterName 'EnableSimilarUsersSafetyTips'
                         supportsEnableUnusualCharactersSafetyTips = Test-ParameterSupported -ParameterNames $policyParameterNames -ParameterName 'EnableUnusualCharactersSafetyTips'
                         supportsEnableTargetedDomainsProtection = Test-ParameterSupported -ParameterNames $policyParameterNames -ParameterName 'EnableTargetedDomainsProtection'
                         supportsTargetedDomainsToProtect = Test-ParameterSupported -ParameterNames $policyParameterNames -ParameterName 'TargetedDomainsToProtect'
                         supportsTargetedDomainProtectionAction = Test-ParameterSupported -ParameterNames $policyParameterNames -ParameterName 'TargetedDomainProtectionAction'
                         supportsEnableTargetedUserProtection = Test-ParameterSupported -ParameterNames $policyParameterNames -ParameterName 'EnableTargetedUserProtection'
                         supportsTargetedUsersToProtect = Test-ParameterSupported -ParameterNames $policyParameterNames -ParameterName 'TargetedUsersToProtect'
                         supportsTargetedUserProtectionAction = Test-ParameterSupported -ParameterNames $policyParameterNames -ParameterName 'TargetedUserProtectionAction'
                     }
                 }

                 function Get-MissingAntiPhishCapabilityDescriptions {
                     param(
                         [hashtable] $Capabilities,
                         [bool] $NeedsProtectedUserCoverage
                     )

                     $missing = New-Object System.Collections.Generic.List[string]

                     if (-not $Capabilities.supportsEnableMailboxIntelligence) {
                         $missing.Add('EnableMailboxIntelligence')
                     }

                     if (-not $Capabilities.supportsEnableMailboxIntelligenceProtection) {
                         $missing.Add('EnableMailboxIntelligenceProtection')
                     }

                     if (-not $Capabilities.supportsMailboxIntelligenceProtectionAction) {
                         $missing.Add('MailboxIntelligenceProtectionAction')
                     }

                     if (-not $Capabilities.supportsImpersonationProtectionState) {
                         $missing.Add('ImpersonationProtectionState')
                     }

                     if (-not $Capabilities.supportsEnableOrganizationDomainsProtection) {
                         $missing.Add('EnableOrganizationDomainsProtection')
                     }

                     if (-not $Capabilities.supportsPhishThresholdLevel) {
                         $missing.Add('PhishThresholdLevel')
                     }

                     if (-not $Capabilities.supportsEnableSimilarDomainsSafetyTips) {
                         $missing.Add('EnableSimilarDomainsSafetyTips')
                     }

                     if (-not $Capabilities.supportsEnableSimilarUsersSafetyTips) {
                         $missing.Add('EnableSimilarUsersSafetyTips')
                     }

                     if (-not $Capabilities.supportsEnableUnusualCharactersSafetyTips) {
                         $missing.Add('EnableUnusualCharactersSafetyTips')
                     }

                     if (-not $Capabilities.supportsEnableTargetedDomainsProtection) {
                         $missing.Add('EnableTargetedDomainsProtection')
                     }

                     if (-not $Capabilities.supportsTargetedDomainsToProtect) {
                         $missing.Add('TargetedDomainsToProtect')
                     }

                     if (-not $Capabilities.supportsTargetedDomainProtectionAction) {
                         $missing.Add('TargetedDomainProtectionAction')
                     }

                     if ($NeedsProtectedUserCoverage) {
                         if (-not $Capabilities.supportsEnableTargetedUserProtection) {
                             $missing.Add('EnableTargetedUserProtection')
                         }

                         if (-not $Capabilities.supportsTargetedUsersToProtect) {
                             $missing.Add('TargetedUsersToProtect')
                         }

                         if (-not $Capabilities.supportsTargetedUserProtectionAction) {
                             $missing.Add('TargetedUserProtectionAction')
                         }
                     }

                     return @($missing | Sort-Object -Unique)
                 }

                 function Ensure-OrganizationCustomizationEnabled {
                     $organizationConfig = Get-OrganizationConfig -ErrorAction Stop
                     if ($null -ne $organizationConfig -and [bool] $organizationConfig.IsDehydrated) {
                         Enable-OrganizationCustomization -ErrorAction Stop | Out-Null
                         Start-Sleep -Seconds 5
                         return $true
                     }

                     return $false
                 }

                 function Get-AntiPhishSnapshot {
                     param(
                         [string] $PolicyName,
                         [string] $RuleName
                     )

                     $policy = Get-FirstOrDefault -Items ((Get-AntiPhishPolicy -ErrorAction Stop) | Where-Object { $_.Name -eq $PolicyName })
                     $rule = Get-FirstOrDefault -Items ((Get-AntiPhishRule -ErrorAction Stop) | Where-Object { $_.Name -eq $RuleName })
                     $recipientDomains = Convert-ToStringArray -Values (Get-OptionalPropertyValue -InputObject $rule -PropertyName 'RecipientDomainIs')
                     $targetedDomains = Convert-ToStringArray -Values (Get-OptionalPropertyValue -InputObject $policy -PropertyName 'TargetedDomainsToProtect')
                     $targetedUsers = Convert-ToStringArray -Values (Get-OptionalPropertyValue -InputObject $policy -PropertyName 'TargetedUsersToProtect')
                     $state = [string] (Get-OptionalPropertyValue -InputObject $rule -PropertyName 'State')

                     return [ordered]@{
                         policyExists = $null -ne $policy
                         ruleExists = $null -ne $rule
                         policyName = if ($null -eq $policy) { $PolicyName } else { [string] $policy.Name }
                         ruleName = if ($null -eq $rule) { $RuleName } else { [string] $rule.Name }
                         ruleState = $state
                         enableMailboxIntelligence = if ($null -eq $policy) { $false } else { [bool] (Get-OptionalPropertyValue -InputObject $policy -PropertyName 'EnableMailboxIntelligence') }
                         enableMailboxIntelligenceProtection = if ($null -eq $policy) { $false } else { [bool] (Get-OptionalPropertyValue -InputObject $policy -PropertyName 'EnableMailboxIntelligenceProtection') }
                         mailboxIntelligenceProtectionAction = if ($null -eq $policy) { '' } else { [string] (Get-OptionalPropertyValue -InputObject $policy -PropertyName 'MailboxIntelligenceProtectionAction') }
                         impersonationProtectionState = if ($null -eq $policy) { '' } else { [string] (Get-OptionalPropertyValue -InputObject $policy -PropertyName 'ImpersonationProtectionState') }
                         enableOrganizationDomainsProtection = if ($null -eq $policy) { $false } else { [bool] (Get-OptionalPropertyValue -InputObject $policy -PropertyName 'EnableOrganizationDomainsProtection') }
                         enableTargetedDomainsProtection = if ($null -eq $policy) { $false } else { [bool] (Get-OptionalPropertyValue -InputObject $policy -PropertyName 'EnableTargetedDomainsProtection') }
                         targetedDomainProtectionAction = if ($null -eq $policy) { '' } else { [string] (Get-OptionalPropertyValue -InputObject $policy -PropertyName 'TargetedDomainProtectionAction') }
                         enableTargetedUserProtection = if ($null -eq $policy) { $false } else { [bool] (Get-OptionalPropertyValue -InputObject $policy -PropertyName 'EnableTargetedUserProtection') }
                         targetedUserProtectionAction = if ($null -eq $policy) { '' } else { [string] (Get-OptionalPropertyValue -InputObject $policy -PropertyName 'TargetedUserProtectionAction') }
                         enableSimilarDomainsSafetyTips = if ($null -eq $policy) { $false } else { [bool] (Get-OptionalPropertyValue -InputObject $policy -PropertyName 'EnableSimilarDomainsSafetyTips') }
                         enableSimilarUsersSafetyTips = if ($null -eq $policy) { $false } else { [bool] (Get-OptionalPropertyValue -InputObject $policy -PropertyName 'EnableSimilarUsersSafetyTips') }
                         enableUnusualCharactersSafetyTips = if ($null -eq $policy) { $false } else { [bool] (Get-OptionalPropertyValue -InputObject $policy -PropertyName 'EnableUnusualCharactersSafetyTips') }
                         phishThresholdLevel = if ($null -eq $policy) { 0 } else { [int] (Get-OptionalPropertyValue -InputObject $policy -PropertyName 'PhishThresholdLevel') }
                         recipientDomains = $recipientDomains
                         targetedDomains = $targetedDomains
                         targetedUsers = $targetedUsers
                     }
                 }

                 function Test-AntiPhishCompliance {
                     param(
                         [hashtable] $Snapshot,
                         [string[]] $AcceptedDomains,
                         [string[]] $ProtectedUsersToProtect,
                         [hashtable] $Capabilities
                     )

                     $canEvaluateTargetedDomainProtection =
                         $Capabilities.supportsEnableTargetedDomainsProtection -and
                         $Capabilities.supportsTargetedDomainsToProtect -and
                         $Capabilities.supportsTargetedDomainProtectionAction

                        $canEvaluateTargetedUserProtection =
                         @($ProtectedUsersToProtect).Count -gt 0 -and
                         $Capabilities.supportsEnableTargetedUserProtection -and
                         $Capabilities.supportsTargetedUsersToProtect -and
                         $Capabilities.supportsTargetedUserProtectionAction

                     $mailboxIntelligenceCompliant =
                         (-not $Capabilities.supportsEnableMailboxIntelligence -or $Snapshot.enableMailboxIntelligence -eq $true) -and
                         (-not $Capabilities.supportsEnableMailboxIntelligenceProtection -or $Snapshot.enableMailboxIntelligenceProtection -eq $true)

                     if ($Capabilities.supportsMailboxIntelligenceProtectionAction) {
                         $mailboxIntelligenceCompliant =
                             $mailboxIntelligenceCompliant -and
                             $Snapshot.mailboxIntelligenceProtectionAction -eq 'MoveToJmf'
                     }

                     $impersonationStateCompliant = if ($Capabilities.supportsImpersonationProtectionState) {
                         $Snapshot.impersonationProtectionState -eq 'Manual'
                     }
                     else {
                         $true
                     }

                     $organizationDomainsProtectionCompliant = -not $Capabilities.supportsEnableOrganizationDomainsProtection -or $Snapshot.enableOrganizationDomainsProtection -eq $true
                     $phishThresholdCompliant = -not $Capabilities.supportsPhishThresholdLevel -or $Snapshot.phishThresholdLevel -ge 3
                     $similarDomainsSafetyTipsCompliant = -not $Capabilities.supportsEnableSimilarDomainsSafetyTips -or $Snapshot.enableSimilarDomainsSafetyTips -eq $true
                     $similarUsersSafetyTipsCompliant = -not $Capabilities.supportsEnableSimilarUsersSafetyTips -or $Snapshot.enableSimilarUsersSafetyTips -eq $true
                     $unusualCharactersSafetyTipsCompliant = -not $Capabilities.supportsEnableUnusualCharactersSafetyTips -or $Snapshot.enableUnusualCharactersSafetyTips -eq $true

                     $domainProtectionCompliant =
                         $organizationDomainsProtectionCompliant -and
                         $similarDomainsSafetyTipsCompliant -and
                         $similarUsersSafetyTipsCompliant -and
                         $unusualCharactersSafetyTipsCompliant -and
                         $phishThresholdCompliant -and
                         (Test-StringArrayEquals -Left $Snapshot.recipientDomains -Right $AcceptedDomains)

                     if ($canEvaluateTargetedDomainProtection) {
                         $domainProtectionCompliant =
                             $domainProtectionCompliant -and
                             $Snapshot.enableTargetedDomainsProtection -eq $true -and
                             $Snapshot.targetedDomainProtectionAction -eq 'Quarantine' -and
                             (Test-StringArrayEquals -Left $Snapshot.targetedDomains -Right $AcceptedDomains)
                     }

                     $userProtectionCompliant = $true
                     if ($canEvaluateTargetedUserProtection) {
                         $userProtectionCompliant =
                             $Snapshot.enableTargetedUserProtection -eq $true -and
                             $Snapshot.targetedUserProtectionAction -eq 'Quarantine' -and
                             (Test-StringArrayEquals -Left $Snapshot.targetedUsers -Right $ProtectedUsersToProtect)
                     }

                     $baseCompliance =
                         $Snapshot.policyExists -and
                         $Snapshot.ruleExists -and
                         $mailboxIntelligenceCompliant -and
                         $impersonationStateCompliant -and
                         $domainProtectionCompliant -and
                         $userProtectionCompliant

                     if (-not $baseCompliance) {
                         return $false
                     }

                     return $true
                 }

                 function Find-Certificate {
                     param(
                         [string] $Thumbprint,
                         [string] $StoreLocationText,
                         [string] $StoreNameText
                     )

                     $storeLocation = [System.Security.Cryptography.X509Certificates.StoreLocation]::$StoreLocationText
                     $storeName = [System.Security.Cryptography.X509Certificates.StoreName]::$StoreNameText
                     $store = [System.Security.Cryptography.X509Certificates.X509Store]::new($storeName, $storeLocation)
                     $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)

                     try {
                         $certificate = $store.Certificates |
                             Where-Object { $_.Thumbprint -eq $Thumbprint } |
                             Sort-Object NotAfter -Descending |
                             Select-Object -First 1

                         if ($null -eq $certificate) {
                             throw "Automation certificate '$Thumbprint' was not found in $StoreLocationText\$StoreNameText."
                         }

                         if (-not $certificate.HasPrivateKey) {
                             throw "Automation certificate '$Thumbprint' does not have an accessible private key."
                         }

                         return $certificate
                     }
                     finally {
                         $store.Close()
                     }
                 }

                 $certificate = Find-Certificate `
                     -Thumbprint '{{EscapePowerShellSingleQuotedString(certificateThumbprint)}}' `
                     -StoreLocationText '{{EscapePowerShellSingleQuotedString(certificateStoreLocation)}}' `
                     -StoreNameText '{{EscapePowerShellSingleQuotedString(certificateStoreName)}}'

                 Import-Module ExchangeOnlineManagement -MinimumVersion 3.0.0 -ErrorAction Stop
                 Connect-ExchangeOnline `
                     -AppId '{{EscapePowerShellSingleQuotedString(clientId)}}' `
                     -Certificate $certificate `
                     -Organization '{{EscapePowerShellSingleQuotedString(tenantId)}}' `
                     -ShowBanner:$false `
                     -ShowProgress:$false `
                     -ErrorAction Stop | Out-Null

                 try {
                     try {
                         $organizationCustomizationEnabled = Ensure-OrganizationCustomizationEnabled
                         $antiPhishCapabilities = Get-AntiPhishCapabilities
                         $acceptedDomains = @(Get-AcceptedDomain -ErrorAction Stop |
                             ForEach-Object { [string] $_.DomainName } |
                             Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
                             Sort-Object -Unique)

                         if (@($acceptedDomains).Count -eq 0) {
                             throw 'Get-AcceptedDomain did not return any accepted domains for this tenant.'
                         }

                         $beforeAntiPhish = Get-AntiPhishSnapshot -PolicyName $antiPhishPolicyName -RuleName $antiPhishRuleName
                         $needsManualFollowUp = @($protectedUsersToProtect).Count -eq 0
                         $alreadyCompliant = Test-AntiPhishCompliance -Snapshot $beforeAntiPhish -AcceptedDomains $acceptedDomains -ProtectedUsersToProtect $protectedUsersToProtect -Capabilities $antiPhishCapabilities

                         $canApplyTargetedDomainProtection =
                             $antiPhishCapabilities.supportsEnableTargetedDomainsProtection -and
                             $antiPhishCapabilities.supportsTargetedDomainsToProtect -and
                             $antiPhishCapabilities.supportsTargetedDomainProtectionAction

                         $canApplyTargetedUserProtection =
                             @($protectedUsersToProtect).Count -gt 0 -and
                             $antiPhishCapabilities.supportsEnableTargetedUserProtection -and
                             $antiPhishCapabilities.supportsTargetedUsersToProtect -and
                             $antiPhishCapabilities.supportsTargetedUserProtectionAction

                         if (-not $alreadyCompliant) {
                             $policyParameters = @{
                                 ErrorAction = 'Stop'
                             }

                             if ($antiPhishCapabilities.supportsEnableMailboxIntelligence) {
                                 $policyParameters['EnableMailboxIntelligence'] = $true
                             }

                             if ($antiPhishCapabilities.supportsEnableMailboxIntelligenceProtection) {
                                 $policyParameters['EnableMailboxIntelligenceProtection'] = $true
                             }

                             if ($antiPhishCapabilities.supportsEnableOrganizationDomainsProtection) {
                                 $policyParameters['EnableOrganizationDomainsProtection'] = $true
                             }

                             if ($antiPhishCapabilities.supportsPhishThresholdLevel) {
                                 $policyParameters['PhishThresholdLevel'] = 3
                             }

                             if ($antiPhishCapabilities.supportsEnableSimilarDomainsSafetyTips) {
                                 $policyParameters['EnableSimilarDomainsSafetyTips'] = $true
                             }

                             if ($antiPhishCapabilities.supportsEnableSimilarUsersSafetyTips) {
                                 $policyParameters['EnableSimilarUsersSafetyTips'] = $true
                             }

                             if ($antiPhishCapabilities.supportsEnableUnusualCharactersSafetyTips) {
                                 $policyParameters['EnableUnusualCharactersSafetyTips'] = $true
                             }

                             if ($antiPhishCapabilities.supportsMailboxIntelligenceProtectionAction) {
                                 $policyParameters['MailboxIntelligenceProtectionAction'] = 'MoveToJmf'
                             }

                             if ($antiPhishCapabilities.supportsImpersonationProtectionState) {
                                 $policyParameters['ImpersonationProtectionState'] = 'Manual'
                             }

                             if ($canApplyTargetedDomainProtection) {
                                 $policyParameters['EnableTargetedDomainsProtection'] = $true
                                 $policyParameters['TargetedDomainsToProtect'] = $acceptedDomains
                                 $policyParameters['TargetedDomainProtectionAction'] = 'Quarantine'
                             }

                             if ($canApplyTargetedUserProtection) {
                                 $policyParameters['EnableTargetedUserProtection'] = $true
                                 $policyParameters['TargetedUsersToProtect'] = $protectedUsersToProtect
                                 $policyParameters['TargetedUserProtectionAction'] = 'Quarantine'
                             }

                             if ($beforeAntiPhish.policyExists) {
                                 $policyParameters['Identity'] = $antiPhishPolicyName
                                 Set-AntiPhishPolicy @policyParameters | Out-Null
                             }
                             else {
                                 $policyParameters['Name'] = $antiPhishPolicyName
                                 New-AntiPhishPolicy @policyParameters | Out-Null
                             }

                             if ($beforeAntiPhish.ruleExists) {
                                 Set-AntiPhishRule `
                                     -Identity $antiPhishRuleName `
                                     -RecipientDomainIs $acceptedDomains `
                                     -Priority 0 `
                                     -ErrorAction Stop | Out-Null

                                 if ($beforeAntiPhish.ruleState -ne 'Enabled') {
                                     Enable-AntiPhishRule -Identity $antiPhishRuleName -Confirm:$false -ErrorAction Stop | Out-Null
                                 }
                             }
                             else {
                                 New-AntiPhishRule `
                                     -Name $antiPhishRuleName `
                                     -AntiPhishPolicy $antiPhishPolicyName `
                                     -RecipientDomainIs $acceptedDomains `
                                     -Enabled $true `
                                     -Priority 0 `
                                     -ErrorAction Stop | Out-Null
                             }
                         }

                         $afterAntiPhish = Get-AntiPhishSnapshot -PolicyName $antiPhishPolicyName -RuleName $antiPhishRuleName
                         $notes = New-Object System.Collections.Generic.List[string]
                         $missingCapabilities = Get-MissingAntiPhishCapabilityDescriptions -Capabilities $antiPhishCapabilities -NeedsProtectedUserCoverage (@($protectedUsersToProtect).Count -gt 0)

                         if ($organizationCustomizationEnabled) {
                             $notes.Add('Exchange Online organization customization was enabled automatically before the anti-phish baseline was applied.')
                         }

                         if (@($missingCapabilities).Count -gt 0) {
                             $needsManualFollowUp = $true
                             $notes.Add("This Exchange session does not expose the full anti-phish parameter surface. Missing parameters: $($missingCapabilities -join ', '). Use a fuller Exchange Online PowerShell session or the Defender portal for the missing impersonation settings.")
                         }

                         if (@($protectedUsersToProtect).Count -eq 0) {
                             $needsManualFollowUp = $true
                             $notes.Add('Protected-user discovery did not return any privileged accounts to seed targeted user impersonation protection.')
                         }
                         elseif (-not $canApplyTargetedUserProtection -or -not $afterAntiPhish.enableTargetedUserProtection -or @($afterAntiPhish.targetedUsers).Count -eq 0) {
                             $needsManualFollowUp = $true
                             $notes.Add('Targeted user impersonation protection still needs operator review. This baseline hardened mailbox intelligence, recipient scope, and available impersonation controls, but the protected-user seed list was not fully applied in the current Exchange session.')
                         }

                         $notes.Add('Phishing ZAP remains covered through the Defender for Office spam baseline where PhishZapEnabled is managed.')

                         [ordered]@{
                             success = $true
                             alreadyCompliant = $alreadyCompliant
                             needsManualFollowUp = $needsManualFollowUp
                             antiPhish = $afterAntiPhish
                             notes = $notes
                         } | ConvertTo-Json -Depth 6 -Compress
                     }
                     catch {
                         [ordered]@{
                             success = $false
                             errorMessage = $_.Exception.Message
                         } | ConvertTo-Json -Depth 4 -Compress
                     }
                 }
                 finally {
                     Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
                 }
                 """;
    }

    private static string BuildApplyBaselineScript(
        string tenantId,
        string clientId,
        string certificateThumbprint,
        string certificateStoreLocation,
        string certificateStoreName)
    {
        return $$"""
                 $ErrorActionPreference = 'Stop'
                 $ProgressPreference = 'SilentlyContinue'
                 Set-StrictMode -Version Latest

                 $safeLinksPolicyName = '{{EscapePowerShellSingleQuotedString(SafeLinksPolicyName)}}'
                 $safeLinksRuleName = '{{EscapePowerShellSingleQuotedString(SafeLinksRuleName)}}'
                 $safeAttachmentPolicyName = '{{EscapePowerShellSingleQuotedString(SafeAttachmentPolicyName)}}'
                 $safeAttachmentRuleName = '{{EscapePowerShellSingleQuotedString(SafeAttachmentRuleName)}}'

                 if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
                     throw 'The ExchangeOnlineManagement PowerShell module is not installed on this host. Install it before queueing the Defender for Office baseline.'
                 }

                 function Get-FirstOrDefault {
                     param([object[]] $Items)

                     if ($null -eq $Items) {
                         return $null
                     }

                     return @($Items | Select-Object -First 1)[0]
                 }

                 function Convert-ToDomainArray {
                     param([object] $Values)

                     if ($null -eq $Values) {
                         return @()
                     }

                     return @($Values | ForEach-Object { [string] $_ } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
                 }

                 function Test-DomainArrayEquals {
                     param(
                         [string[]] $Left,
                         [string[]] $Right
                     )

                     $leftValue = (@($Left | Sort-Object -Unique) -join '|')
                     $rightValue = (@($Right | Sort-Object -Unique) -join '|')

                     return $leftValue -eq $rightValue
                 }

                 function Get-DefenderGlobalSnapshot {
                     $policy = Get-FirstOrDefault -Items (Get-AtpPolicyForO365 -ErrorAction Stop)

                     if ($null -eq $policy) {
                         throw 'Get-AtpPolicyForO365 did not return a Defender for Office policy.'
                     }

                     return [ordered]@{
                         enableAtpForSpoTeamsOdb = [bool] $policy.EnableATPForSPOTeamsODB
                         enableSafeDocs = if ($null -eq $policy.EnableSafeDocs) { $null } else { [bool] $policy.EnableSafeDocs }
                         allowSafeDocsOpen = if ($null -eq $policy.AllowSafeDocsOpen) { $null } else { [bool] $policy.AllowSafeDocsOpen }
                     }
                 }

                 function Ensure-OrganizationCustomizationEnabled {
                     $organizationConfig = Get-OrganizationConfig -ErrorAction Stop
                     if ($null -ne $organizationConfig -and [bool] $organizationConfig.IsDehydrated) {
                         Enable-OrganizationCustomization -ErrorAction Stop | Out-Null
                         Start-Sleep -Seconds 5
                         return $true
                     }

                     return $false
                 }

                 function Get-SafeLinksSnapshot {
                     param(
                         [string] $PolicyName,
                         [string] $RuleName
                     )

                     $policy = Get-FirstOrDefault -Items ((Get-SafeLinksPolicy -ErrorAction Stop) | Where-Object { $_.Name -eq $PolicyName })
                     $rule = Get-FirstOrDefault -Items ((Get-SafeLinksRule -ErrorAction Stop) | Where-Object { $_.Name -eq $RuleName })
                     $domains = Convert-ToDomainArray -Values ($rule | ForEach-Object { $_.RecipientDomainIs })

                     return [ordered]@{
                         policyExists = $null -ne $policy
                         ruleExists = $null -ne $rule
                         policyName = if ($null -eq $policy) { $PolicyName } else { [string] $policy.Name }
                         ruleName = if ($null -eq $rule) { $RuleName } else { [string] $rule.Name }
                         enableSafeLinksForEmail = if ($null -eq $policy) { $false } else { [bool] $policy.EnableSafeLinksForEmail }
                         enableSafeLinksForTeams = if ($null -eq $policy) { $false } else { [bool] $policy.EnableSafeLinksForTeams }
                         enableSafeLinksForOffice = if ($null -eq $policy) { $false } else { [bool] $policy.EnableSafeLinksForOffice }
                         trackClicks = if ($null -eq $policy) { $false } else { [bool] $policy.TrackClicks }
                         allowClickThrough = if ($null -eq $policy) { $false } else { [bool] $policy.AllowClickThrough }
                         scanUrls = if ($null -eq $policy) { $false } else { [bool] $policy.ScanUrls }
                         enableForInternalSenders = if ($null -eq $policy) { $false } else { [bool] $policy.EnableForInternalSenders }
                         deliverMessageAfterScan = if ($null -eq $policy) { $false } else { [bool] $policy.DeliverMessageAfterScan }
                         disableUrlRewrite = if ($null -eq $policy) { $false } else { [bool] $policy.DisableUrlRewrite }
                         recipientDomains = $domains
                     }
                 }

                 function Get-SafeAttachmentSnapshot {
                     param(
                         [string] $PolicyName,
                         [string] $RuleName
                     )

                     $policy = Get-FirstOrDefault -Items ((Get-SafeAttachmentPolicy -ErrorAction Stop) | Where-Object { $_.Name -eq $PolicyName })
                     $rule = Get-FirstOrDefault -Items ((Get-SafeAttachmentRule -ErrorAction Stop) | Where-Object { $_.Name -eq $RuleName })
                     $domains = Convert-ToDomainArray -Values ($rule | ForEach-Object { $_.RecipientDomainIs })

                     return [ordered]@{
                         policyExists = $null -ne $policy
                         ruleExists = $null -ne $rule
                         policyName = if ($null -eq $policy) { $PolicyName } else { [string] $policy.Name }
                         ruleName = if ($null -eq $rule) { $RuleName } else { [string] $rule.Name }
                         enable = if ($null -eq $policy) { $false } else { [bool] $policy.Enable }
                         action = if ($null -eq $policy) { '' } else { [string] $policy.Action }
                         redirect = if ($null -eq $policy) { $false } else { [bool] $policy.Redirect }
                         recipientDomains = $domains
                     }
                 }

                 function Test-SafeLinksCompliance {
                     param(
                         [hashtable] $Snapshot,
                         [string[]] $AcceptedDomains
                     )

                     return
                         $Snapshot.policyExists -and
                         $Snapshot.ruleExists -and
                         $Snapshot.enableSafeLinksForEmail -eq $true -and
                         $Snapshot.enableSafeLinksForTeams -eq $true -and
                         $Snapshot.enableSafeLinksForOffice -eq $true -and
                         $Snapshot.trackClicks -eq $true -and
                         $Snapshot.allowClickThrough -eq $false -and
                         $Snapshot.scanUrls -eq $true -and
                         $Snapshot.enableForInternalSenders -eq $true -and
                         $Snapshot.deliverMessageAfterScan -eq $true -and
                         $Snapshot.disableUrlRewrite -eq $false -and
                         (Test-DomainArrayEquals -Left $Snapshot.recipientDomains -Right $AcceptedDomains)
                 }

                 function Test-SafeAttachmentCompliance {
                     param(
                         [hashtable] $Snapshot,
                         [string[]] $AcceptedDomains
                     )

                     return
                         $Snapshot.policyExists -and
                         $Snapshot.ruleExists -and
                         $Snapshot.enable -eq $true -and
                         $Snapshot.action -eq 'Block' -and
                         $Snapshot.redirect -eq $false -and
                         (Test-DomainArrayEquals -Left $Snapshot.recipientDomains -Right $AcceptedDomains)
                 }

                 function Find-Certificate {
                     param(
                         [string] $Thumbprint,
                         [string] $StoreLocationText,
                         [string] $StoreNameText
                     )

                     $storeLocation = [System.Security.Cryptography.X509Certificates.StoreLocation]::$StoreLocationText
                     $storeName = [System.Security.Cryptography.X509Certificates.StoreName]::$StoreNameText
                     $store = [System.Security.Cryptography.X509Certificates.X509Store]::new($storeName, $storeLocation)
                     $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)

                     try {
                         $certificate = $store.Certificates |
                             Where-Object { $_.Thumbprint -eq $Thumbprint } |
                             Sort-Object NotAfter -Descending |
                             Select-Object -First 1

                         if ($null -eq $certificate) {
                             throw "Automation certificate '$Thumbprint' was not found in $StoreLocationText\$StoreNameText."
                         }

                         if (-not $certificate.HasPrivateKey) {
                             throw "Automation certificate '$Thumbprint' does not have an accessible private key."
                         }

                         return $certificate
                     }
                     finally {
                         $store.Close()
                     }
                 }

                 $certificate = Find-Certificate `
                     -Thumbprint '{{EscapePowerShellSingleQuotedString(certificateThumbprint)}}' `
                     -StoreLocationText '{{EscapePowerShellSingleQuotedString(certificateStoreLocation)}}' `
                     -StoreNameText '{{EscapePowerShellSingleQuotedString(certificateStoreName)}}'

                 Import-Module ExchangeOnlineManagement -MinimumVersion 3.0.0 -ErrorAction Stop
                 Connect-ExchangeOnline `
                     -AppId '{{EscapePowerShellSingleQuotedString(clientId)}}' `
                     -Certificate $certificate `
                     -Organization '{{EscapePowerShellSingleQuotedString(tenantId)}}' `
                     -ShowBanner:$false `
                     -ShowProgress:$false `
                     -ErrorAction Stop | Out-Null

                 try {
                     try {
                         $organizationCustomizationEnabled = Ensure-OrganizationCustomizationEnabled
                         $acceptedDomains = @(Get-AcceptedDomain -ErrorAction Stop |
                             ForEach-Object { [string] $_.DomainName } |
                             Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
                             Sort-Object -Unique)

                         if (@($acceptedDomains).Count -eq 0) {
                             throw 'Get-AcceptedDomain did not return any accepted domains for this tenant.'
                         }

                         $beforeGlobal = Get-DefenderGlobalSnapshot
                         $beforeSafeLinks = Get-SafeLinksSnapshot -PolicyName $safeLinksPolicyName -RuleName $safeLinksRuleName
                         $beforeSafeAttachments = Get-SafeAttachmentSnapshot -PolicyName $safeAttachmentPolicyName -RuleName $safeAttachmentRuleName

                         $alreadyCompliant =
                             $beforeGlobal.enableAtpForSpoTeamsOdb -eq $true -and
                             (Test-SafeLinksCompliance -Snapshot $beforeSafeLinks -AcceptedDomains $acceptedDomains) -and
                             (Test-SafeAttachmentCompliance -Snapshot $beforeSafeAttachments -AcceptedDomains $acceptedDomains)

                         if (-not $alreadyCompliant) {
                             Set-AtpPolicyForO365 -EnableATPForSPOTeamsODB $true -ErrorAction Stop | Out-Null

                             if ($beforeSafeLinks.policyExists) {
                                 Set-SafeLinksPolicy `
                                     -Identity $safeLinksPolicyName `
                                     -EnableSafeLinksForEmail $true `
                                     -EnableSafeLinksForTeams $true `
                                     -EnableSafeLinksForOffice $true `
                                     -TrackClicks $true `
                                     -AllowClickThrough $false `
                                     -ScanUrls $true `
                                     -EnableForInternalSenders $true `
                                     -DeliverMessageAfterScan $true `
                                     -DisableUrlRewrite $false `
                                     -ErrorAction Stop | Out-Null
                             }
                             else {
                                 New-SafeLinksPolicy `
                                     -Name $safeLinksPolicyName `
                                     -EnableSafeLinksForEmail $true `
                                     -EnableSafeLinksForTeams $true `
                                     -EnableSafeLinksForOffice $true `
                                     -TrackClicks $true `
                                     -AllowClickThrough $false `
                                     -ScanUrls $true `
                                     -EnableForInternalSenders $true `
                                     -DeliverMessageAfterScan $true `
                                     -DisableUrlRewrite $false `
                                     -ErrorAction Stop | Out-Null
                             }

                             if ($beforeSafeLinks.ruleExists) {
                                 Set-SafeLinksRule `
                                     -Identity $safeLinksRuleName `
                                     -RecipientDomainIs $acceptedDomains `
                                     -Enabled $true `
                                     -ErrorAction Stop | Out-Null
                             }
                             else {
                                 New-SafeLinksRule `
                                     -Name $safeLinksRuleName `
                                     -SafeLinksPolicy $safeLinksPolicyName `
                                     -RecipientDomainIs $acceptedDomains `
                                     -Enabled $true `
                                     -Priority 0 `
                                     -ErrorAction Stop | Out-Null
                             }

                             if ($beforeSafeAttachments.policyExists) {
                                 Set-SafeAttachmentPolicy `
                                     -Identity $safeAttachmentPolicyName `
                                     -Enable $true `
                                     -Action Block `
                                     -Redirect $false `
                                     -ErrorAction Stop | Out-Null
                             }
                             else {
                                 New-SafeAttachmentPolicy `
                                     -Name $safeAttachmentPolicyName `
                                     -Enable $true `
                                     -Action Block `
                                     -Redirect $false `
                                     -ErrorAction Stop | Out-Null
                             }

                             if ($beforeSafeAttachments.ruleExists) {
                                 Set-SafeAttachmentRule `
                                     -Identity $safeAttachmentRuleName `
                                     -RecipientDomainIs $acceptedDomains `
                                     -Enabled $true `
                                     -ErrorAction Stop | Out-Null
                             }
                             else {
                                 New-SafeAttachmentRule `
                                     -Name $safeAttachmentRuleName `
                                     -SafeAttachmentPolicy $safeAttachmentPolicyName `
                                     -RecipientDomainIs $acceptedDomains `
                                     -Enabled $true `
                                     -Priority 0 `
                                     -ErrorAction Stop | Out-Null
                             }
                         }

                         $afterGlobal = Get-DefenderGlobalSnapshot
                         $afterSafeLinks = Get-SafeLinksSnapshot -PolicyName $safeLinksPolicyName -RuleName $safeLinksRuleName
                         $afterSafeAttachments = Get-SafeAttachmentSnapshot -PolicyName $safeAttachmentPolicyName -RuleName $safeAttachmentRuleName

                         [ordered]@{
                             success = $true
                             alreadyCompliant = $alreadyCompliant
                             globalProtection = $afterGlobal
                             safeLinks = $afterSafeLinks
                             safeAttachments = $afterSafeAttachments
                             notes = @(
                                 if ($organizationCustomizationEnabled) { 'Exchange Online organization customization was enabled automatically before the baseline was applied.' }
                                 'Safe Documents was not modified in this Business Premium baseline. Current Microsoft guidance lists Safe Documents under Microsoft 365 A5/E5/G5 or Microsoft Defender Suite, not Defender for Office 365 Plan 1/2.'
                             )
                         } | ConvertTo-Json -Depth 6 -Compress
                     }
                     catch {
                         [ordered]@{
                             success = $false
                             errorMessage = $_.Exception.Message
                         } | ConvertTo-Json -Depth 4 -Compress
                     }
                 }
                 finally {
                     Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
                 }
                 """;
    }

    private static string BuildApplyExchangeCollaborationMailboxBaselineScript(
        string tenantId,
        string clientId,
        string certificateThumbprint,
        string certificateStoreLocation,
        string certificateStoreName)
    {
        return $$"""
                 $ErrorActionPreference = 'Stop'
                 $ProgressPreference = 'SilentlyContinue'
                 Set-StrictMode -Version Latest

                 if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
                     throw 'The ExchangeOnlineManagement PowerShell module is not installed on this host. Install it before queueing the Exchange collaboration baseline.'
                 }

                 function Get-FirstOrDefault {
                     param([object[]] $Items)

                     if ($null -eq $Items) {
                         return $null
                     }

                     return @($Items | Select-Object -First 1)[0]
                 }

                 function Get-OptionalPropertyValue {
                     param(
                         [object] $InputObject,
                         [string] $PropertyName
                     )

                     if ($null -eq $InputObject) {
                         return $null
                     }

                     $property = $InputObject.PSObject.Properties[$PropertyName]
                     if ($null -eq $property) {
                         return $null
                     }

                     return $property.Value
                 }

                 function Convert-ToStringArray {
                     param([object] $Values)

                     if ($null -eq $Values) {
                         return @()
                     }

                     return @($Values | ForEach-Object { [string] $_ } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
                 }

                 function Ensure-OrganizationCustomizationEnabled {
                     $organizationConfig = Get-OrganizationConfig -ErrorAction Stop
                     if ($null -ne $organizationConfig -and [bool] $organizationConfig.IsDehydrated) {
                         Enable-OrganizationCustomization -ErrorAction Stop | Out-Null
                         Start-Sleep -Seconds 5
                         return $true
                     }

                     return $false
                 }

                 function Get-DefaultOwaMailboxPolicy {
                     $defaultPolicy = Get-FirstOrDefault -Items ((Get-OwaMailboxPolicy -ErrorAction Stop) | Where-Object { [bool] (Get-OptionalPropertyValue -InputObject $_ -PropertyName 'IsDefault') })
                     if ($null -ne $defaultPolicy) {
                         return $defaultPolicy
                     }

                     return Get-FirstOrDefault -Items (Get-OwaMailboxPolicy -ErrorAction Stop)
                 }

                 function Get-DefaultSharingPolicy {
                     $defaultPolicy = Get-FirstOrDefault -Items ((Get-SharingPolicy -ErrorAction Stop) | Where-Object { [bool] (Get-OptionalPropertyValue -InputObject $_ -PropertyName 'Default') -or [bool] (Get-OptionalPropertyValue -InputObject $_ -PropertyName 'IsDefault') })
                     if ($null -ne $defaultPolicy) {
                         return $defaultPolicy
                     }

                     return Get-FirstOrDefault -Items (Get-SharingPolicy -ErrorAction Stop)
                 }

                 function Get-OrganizationSnapshot {
                     $organizationConfig = Get-OrganizationConfig -ErrorAction Stop

                     return [ordered]@{
                         auditDisabled = [bool] (Get-OptionalPropertyValue -InputObject $organizationConfig -PropertyName 'AuditDisabled')
                         mailTipsAllTipsEnabled = [bool] (Get-OptionalPropertyValue -InputObject $organizationConfig -PropertyName 'MailTipsAllTipsEnabled')
                         appsForOfficeEnabled = [bool] (Get-OptionalPropertyValue -InputObject $organizationConfig -PropertyName 'AppsForOfficeEnabled')
                         oAuth2ClientProfileEnabled = [bool] (Get-OptionalPropertyValue -InputObject $organizationConfig -PropertyName 'OAuth2ClientProfileEnabled')
                     }
                 }

                 function Get-OwaSnapshot {
                     $owaPolicy = Get-DefaultOwaMailboxPolicy
                     $isDefault = if ($null -eq $owaPolicy) { $false } else { [bool] (Get-OptionalPropertyValue -InputObject $owaPolicy -PropertyName 'IsDefault') }

                     return [ordered]@{
                         policyExists = $null -ne $owaPolicy
                         identity = if ($null -eq $owaPolicy) { '{{EscapePowerShellSingleQuotedString(ExchangeMailboxBaselineName)}}' } else { [string] $owaPolicy.Identity }
                         name = if ($null -eq $owaPolicy) { '' } else { [string] $owaPolicy.Name }
                         isDefault = $isDefault
                         additionalStorageProvidersAvailable = if ($null -eq $owaPolicy) { $true } else { [bool] (Get-OptionalPropertyValue -InputObject $owaPolicy -PropertyName 'AdditionalStorageProvidersAvailable') }
                     }
                 }

                 function Get-SharingSnapshot {
                     $sharingPolicy = Get-DefaultSharingPolicy
                     $domains = Convert-ToStringArray -Values (Get-OptionalPropertyValue -InputObject $sharingPolicy -PropertyName 'Domains')
                     $hasAnonymousCalendarSharing = @($domains | Where-Object { $_ -like 'Anonymous:*' }).Count -gt 0

                     return [ordered]@{
                         policyExists = $null -ne $sharingPolicy
                         identity = if ($null -eq $sharingPolicy) { '' } else { [string] $sharingPolicy.Identity }
                         name = if ($null -eq $sharingPolicy) { '' } else { [string] $sharingPolicy.Name }
                         domains = $domains
                         hasAnonymousCalendarSharing = $hasAnonymousCalendarSharing
                     }
                 }

                 function Test-ExchangeMailboxBaselineCompliance {
                     param(
                         [hashtable] $OrganizationSnapshot,
                         [hashtable] $OwaSnapshot
                     )

                     return (
                         $OrganizationSnapshot.auditDisabled -eq $false -and
                         $OrganizationSnapshot.mailTipsAllTipsEnabled -eq $true -and
                         $OrganizationSnapshot.appsForOfficeEnabled -eq $false -and
                         $OrganizationSnapshot.oAuth2ClientProfileEnabled -eq $true -and
                         $OwaSnapshot.policyExists -and
                         $OwaSnapshot.additionalStorageProvidersAvailable -eq $false
                     )
                 }

                 function Find-Certificate {
                     param(
                         [string] $Thumbprint,
                         [string] $StoreLocationText,
                         [string] $StoreNameText
                     )

                     $storeLocation = [System.Security.Cryptography.X509Certificates.StoreLocation]::$StoreLocationText
                     $storeName = [System.Security.Cryptography.X509Certificates.StoreName]::$StoreNameText
                     $store = [System.Security.Cryptography.X509Certificates.X509Store]::new($storeName, $storeLocation)
                     $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)

                     try {
                         $certificate = $store.Certificates |
                             Where-Object { $_.Thumbprint -eq $Thumbprint } |
                             Sort-Object NotAfter -Descending |
                             Select-Object -First 1

                         if ($null -eq $certificate) {
                             throw "Automation certificate '$Thumbprint' was not found in $StoreLocationText\$StoreNameText."
                         }

                         if (-not $certificate.HasPrivateKey) {
                             throw "Automation certificate '$Thumbprint' does not have an accessible private key."
                         }

                         return $certificate
                     }
                     finally {
                         $store.Close()
                     }
                 }

                 $certificate = Find-Certificate `
                     -Thumbprint '{{EscapePowerShellSingleQuotedString(certificateThumbprint)}}' `
                     -StoreLocationText '{{EscapePowerShellSingleQuotedString(certificateStoreLocation)}}' `
                     -StoreNameText '{{EscapePowerShellSingleQuotedString(certificateStoreName)}}'

                 Import-Module ExchangeOnlineManagement -MinimumVersion 3.0.0 -ErrorAction Stop
                 Connect-ExchangeOnline `
                     -AppId '{{EscapePowerShellSingleQuotedString(clientId)}}' `
                     -Certificate $certificate `
                     -Organization '{{EscapePowerShellSingleQuotedString(tenantId)}}' `
                     -ShowBanner:$false `
                     -ShowProgress:$false `
                     -ErrorAction Stop | Out-Null

                 try {
                     try {
                         $organizationCustomizationEnabled = Ensure-OrganizationCustomizationEnabled

                         $beforeOrganization = Get-OrganizationSnapshot
                         $beforeOwa = Get-OwaSnapshot
                         $beforeSharing = Get-SharingSnapshot

                         $alreadyCompliant = Test-ExchangeMailboxBaselineCompliance -OrganizationSnapshot $beforeOrganization -OwaSnapshot $beforeOwa

                         if (-not $alreadyCompliant) {
                             Set-OrganizationConfig `
                                 -AuditDisabled $false `
                                 -MailTipsAllTipsEnabled $true `
                                 -AppsForOfficeEnabled $false `
                                 -OAuth2ClientProfileEnabled $true `
                                 -ErrorAction Stop | Out-Null

                             if ($beforeOwa.policyExists) {
                                 Set-OwaMailboxPolicy `
                                     -Identity $beforeOwa.identity `
                                     -AdditionalStorageProvidersAvailable $false `
                                     -ErrorAction Stop | Out-Null
                             }
                         }

                         $afterOrganization = Get-OrganizationSnapshot
                         $afterOwa = Get-OwaSnapshot
                         $afterSharing = Get-SharingSnapshot

                         $notes = New-Object System.Collections.Generic.List[string]
                         if ($organizationCustomizationEnabled) {
                             $notes.Add('Exchange Online organization customization was enabled automatically before the baseline was applied.')
                         }

                         $needsManualFollowUp = $false

                         if (-not $afterSharing.policyExists) {
                             $needsManualFollowUp = $true
                             $notes.Add('No default sharing policy was detected for Exchange calendar sharing review.')
                         }
                         elseif ($afterSharing.hasAnonymousCalendarSharing) {
                             $needsManualFollowUp = $true
                             $notes.Add('The default sharing policy still allows Anonymous calendar sharing. Securityzator did not remove sharing domains automatically in this slice.')
                         }
                         elseif ($afterSharing.domains.Count -gt 0) {
                             $needsManualFollowUp = $true
                             $notes.Add('The default sharing policy still contains external sharing entries. Review whether broader calendar sharing should remain available.')
                         }

                         $notes.Add('Customer Lockbox remains a licensing-dependent control and was not changed by this Business Premium baseline.')

                         [ordered]@{
                             success = $true
                             alreadyCompliant = $alreadyCompliant
                             needsManualFollowUp = $needsManualFollowUp
                             organization = $afterOrganization
                             owaMailboxPolicy = $afterOwa
                             sharingPolicy = $afterSharing
                             notes = $notes
                         } | ConvertTo-Json -Depth 6 -Compress
                     }
                     catch {
                         [ordered]@{
                             success = $false
                             errorMessage = $_.Exception.Message
                         } | ConvertTo-Json -Depth 4 -Compress
                     }
                 }
                 finally {
                     Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
                 }
                 """;
    }

    private static string BuildApplySpamAndForwardingBaselineScript(
        string tenantId,
        string clientId,
        string certificateThumbprint,
        string certificateStoreLocation,
        string certificateStoreName)
    {
        return $$"""
                 $ErrorActionPreference = 'Stop'
                 $ProgressPreference = 'SilentlyContinue'
                 Set-StrictMode -Version Latest

                 $spamFilterPolicyName = '{{EscapePowerShellSingleQuotedString(SpamFilterPolicyName)}}'
                 $spamFilterRuleName = '{{EscapePowerShellSingleQuotedString(SpamFilterRuleName)}}'
                 $outboundSpamPolicyName = '{{EscapePowerShellSingleQuotedString(OutboundSpamFilterPolicyName)}}'
                 $outboundSpamRuleName = '{{EscapePowerShellSingleQuotedString(OutboundSpamFilterRuleName)}}'

                 if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
                     throw 'The ExchangeOnlineManagement PowerShell module is not installed on this host. Install it before queueing the Defender for Office spam and forwarding baseline.'
                 }

                 function Get-FirstOrDefault {
                     param([object[]] $Items)

                     if ($null -eq $Items) {
                         return $null
                     }

                     return @($Items | Select-Object -First 1)[0]
                 }

                 function Convert-ToStringArray {
                     param([object] $Values)

                     if ($null -eq $Values) {
                         return @()
                     }

                     return @($Values | ForEach-Object { [string] $_ } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
                 }

                 function Test-StringArrayEquals {
                     param(
                         [string[]] $Left,
                         [string[]] $Right
                     )

                     $leftValue = (@($Left | Sort-Object -Unique) -join '|')
                     $rightValue = (@($Right | Sort-Object -Unique) -join '|')

                     return $leftValue -eq $rightValue
                 }

                 function Test-AutoForwardingModeCompliant {
                     param([string] $Value)

                     return $Value -eq 'Automatic' -or $Value -eq 'Off'
                 }

                 function Ensure-OrganizationCustomizationEnabled {
                     $organizationConfig = Get-OrganizationConfig -ErrorAction Stop
                     if ($null -ne $organizationConfig -and [bool] $organizationConfig.IsDehydrated) {
                         Enable-OrganizationCustomization -ErrorAction Stop | Out-Null
                         Start-Sleep -Seconds 5
                         return $true
                     }

                     return $false
                 }

                 function Get-OptionalPropertyValue {
                     param(
                         [object] $InputObject,
                         [string] $PropertyName
                     )

                     if ($null -eq $InputObject) {
                         return $null
                     }

                     $property = $InputObject.PSObject.Properties[$PropertyName]
                     if ($null -eq $property) {
                         return $null
                     }

                     return $property.Value
                 }

                 function Get-InboundSpamSnapshot {
                     param(
                         [string] $PolicyName,
                         [string] $RuleName
                     )

                     $policy = Get-FirstOrDefault -Items ((Get-HostedContentFilterPolicy -ErrorAction Stop) | Where-Object { $_.Name -eq $PolicyName })
                     $rule = Get-FirstOrDefault -Items ((Get-HostedContentFilterRule -ErrorAction Stop) | Where-Object { $_.Name -eq $RuleName })
                     $allowedSenderDomains = Convert-ToStringArray -Values (Get-OptionalPropertyValue -InputObject $policy -PropertyName 'AllowedSenderDomains')
                     $recipientDomains = Convert-ToStringArray -Values (Get-OptionalPropertyValue -InputObject $rule -PropertyName 'RecipientDomainIs')

                     return [ordered]@{
                         policyExists = $null -ne $policy
                         ruleExists = $null -ne $rule
                         policyName = if ($null -eq $policy) { $PolicyName } else { [string] $policy.Name }
                         ruleName = if ($null -eq $rule) { $RuleName } else { [string] $rule.Name }
                         spamAction = if ($null -eq $policy) { '' } else { [string] (Get-OptionalPropertyValue -InputObject $policy -PropertyName 'SpamAction') }
                         highConfidenceSpamAction = if ($null -eq $policy) { '' } else { [string] (Get-OptionalPropertyValue -InputObject $policy -PropertyName 'HighConfidenceSpamAction') }
                         phishSpamAction = if ($null -eq $policy) { '' } else { [string] (Get-OptionalPropertyValue -InputObject $policy -PropertyName 'PhishSpamAction') }
                         highConfidencePhishAction = if ($null -eq $policy) { '' } else { [string] (Get-OptionalPropertyValue -InputObject $policy -PropertyName 'HighConfidencePhishAction') }
                         bulkSpamAction = if ($null -eq $policy) { '' } else { [string] (Get-OptionalPropertyValue -InputObject $policy -PropertyName 'BulkSpamAction') }
                         bulkThreshold = if ($null -eq $policy) { 0 } else { [int] (Get-OptionalPropertyValue -InputObject $policy -PropertyName 'BulkThreshold') }
                         quarantineRetentionPeriod = if ($null -eq $policy) { 0 } else { [int] (Get-OptionalPropertyValue -InputObject $policy -PropertyName 'QuarantineRetentionPeriod') }
                         spamZapEnabled = if ($null -eq $policy) { $false } else { [bool] (Get-OptionalPropertyValue -InputObject $policy -PropertyName 'SpamZapEnabled') }
                         phishZapEnabled = if ($null -eq $policy) { $false } else { [bool] (Get-OptionalPropertyValue -InputObject $policy -PropertyName 'PhishZapEnabled') }
                         allowedSenderDomains = $allowedSenderDomains
                         recipientDomains = $recipientDomains
                     }
                 }

                 function Get-OutboundSpamSnapshot {
                     param(
                         [string] $PolicyName,
                         [string] $RuleName
                     )

                     $policy = Get-FirstOrDefault -Items ((Get-HostedOutboundSpamFilterPolicy -ErrorAction Stop) | Where-Object { $_.Name -eq $PolicyName })
                     $rule = Get-FirstOrDefault -Items ((Get-HostedOutboundSpamFilterRule -ErrorAction Stop) | Where-Object { $_.Name -eq $RuleName })
                     $senderDomains = Convert-ToStringArray -Values (Get-OptionalPropertyValue -InputObject $rule -PropertyName 'SenderDomainIs')

                     return [ordered]@{
                         policyExists = $null -ne $policy
                         ruleExists = $null -ne $rule
                         policyName = if ($null -eq $policy) { $PolicyName } else { [string] $policy.Name }
                         ruleName = if ($null -eq $rule) { $RuleName } else { [string] $rule.Name }
                         autoForwardingMode = if ($null -eq $policy) { '' } else { [string] (Get-OptionalPropertyValue -InputObject $policy -PropertyName 'AutoForwardingMode') }
                         notifyOutboundSpam = if ($null -eq $policy) { $false } else { [bool] (Get-OptionalPropertyValue -InputObject $policy -PropertyName 'NotifyOutboundSpam') }
                         recipientLimitExternalPerHour = if ($null -eq $policy) { 0 } else { [uint32] (Get-OptionalPropertyValue -InputObject $policy -PropertyName 'RecipientLimitExternalPerHour') }
                         recipientLimitInternalPerHour = if ($null -eq $policy) { 0 } else { [uint32] (Get-OptionalPropertyValue -InputObject $policy -PropertyName 'RecipientLimitInternalPerHour') }
                         recipientLimitPerDay = if ($null -eq $policy) { 0 } else { [uint32] (Get-OptionalPropertyValue -InputObject $policy -PropertyName 'RecipientLimitPerDay') }
                         actionWhenThresholdReached = if ($null -eq $policy) { '' } else { [string] (Get-OptionalPropertyValue -InputObject $policy -PropertyName 'ActionWhenThresholdReached') }
                         senderDomains = $senderDomains
                     }
                 }

                 function Get-ConnectionFilterSnapshot {
                     try {
                         $policy = $null

                         try {
                             $policy = Get-HostedConnectionFilterPolicy -Identity 'Default' -ErrorAction Stop
                         }
                         catch {
                             $policy = Get-FirstOrDefault -Items (Get-HostedConnectionFilterPolicy -ErrorAction Stop)
                         }

                         $ipAllowList = Convert-ToStringArray -Values ($policy | ForEach-Object { $_.IPAllowList })

                         return [ordered]@{
                             policyExists = $null -ne $policy
                             policyName = if ($null -eq $policy) { 'Default' } else { [string] $policy.Name }
                             ipAllowList = $ipAllowList
                             readbackError = ''
                         }
                     }
                     catch {
                         return [ordered]@{
                             policyExists = $false
                             policyName = 'Unavailable'
                             ipAllowList = @()
                             readbackError = [string] $_.Exception.Message
                         }
                     }
                 }

                 function Test-InboundSpamCompliance {
                     param(
                         [hashtable] $Snapshot,
                         [string[]] $AcceptedDomains
                     )

                     return
                         $Snapshot.policyExists -and
                         $Snapshot.ruleExists -and
                         $Snapshot.spamAction -eq 'Quarantine' -and
                         $Snapshot.highConfidenceSpamAction -eq 'Quarantine' -and
                         $Snapshot.phishSpamAction -eq 'Quarantine' -and
                         $Snapshot.highConfidencePhishAction -eq 'Quarantine' -and
                         $Snapshot.bulkSpamAction -eq 'Quarantine' -and
                         $Snapshot.bulkThreshold -gt 0 -and
                         $Snapshot.bulkThreshold -le 6 -and
                         $Snapshot.quarantineRetentionPeriod -eq 30 -and
                         $Snapshot.spamZapEnabled -eq $true -and
                         $Snapshot.phishZapEnabled -eq $true -and
                         @($Snapshot.allowedSenderDomains).Count -eq 0 -and
                         (Test-StringArrayEquals -Left $Snapshot.recipientDomains -Right $AcceptedDomains)
                 }

                 function Test-OutboundSpamCompliance {
                     param(
                         [hashtable] $Snapshot,
                         [string[]] $AcceptedDomains
                     )

                     return
                         $Snapshot.policyExists -and
                         $Snapshot.ruleExists -and
                         (Test-AutoForwardingModeCompliant -Value $Snapshot.autoForwardingMode) -and
                         $Snapshot.notifyOutboundSpam -eq $false -and
                         $Snapshot.recipientLimitExternalPerHour -eq {{OutboundExternalRecipientLimit}} -and
                         $Snapshot.recipientLimitInternalPerHour -eq {{OutboundInternalRecipientLimit}} -and
                         $Snapshot.recipientLimitPerDay -eq {{OutboundDailyRecipientLimit}} -and
                         $Snapshot.actionWhenThresholdReached -eq 'BlockUserForToday' -and
                         (Test-StringArrayEquals -Left $Snapshot.senderDomains -Right $AcceptedDomains)
                 }

                 function Find-Certificate {
                     param(
                         [string] $Thumbprint,
                         [string] $StoreLocationText,
                         [string] $StoreNameText
                     )

                     $storeLocation = [System.Security.Cryptography.X509Certificates.StoreLocation]::$StoreLocationText
                     $storeName = [System.Security.Cryptography.X509Certificates.StoreName]::$StoreNameText
                     $store = [System.Security.Cryptography.X509Certificates.X509Store]::new($storeName, $storeLocation)
                     $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)

                     try {
                         $certificate = $store.Certificates |
                             Where-Object { $_.Thumbprint -eq $Thumbprint } |
                             Sort-Object NotAfter -Descending |
                             Select-Object -First 1

                         if ($null -eq $certificate) {
                             throw "Automation certificate '$Thumbprint' was not found in $StoreLocationText\$StoreNameText."
                         }

                         if (-not $certificate.HasPrivateKey) {
                             throw "Automation certificate '$Thumbprint' does not have an accessible private key."
                         }

                         return $certificate
                     }
                     finally {
                         $store.Close()
                     }
                 }

                 $certificate = Find-Certificate `
                     -Thumbprint '{{EscapePowerShellSingleQuotedString(certificateThumbprint)}}' `
                     -StoreLocationText '{{EscapePowerShellSingleQuotedString(certificateStoreLocation)}}' `
                     -StoreNameText '{{EscapePowerShellSingleQuotedString(certificateStoreName)}}'

                 Import-Module ExchangeOnlineManagement -MinimumVersion 3.0.0 -ErrorAction Stop
                 Connect-ExchangeOnline `
                     -AppId '{{EscapePowerShellSingleQuotedString(clientId)}}' `
                     -Certificate $certificate `
                     -Organization '{{EscapePowerShellSingleQuotedString(tenantId)}}' `
                     -ShowBanner:$false `
                     -ShowProgress:$false `
                     -ErrorAction Stop | Out-Null

                 try {
                     try {
                         $organizationCustomizationEnabled = Ensure-OrganizationCustomizationEnabled
                         $acceptedDomains = @(Get-AcceptedDomain -ErrorAction Stop |
                             ForEach-Object { [string] $_.DomainName } |
                             Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
                             Sort-Object -Unique)

                         if (@($acceptedDomains).Count -eq 0) {
                             throw 'Get-AcceptedDomain did not return any accepted domains for this tenant.'
                         }

                         $beforeInboundSpam = Get-InboundSpamSnapshot -PolicyName $spamFilterPolicyName -RuleName $spamFilterRuleName
                         $beforeOutboundSpam = Get-OutboundSpamSnapshot -PolicyName $outboundSpamPolicyName -RuleName $outboundSpamRuleName

                         $alreadyCompliant =
                             (Test-InboundSpamCompliance -Snapshot $beforeInboundSpam -AcceptedDomains $acceptedDomains) -and
                             (Test-OutboundSpamCompliance -Snapshot $beforeOutboundSpam -AcceptedDomains $acceptedDomains)

                         if (-not $alreadyCompliant) {
                             if ($beforeInboundSpam.policyExists) {
                                 Set-HostedContentFilterPolicy `
                                     -Identity $spamFilterPolicyName `
                                     -SpamAction Quarantine `
                                     -HighConfidenceSpamAction Quarantine `
                                     -PhishSpamAction Quarantine `
                                     -HighConfidencePhishAction Quarantine `
                                     -BulkSpamAction Quarantine `
                                     -BulkThreshold 6 `
                                     -QuarantineRetentionPeriod 30 `
                                     -SpamZapEnabled $true `
                                     -PhishZapEnabled $true `
                                     -AllowedSenderDomains $null `
                                     -AllowedSenders $null `
                                     -ErrorAction Stop | Out-Null
                             }
                             else {
                                 New-HostedContentFilterPolicy `
                                     -Name $spamFilterPolicyName `
                                     -SpamAction Quarantine `
                                     -HighConfidenceSpamAction Quarantine `
                                     -PhishSpamAction Quarantine `
                                     -HighConfidencePhishAction Quarantine `
                                     -BulkSpamAction Quarantine `
                                     -BulkThreshold 6 `
                                     -QuarantineRetentionPeriod 30 `
                                     -SpamZapEnabled $true `
                                     -PhishZapEnabled $true `
                                     -ErrorAction Stop | Out-Null
                             }

                             if ($beforeInboundSpam.ruleExists) {
                                 Set-HostedContentFilterRule `
                                     -Identity $spamFilterRuleName `
                                     -RecipientDomainIs $acceptedDomains `
                                     -ErrorAction Stop | Out-Null

                                 Enable-HostedContentFilterRule `
                                     -Identity $spamFilterRuleName `
                                     -Confirm:$false `
                                     -ErrorAction Stop | Out-Null
                             }
                             else {
                                 New-HostedContentFilterRule `
                                     -Name $spamFilterRuleName `
                                     -HostedContentFilterPolicy $spamFilterPolicyName `
                                     -RecipientDomainIs $acceptedDomains `
                                     -Enabled $true `
                                     -Priority 0 `
                                     -ErrorAction Stop | Out-Null
                             }

                             if ($beforeOutboundSpam.policyExists) {
                                 Set-HostedOutboundSpamFilterPolicy `
                                     -Identity $outboundSpamPolicyName `
                                     -AutoForwardingMode Automatic `
                                     -NotifyOutboundSpam $false `
                                     -RecipientLimitExternalPerHour {{OutboundExternalRecipientLimit}} `
                                     -RecipientLimitInternalPerHour {{OutboundInternalRecipientLimit}} `
                                     -RecipientLimitPerDay {{OutboundDailyRecipientLimit}} `
                                     -ActionWhenThresholdReached BlockUserForToday `
                                     -ErrorAction Stop | Out-Null
                             }
                             else {
                                 New-HostedOutboundSpamFilterPolicy `
                                     -Name $outboundSpamPolicyName `
                                     -AutoForwardingMode Automatic `
                                     -NotifyOutboundSpam $false `
                                     -RecipientLimitExternalPerHour {{OutboundExternalRecipientLimit}} `
                                     -RecipientLimitInternalPerHour {{OutboundInternalRecipientLimit}} `
                                     -RecipientLimitPerDay {{OutboundDailyRecipientLimit}} `
                                     -ActionWhenThresholdReached BlockUserForToday `
                                     -ErrorAction Stop | Out-Null
                             }

                             if ($beforeOutboundSpam.ruleExists) {
                                 Set-HostedOutboundSpamFilterRule `
                                     -Identity $outboundSpamRuleName `
                                     -SenderDomainIs $acceptedDomains `
                                     -ErrorAction Stop | Out-Null

                                 Enable-HostedOutboundSpamFilterRule `
                                     -Identity $outboundSpamRuleName `
                                     -Confirm:$false `
                                     -ErrorAction Stop | Out-Null
                             }
                             else {
                                 New-HostedOutboundSpamFilterRule `
                                     -Name $outboundSpamRuleName `
                                     -HostedOutboundSpamFilterPolicy $outboundSpamPolicyName `
                                     -SenderDomainIs $acceptedDomains `
                                     -Enabled $true `
                                     -Priority 0 `
                                     -ErrorAction Stop | Out-Null
                             }
                         }

                         $afterInboundSpam = Get-InboundSpamSnapshot -PolicyName $spamFilterPolicyName -RuleName $spamFilterRuleName
                         $afterOutboundSpam = Get-OutboundSpamSnapshot -PolicyName $outboundSpamPolicyName -RuleName $outboundSpamRuleName
                         $connectionFilter = Get-ConnectionFilterSnapshot

                         $notes = New-Object System.Collections.Generic.List[string]
                         if ($organizationCustomizationEnabled) {
                             $notes.Add('Exchange Online organization customization was enabled automatically before the baseline was applied.')
                         }
                         $notes.Add('Automatic external forwarding uses AutoForwardingMode Automatic. Current Microsoft documentation states that Automatic now has the same effect as Off.')
                         $notes.Add('Admin notifications for restricted users should be verified through the default alert policy named User restricted from sending email. This baseline intentionally leaves legacy NotifyOutboundSpam recipients unset.')
                         $notes.Add('Securityzator did not create SCL-specific mail flow rules in this slice.')

                         $needsManualFollowUp = $false

                         if (-not [string]::IsNullOrWhiteSpace($connectionFilter.readbackError)) {
                             $needsManualFollowUp = $true
                             $notes.Add("Hosted Connection Filter readback was unavailable: $($connectionFilter.readbackError)")
                         }
                         elseif (@($connectionFilter.ipAllowList).Count -gt 0) {
                             $needsManualFollowUp = $true
                             $notes.Add('Default Hosted Connection Filter policy still contains IP allow list entries. Securityzator did not clear them automatically in this slice because approved inbound relays can depend on them.')
                         }

                         [ordered]@{
                             success = $true
                             alreadyCompliant = $alreadyCompliant
                             needsManualFollowUp = $needsManualFollowUp
                             inboundSpam = $afterInboundSpam
                             outboundSpam = $afterOutboundSpam
                             connectionFilter = $connectionFilter
                             notes = $notes
                         } | ConvertTo-Json -Depth 6 -Compress
                     }
                     catch {
                         [ordered]@{
                             success = $false
                             errorMessage = $_.Exception.Message
                         } | ConvertTo-Json -Depth 4 -Compress
                     }
                 }
                 finally {
                     Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
                 }
                 """;
    }

    private static string BuildApplyAntiMalwareBaselineScript(
        string tenantId,
        string clientId,
        string certificateThumbprint,
        string certificateStoreLocation,
        string certificateStoreName)
    {
        return $$"""
                 $ErrorActionPreference = 'Stop'
                 $ProgressPreference = 'SilentlyContinue'
                 Set-StrictMode -Version Latest

                 $malwareFilterPolicyName = '{{EscapePowerShellSingleQuotedString(MalwareFilterPolicyName)}}'
                 $malwareFilterRuleName = '{{EscapePowerShellSingleQuotedString(MalwareFilterRuleName)}}'

                 if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
                     throw 'The ExchangeOnlineManagement PowerShell module is not installed on this host. Install it before queueing the Defender for Office anti-malware baseline.'
                 }

                 function Get-FirstOrDefault {
                     param([object[]] $Items)

                     if ($null -eq $Items) {
                         return $null
                     }

                     return @($Items | Select-Object -First 1)[0]
                 }

                 function Convert-ToStringArray {
                     param([object] $Values)

                     if ($null -eq $Values) {
                         return @()
                     }

                     return @($Values | ForEach-Object { [string] $_ } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
                 }

                 function Test-StringArrayEquals {
                     param(
                         [string[]] $Left,
                         [string[]] $Right
                     )

                     $leftValue = (@($Left | Sort-Object -Unique) -join '|')
                     $rightValue = (@($Right | Sort-Object -Unique) -join '|')

                     return $leftValue -eq $rightValue
                 }

                 function Ensure-OrganizationCustomizationEnabled {
                     $organizationConfig = Get-OrganizationConfig -ErrorAction Stop
                     if ($null -ne $organizationConfig -and [bool] $organizationConfig.IsDehydrated) {
                         Enable-OrganizationCustomization -ErrorAction Stop | Out-Null
                         Start-Sleep -Seconds 5
                         return $true
                     }

                     return $false
                 }

                 function Get-OptionalPropertyValue {
                     param(
                         [object] $InputObject,
                         [string] $PropertyName
                     )

                     if ($null -eq $InputObject) {
                         return $null
                     }

                     $property = $InputObject.PSObject.Properties[$PropertyName]
                     if ($null -eq $property) {
                         return $null
                     }

                     return $property.Value
                 }

                 function Get-AntiMalwareSnapshot {
                     param(
                         [string] $PolicyName,
                         [string] $RuleName
                     )

                     $policy = Get-FirstOrDefault -Items ((Get-MalwareFilterPolicy -ErrorAction Stop) | Where-Object { $_.Name -eq $PolicyName })
                     $rule = Get-FirstOrDefault -Items ((Get-MalwareFilterRule -ErrorAction Stop) | Where-Object { $_.Name -eq $RuleName })
                     $recipientDomains = Convert-ToStringArray -Values (Get-OptionalPropertyValue -InputObject $rule -PropertyName 'RecipientDomainIs')

                     return [ordered]@{
                         policyExists = $null -ne $policy
                         ruleExists = $null -ne $rule
                         policyName = if ($null -eq $policy) { $PolicyName } else { [string] $policy.Name }
                         ruleName = if ($null -eq $rule) { $RuleName } else { [string] $rule.Name }
                         ruleState = [string] (Get-OptionalPropertyValue -InputObject $rule -PropertyName 'State')
                         enableFileFilter = if ($null -eq $policy) { $false } else { [bool] (Get-OptionalPropertyValue -InputObject $policy -PropertyName 'EnableFileFilter') }
                         fileTypeAction = if ($null -eq $policy) { '' } else { [string] (Get-OptionalPropertyValue -InputObject $policy -PropertyName 'FileTypeAction') }
                         zapEnabled = if ($null -eq $policy) { $false } else { [bool] (Get-OptionalPropertyValue -InputObject $policy -PropertyName 'ZapEnabled') }
                         quarantineTag = if ($null -eq $policy) { '' } else { [string] (Get-OptionalPropertyValue -InputObject $policy -PropertyName 'QuarantineTag') }
                         recipientDomains = $recipientDomains
                     }
                 }

                 function Test-AntiMalwareCompliance {
                     param(
                         [hashtable] $Snapshot,
                         [string[]] $AcceptedDomains
                     )

                     return (
                         $Snapshot.policyExists -and
                         $Snapshot.ruleExists -and
                         $Snapshot.enableFileFilter -eq $true -and
                         $Snapshot.fileTypeAction -eq 'Reject' -and
                         $Snapshot.zapEnabled -eq $true -and
                         $Snapshot.quarantineTag -eq 'AdminOnlyAccessPolicy' -and
                         (Test-StringArrayEquals -Left $Snapshot.recipientDomains -Right $AcceptedDomains))
                 }

                 function Find-Certificate {
                     param(
                         [string] $Thumbprint,
                         [string] $StoreLocationText,
                         [string] $StoreNameText
                     )

                     $storeLocation = [System.Security.Cryptography.X509Certificates.StoreLocation]::$StoreLocationText
                     $storeName = [System.Security.Cryptography.X509Certificates.StoreName]::$StoreNameText
                     $store = [System.Security.Cryptography.X509Certificates.X509Store]::new($storeName, $storeLocation)
                     $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)

                     try {
                         $certificate = $store.Certificates |
                             Where-Object { $_.Thumbprint -eq $Thumbprint } |
                             Sort-Object NotAfter -Descending |
                             Select-Object -First 1

                         if ($null -eq $certificate) {
                             throw "Automation certificate '$Thumbprint' was not found in $StoreLocationText\$StoreNameText."
                         }

                         if (-not $certificate.HasPrivateKey) {
                             throw "Automation certificate '$Thumbprint' does not have an accessible private key."
                         }

                         return $certificate
                     }
                     finally {
                         $store.Close()
                     }
                 }

                 $certificate = Find-Certificate `
                     -Thumbprint '{{EscapePowerShellSingleQuotedString(certificateThumbprint)}}' `
                     -StoreLocationText '{{EscapePowerShellSingleQuotedString(certificateStoreLocation)}}' `
                     -StoreNameText '{{EscapePowerShellSingleQuotedString(certificateStoreName)}}'

                 Import-Module ExchangeOnlineManagement -MinimumVersion 3.0.0 -ErrorAction Stop
                 Connect-ExchangeOnline `
                     -AppId '{{EscapePowerShellSingleQuotedString(clientId)}}' `
                     -Certificate $certificate `
                     -Organization '{{EscapePowerShellSingleQuotedString(tenantId)}}' `
                     -ShowBanner:$false `
                     -ShowProgress:$false `
                     -ErrorAction Stop | Out-Null

                 try {
                     try {
                         $organizationCustomizationEnabled = Ensure-OrganizationCustomizationEnabled
                         $acceptedDomains = @(Get-AcceptedDomain -ErrorAction Stop |
                             ForEach-Object { [string] $_.DomainName } |
                             Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
                             Sort-Object -Unique)

                         if ($acceptedDomains.Count -eq 0) {
                             throw 'Get-AcceptedDomain did not return any accepted domains for this tenant.'
                         }

                         $beforeAntiMalware = Get-AntiMalwareSnapshot -PolicyName $malwareFilterPolicyName -RuleName $malwareFilterRuleName
                         $alreadyCompliant = Test-AntiMalwareCompliance -Snapshot $beforeAntiMalware -AcceptedDomains $acceptedDomains

                         if (-not $alreadyCompliant) {
                             if ($beforeAntiMalware.policyExists) {
                                 Set-MalwareFilterPolicy `
                                     -Identity $malwareFilterPolicyName `
                                     -EnableFileFilter $true `
                                     -FileTypeAction Reject `
                                     -ZapEnabled $true `
                                     -QuarantineTag AdminOnlyAccessPolicy `
                                     -ErrorAction Stop | Out-Null
                             }
                             else {
                                 New-MalwareFilterPolicy `
                                     -Name $malwareFilterPolicyName `
                                     -EnableFileFilter $true `
                                     -FileTypeAction Reject `
                                     -ZapEnabled $true `
                                     -QuarantineTag AdminOnlyAccessPolicy `
                                     -ErrorAction Stop | Out-Null
                             }

                             if ($beforeAntiMalware.ruleExists) {
                                 Set-MalwareFilterRule `
                                     -Identity $malwareFilterRuleName `
                                     -RecipientDomainIs $acceptedDomains `
                                     -Priority 0 `
                                     -ErrorAction Stop | Out-Null

                                 if ($beforeAntiMalware.ruleState -ne 'Enabled') {
                                     Enable-MalwareFilterRule -Identity $malwareFilterRuleName -Confirm:$false -ErrorAction Stop | Out-Null
                                 }
                             }
                             else {
                                 New-MalwareFilterRule `
                                     -Name $malwareFilterRuleName `
                                     -MalwareFilterPolicy $malwareFilterPolicyName `
                                     -RecipientDomainIs $acceptedDomains `
                                     -Enabled $true `
                                     -Priority 0 `
                                     -ErrorAction Stop | Out-Null
                             }
                         }

                         $afterAntiMalware = Get-AntiMalwareSnapshot -PolicyName $malwareFilterPolicyName -RuleName $malwareFilterRuleName
                         $notes = New-Object System.Collections.Generic.List[string]

                         if ($organizationCustomizationEnabled) {
                             $notes.Add('Exchange Online organization customization was enabled automatically before the anti-malware baseline was applied.')
                         }

                         $notes.Add('This custom anti-malware baseline keeps Microsoft recommended malware ZAP enabled, turns on the common attachment types filter, and sends malware detections to the admin-only quarantine policy.')
                         $notes.Add('Custom anti-malware policies apply to inbound mail. If Standard or Strict preset security policies cover a recipient, the preset settings take precedence.')

                         [ordered]@{
                             success = $true
                             alreadyCompliant = $alreadyCompliant
                             needsManualFollowUp = $false
                             antiMalware = $afterAntiMalware
                             notes = $notes
                         } | ConvertTo-Json -Depth 6 -Compress
                     }
                     catch {
                         [ordered]@{
                             success = $false
                             errorMessage = $_.Exception.Message
                         } | ConvertTo-Json -Depth 4 -Compress
                     }
                 }
                 finally {
                     Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
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
            throw new InvalidOperationException("Defender for Office automation completed without returning a JSON payload.");
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

        return NormalizeFailureMessage(normalized);
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

    private static string NormalizeFailureMessage(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return "Defender for Office automation failed without returning a reason.";
        }

        var normalized = value.Trim().ReplaceLineEndings(" ");
        return normalized.Length <= 400 ? normalized : normalized[..400];
    }

    private static string EscapePowerShellSingleQuotedString(string value)
    {
        return value.Replace("'", "''", StringComparison.Ordinal);
    }

    private static string BuildPowerShellStringArrayLiteral(IEnumerable<string> values)
    {
        var sanitized = values
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Select(value => $"'{EscapePowerShellSingleQuotedString(value)}'")
            .ToArray();

        return sanitized.Length == 0
            ? "@()"
            : $"@({string.Join(",", sanitized)})";
    }

    public sealed record DefenderForOfficeAntiPhishBaselineResult(
        bool AlreadyCompliant,
        bool NeedsManualFollowUp,
        DefenderForOfficeAntiPhishSnapshot AntiPhish,
        IReadOnlyList<string> Notes);

    public sealed record DefenderForOfficeExchangeMailboxBaselineResult(
        bool AlreadyCompliant,
        bool NeedsManualFollowUp,
        DefenderForOfficeExchangeOrganizationSnapshot Organization,
        DefenderForOfficeExchangeOwaMailboxPolicySnapshot OwaMailboxPolicy,
        DefenderForOfficeExchangeSharingPolicySnapshot SharingPolicy,
        IReadOnlyList<string> Notes);

    public sealed record DefenderForOfficeBaselineResult(
        bool AlreadyCompliant,
        DefenderForOfficeGlobalProtectionSnapshot GlobalProtection,
        DefenderForOfficeSafeLinksSnapshot SafeLinks,
        DefenderForOfficeSafeAttachmentsSnapshot SafeAttachments,
        IReadOnlyList<string> Notes);

    public sealed record DefenderForOfficeGlobalProtectionSnapshot(
        bool EnableAtpForSpoTeamsOdb,
        bool? EnableSafeDocs,
        bool? AllowSafeDocsOpen);

    public sealed record DefenderForOfficeSafeLinksSnapshot(
        bool PolicyExists,
        bool RuleExists,
        string PolicyName,
        string RuleName,
        bool EnableSafeLinksForEmail,
        bool EnableSafeLinksForTeams,
        bool EnableSafeLinksForOffice,
        bool TrackClicks,
        bool AllowClickThrough,
        bool ScanUrls,
        bool EnableForInternalSenders,
        bool DeliverMessageAfterScan,
        bool DisableUrlRewrite,
        IReadOnlyList<string> RecipientDomains);

    public sealed record DefenderForOfficeSafeAttachmentsSnapshot(
        bool PolicyExists,
        bool RuleExists,
        string PolicyName,
        string RuleName,
        bool Enable,
        string Action,
        bool Redirect,
        IReadOnlyList<string> RecipientDomains);

    public sealed record DefenderForOfficeAntiPhishSnapshot(
        bool PolicyExists,
        bool RuleExists,
        string PolicyName,
        string RuleName,
        string RuleState,
        bool EnableMailboxIntelligence,
        bool EnableMailboxIntelligenceProtection,
        string MailboxIntelligenceProtectionAction,
        string ImpersonationProtectionState,
        bool EnableOrganizationDomainsProtection,
        bool EnableTargetedDomainsProtection,
        string TargetedDomainProtectionAction,
        bool EnableTargetedUserProtection,
        string TargetedUserProtectionAction,
        bool EnableSimilarDomainsSafetyTips,
        bool EnableSimilarUsersSafetyTips,
        bool EnableUnusualCharactersSafetyTips,
        int PhishThresholdLevel,
        IReadOnlyList<string> RecipientDomains,
        IReadOnlyList<string> TargetedDomains,
        IReadOnlyList<string> TargetedUsers);

    public sealed record DefenderForOfficeExchangeOrganizationSnapshot(
        bool AuditDisabled,
        bool MailTipsAllTipsEnabled,
        bool AppsForOfficeEnabled,
        bool OAuth2ClientProfileEnabled);

    public sealed record DefenderForOfficeExchangeOwaMailboxPolicySnapshot(
        bool PolicyExists,
        string Identity,
        string Name,
        bool IsDefault,
        bool AdditionalStorageProvidersAvailable);

    public sealed record DefenderForOfficeExchangeSharingPolicySnapshot(
        bool PolicyExists,
        string Identity,
        string Name,
        IReadOnlyList<string> Domains,
        bool HasAnonymousCalendarSharing);

    public sealed record DefenderForOfficeSpamAndForwardingBaselineResult(
        bool AlreadyCompliant,
        bool NeedsManualFollowUp,
        DefenderForOfficeInboundSpamSnapshot InboundSpam,
        DefenderForOfficeOutboundSpamSnapshot OutboundSpam,
        DefenderForOfficeConnectionFilterSnapshot ConnectionFilter,
        IReadOnlyList<string> Notes);

    public sealed record DefenderForOfficeAntiMalwareBaselineResult(
        bool AlreadyCompliant,
        bool NeedsManualFollowUp,
        DefenderForOfficeAntiMalwareSnapshot AntiMalware,
        IReadOnlyList<string> Notes);

    public sealed record DefenderForOfficeInboundSpamSnapshot(
        bool PolicyExists,
        bool RuleExists,
        string PolicyName,
        string RuleName,
        string SpamAction,
        string HighConfidenceSpamAction,
        string PhishSpamAction,
        string HighConfidencePhishAction,
        string BulkSpamAction,
        int BulkThreshold,
        int QuarantineRetentionPeriod,
        bool SpamZapEnabled,
        bool PhishZapEnabled,
        IReadOnlyList<string> AllowedSenderDomains,
        IReadOnlyList<string> RecipientDomains);

    public sealed record DefenderForOfficeOutboundSpamSnapshot(
        bool PolicyExists,
        bool RuleExists,
        string PolicyName,
        string RuleName,
        string AutoForwardingMode,
        bool NotifyOutboundSpam,
        uint RecipientLimitExternalPerHour,
        uint RecipientLimitInternalPerHour,
        uint RecipientLimitPerDay,
        string ActionWhenThresholdReached,
        IReadOnlyList<string> SenderDomains);

    public sealed record DefenderForOfficeConnectionFilterSnapshot(
        bool PolicyExists,
        string PolicyName,
        IReadOnlyList<string> IpAllowList,
        string ReadbackError);

    public sealed record DefenderForOfficeAntiMalwareSnapshot(
        bool PolicyExists,
        bool RuleExists,
        string PolicyName,
        string RuleName,
        string RuleState,
        bool EnableFileFilter,
        string FileTypeAction,
        bool ZapEnabled,
        string QuarantineTag,
        IReadOnlyList<string> RecipientDomains);

    private sealed record DefenderForOfficeBaselinePayload(
        bool Success,
        bool AlreadyCompliant,
        DefenderForOfficeGlobalProtectionSnapshot? GlobalProtection,
        DefenderForOfficeSafeLinksSnapshot? SafeLinks,
        DefenderForOfficeSafeAttachmentsSnapshot? SafeAttachments,
        string[]? Notes,
        string? ErrorMessage);

    private sealed record DefenderForOfficeAntiPhishBaselinePayload(
        bool Success,
        bool AlreadyCompliant,
        bool NeedsManualFollowUp,
        DefenderForOfficeAntiPhishSnapshot? AntiPhish,
        string[]? Notes,
        string? ErrorMessage);

    private sealed record DefenderForOfficeExchangeMailboxBaselinePayload(
        bool Success,
        bool AlreadyCompliant,
        bool NeedsManualFollowUp,
        DefenderForOfficeExchangeOrganizationSnapshot? Organization,
        DefenderForOfficeExchangeOwaMailboxPolicySnapshot? OwaMailboxPolicy,
        DefenderForOfficeExchangeSharingPolicySnapshot? SharingPolicy,
        string[]? Notes,
        string? ErrorMessage);

    private sealed record DefenderForOfficeSpamAndForwardingBaselinePayload(
        bool Success,
        bool AlreadyCompliant,
        bool NeedsManualFollowUp,
        DefenderForOfficeInboundSpamSnapshot? InboundSpam,
        DefenderForOfficeOutboundSpamSnapshot? OutboundSpam,
        DefenderForOfficeConnectionFilterSnapshot? ConnectionFilter,
        string[]? Notes,
        string? ErrorMessage);

    private sealed record DefenderForOfficeAntiMalwareBaselinePayload(
        bool Success,
        bool AlreadyCompliant,
        bool NeedsManualFollowUp,
        DefenderForOfficeAntiMalwareSnapshot? AntiMalware,
        string[]? Notes,
        string? ErrorMessage);
}
