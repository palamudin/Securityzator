@{
    Metadata = @{
        GraphSourceMapPath      = 'graph.source-map.psd1'
        BlueprintCatalogSource  = 'src\Securityzator.Infrastructure\Blueprints\BusinessPremiumBlueprintCatalog.cs'
        SecureScoreDocsUrl      = 'https://github.com/microsoftgraph/microsoft-graph-docs-contrib/blob/main/api-reference/v1.0/api/security-list-securescorecontrolprofiles.md'
        Notes                   = @(
            'This file freezes the current Business Premium recommendation-to-playbook contract.',
            'Use it to catch accidental drift in surfaced recommendation cards, template keys, and queueable control coverage.'
        )
    }

    BusinessPremium = @{
        RecommendationCatalog = @(
            @{
                Rank                   = 1
                Title                  = 'Block legacy authentication'
                Category               = 'Identity'
                Product                = 'Conditional Access'
                Status                 = 'Runnable now'
                Impact                 = 'High'
                RemediationTemplateKey = 'block-legacy-auth'
            },
            @{
                Rank                   = 2
                Title                  = 'Require MFA for privileged administrators'
                Category               = 'Identity'
                Product                = 'Microsoft Entra ID'
                Status                 = 'Runnable now'
                Impact                 = 'High'
                RemediationTemplateKey = 'require-mfa-admins'
            },
            @{
                Rank                   = 3
                Title                  = 'Require MFA for all users'
                Category               = 'Identity'
                Product                = 'Microsoft Entra ID'
                Status                 = 'Runnable now'
                Impact                 = 'High'
                RemediationTemplateKey = 'mfa-all-users'
            },
            @{
                Rank                   = 4
                Title                  = 'Risk-based identity protection'
                Category               = 'Identity'
                Product                = 'Microsoft Entra ID'
                Status                 = 'Runnable now'
                Impact                 = 'High'
                RemediationTemplateKey = 'entra-risk-policies'
            },
            @{
                Rank                   = 5
                Title                  = 'Entra admin and consent hygiene'
                Category               = 'Identity'
                Product                = 'Microsoft Entra ID'
                Status                 = 'Runnable now'
                Impact                 = 'High'
                RemediationTemplateKey = 'entra-identity-hygiene-baseline'
            },
            @{
                Rank                   = 6
                Title                  = 'Require phishing-resistant MFA for privileged administrators'
                Category               = 'Identity'
                Product                = 'Conditional Access'
                Status                 = 'Runnable now'
                Impact                 = 'High'
                RemediationTemplateKey = 'require-phishing-resistant-mfa-admins'
            },
            @{
                Rank                   = 7
                Title                  = 'Defender for Office anti-phishing and impersonation'
                Category               = 'Apps'
                Product                = 'Defender for Office'
                Status                 = 'Runnable now'
                Impact                 = 'High'
                RemediationTemplateKey = 'mdo-anti-phishing-and-impersonation'
            },
            @{
                Rank                   = 8
                Title                  = 'Defender for Office Safe Links and attachments'
                Category               = 'Apps'
                Product                = 'Defender for Office'
                Status                 = 'Runnable now'
                Impact                 = 'High'
                RemediationTemplateKey = 'mdo-safe-links-and-attachments'
            },
            @{
                Rank                   = 9
                Title                  = 'Defender for Office spam and forwarding hardening'
                Category               = 'Apps'
                Product                = 'Defender for Office'
                Status                 = 'Runnable now'
                Impact                 = 'High'
                RemediationTemplateKey = 'mdo-spam-and-forwarding-baseline'
            },
            @{
                Rank                   = 10
                Title                  = 'Exchange Online collaboration and mailbox hardening'
                Category               = 'Apps'
                Product                = 'Exchange Online'
                Status                 = 'Runnable now'
                Impact                 = 'Medium'
                RemediationTemplateKey = 'exchange-online-collaboration-and-mailbox'
            },
            @{
                Rank                   = 11
                Title                  = 'Purview data protection baseline'
                Category               = 'Data'
                Product                = 'Microsoft Information Protection'
                Status                 = 'Control set draft'
                Impact                 = 'High'
                RemediationTemplateKey = 'purview-data-protection-baseline'
            },
            @{
                Rank                   = 12
                Title                  = 'Teams meeting hardening baseline'
                Category               = 'Apps'
                Product                = 'Microsoft Teams'
                Status                 = 'Runnable now'
                Impact                 = 'Medium'
                RemediationTemplateKey = 'teams-meeting-hardening'
            },
            @{
                Rank                   = 13
                Title                  = 'SharePoint session and authentication hardening'
                Category               = 'Apps'
                Product                = 'SharePoint Online'
                Status                 = 'Control set draft'
                Impact                 = 'Medium'
                RemediationTemplateKey = 'sharepoint-online-session-hardening'
            },
            @{
                Rank                   = 14
                Title                  = 'Defender for Cloud Apps discovery'
                Category               = 'Apps'
                Product                = 'Microsoft Defender for Cloud Apps'
                Status                 = 'Guided enablement'
                Impact                 = 'Medium'
                RemediationTemplateKey = 'defender-cloud-apps-foundation'
            },
            @{
                Rank                   = 15
                Title                  = 'Defender for Identity foundation'
                Category               = 'Identity'
                Product                = 'Defender for Identity'
                Status                 = 'Guided enablement'
                Impact                 = 'Medium'
                RemediationTemplateKey = 'defender-identity-foundation'
            },
            @{
                Rank                   = 16
                Title                  = 'Protect breakglass accounts with exclusions and monitoring'
                Category               = 'Identity'
                Product                = 'Conditional Access'
                Status                 = 'Discovery'
                Impact                 = 'Medium'
                RemediationTemplateKey = 'protect-breakglass'
            },
            @{
                Rank                   = 17
                Title                  = 'Review risky sign-in coverage for workload identities'
                Category               = 'Threat protection'
                Product                = 'Microsoft Defender'
                Status                 = 'Discovery'
                Impact                 = 'Medium'
                RemediationTemplateKey = 'workload-identity-review'
            },
            @{
                Rank                   = 18
                Title                  = 'Require MFA when risky sign-ins are detected'
                Category               = 'Identity'
                Product                = 'Microsoft Entra ID'
                Status                 = 'Runnable now'
                Impact                 = 'High'
                RemediationTemplateKey = 'require-mfa-risky-sign-ins'
            },
            @{
                Rank                   = 19
                Title                  = 'Require password change for high-risk users'
                Category               = 'Identity'
                Product                = 'Microsoft Entra ID'
                Status                 = 'Runnable now'
                Impact                 = 'High'
                RemediationTemplateKey = 'require-password-change-high-risk-users'
            },
            @{
                Rank                   = 20
                Title                  = 'Require MFA for guest access'
                Category               = 'Identity'
                Product                = 'Conditional Access'
                Status                 = 'Runnable now'
                Impact                 = 'High'
                RemediationTemplateKey = 'require-mfa-guest-access'
            },
            @{
                Rank                   = 21
                Title                  = 'Require MFA for Microsoft admin portals'
                Category               = 'Identity'
                Product                = 'Conditional Access'
                Status                 = 'Runnable now'
                Impact                 = 'High'
                RemediationTemplateKey = 'require-mfa-admin-portals'
            },
            @{
                Rank                   = 22
                Title                  = 'Require MFA for Azure management'
                Category               = 'Identity'
                Product                = 'Conditional Access'
                Status                 = 'Runnable now'
                Impact                 = 'High'
                RemediationTemplateKey = 'require-mfa-azure-management'
            },
            @{
                Rank                   = 23
                Title                  = 'Secure security info registration'
                Category               = 'Identity'
                Product                = 'Conditional Access'
                Status                 = 'Runnable now'
                Impact                 = 'High'
                RemediationTemplateKey = 'secure-security-info-registration'
            }
        )

        QueueExecutableTemplateKeys = @(
            'block-legacy-auth'
            'require-mfa-admins'
            'mfa-all-users'
            'entra-risk-policies'
            'entra-identity-hygiene-baseline'
            'entra-daily-use-hardening'
            'entra-low-impact-app-consent'
            'require-phishing-resistant-mfa-admins'
            'mdo-anti-phishing-and-impersonation'
            'mdo-anti-malware-baseline'
            'mdo-safe-links-and-attachments'
            'mdo-spam-and-forwarding-baseline'
            'exchange-online-collaboration-and-mailbox'
            'teams-meeting-hardening'
            'defender-endpoint-bitlocker-baseline'
            'defender-endpoint-browser-and-adobe-policy-surface-readiness'
            'defender-endpoint-browser-hardening'
            'defender-endpoint-credential-and-elevation-hardening'
            'defender-endpoint-core-protection'
            'defender-endpoint-exploit-protection'
            'defender-endpoint-firewall-and-smartscreen'
            'defender-endpoint-remote-access-and-network-hardening'
            'defender-endpoint-sensor-and-agent-health'
            'defender-endpoint-attack-surface-reduction'
            'defender-endpoint-os-security-baseline'
            'require-mfa-risky-sign-ins'
            'require-password-change-high-risk-users'
            'require-mfa-guest-access'
            'require-mfa-admin-portals'
            'require-mfa-azure-management'
            'secure-security-info-registration'
        )

        ExtendedTemplateKeys = @(
            'defender-endpoint-attack-surface-reduction'
            'defender-endpoint-bitlocker-baseline'
            'defender-endpoint-browser-and-adobe-policy-surface-readiness'
            'defender-endpoint-browser-hardening'
            'defender-endpoint-credential-and-elevation-hardening'
            'defender-endpoint-core-protection'
            'defender-endpoint-exploit-protection'
            'defender-endpoint-firewall-and-smartscreen'
            'defender-endpoint-remote-access-and-network-hardening'
            'defender-endpoint-os-security-baseline'
            'defender-endpoint-sensor-and-agent-health'
            'entra-daily-use-hardening'
            'entra-low-impact-app-consent'
            'mdo-anti-malware-baseline'
            'defender-endpoint-macos-hardening'
            'defender-endpoint-linux-hardening'
            'defender-endpoint-security-posture'
            'active-directory-certificate-services-hardening'
            'defender-identity-sensor-coverage'
            'active-directory-privileged-account-hygiene'
            'active-directory-domain-security-hardening'
            'federated-identity-provider-hygiene'
            'salesforce-security-posture'
            'servicenow-security-posture'
            'github-enterprise-hardening'
            'connected-saas-session-and-auth-hardening'
            'sharepoint-collaboration-and-device-access'
            'app-governance-and-user-owned-apps'
            'microsoft-365-collaboration-sharing-governance'
        )
    }
}
