@{
    Metadata = @{
        Name = 'Securityzator confirmed-working tenant shakedown'
        LastReviewed = '2026-04-23'
        Description = 'Batch manifest for stress-testing the currently confirmed-working app-driven Securityzator controls against a clean tenant.'
    }

    Templates = @(
        @{
            Sequence = 10
            TemplateKey = 'entra-identity-hygiene-baseline'
            DisplayName = 'Entra identity hygiene assessment'
            Surface = 'Entra'
            Type = 'Assessment'
            RequiresIncludeGroup = $false
            DefaultLaunchMode = 'ReportOnly'
            SupportedLaunchModes = @('ReportOnly')
            Profiles = @('AssessmentOnly', 'AppOnlyConfirmed', 'ArmorMeUpAppOnly')
            Notes = 'Tenant-wide assessment of app consent, admin consent workflow, password-expiration posture, SSPR, and Global Administrator count.'
        }
        @{
            Sequence = 15
            TemplateKey = 'entra-daily-use-hardening'
            DisplayName = 'Entra daily-use hardening'
            Surface = 'Entra'
            Type = 'TenantBaseline'
            RequiresIncludeGroup = $false
            DefaultLaunchMode = 'DirectApply'
            SupportedLaunchModes = @('DirectApply')
            Profiles = @('AppOnlyConfirmed', 'ArmorMeUpAppOnly')
            Notes = 'Tenant-wide user-consent, admin-consent workflow, and default-domain password-policy alignment.'
        }
        @{
            Sequence = 20
            TemplateKey = 'block-legacy-auth'
            DisplayName = 'Block legacy authentication'
            Surface = 'ConditionalAccess'
            Type = 'Policy'
            RequiresIncludeGroup = $true
            DefaultLaunchMode = 'ReportOnly'
            SupportedLaunchModes = @('ReportOnly', 'Enabled')
            Profiles = @('AppOnlyConfirmed', 'ArmorMeUpAppOnly')
            Notes = 'Group-scoped Conditional Access quick win.'
        }
        @{
            Sequence = 30
            TemplateKey = 'require-mfa-admins'
            DisplayName = 'Require MFA for privileged admins'
            Surface = 'ConditionalAccess'
            Type = 'Policy'
            RequiresIncludeGroup = $true
            DefaultLaunchMode = 'ReportOnly'
            SupportedLaunchModes = @('ReportOnly', 'Enabled')
            Profiles = @('AppOnlyConfirmed', 'ArmorMeUpAppOnly')
            Notes = 'Targets the chosen privileged-admin group.'
        }
        @{
            Sequence = 40
            TemplateKey = 'mfa-all-users'
            DisplayName = 'Require MFA for all users'
            Surface = 'ConditionalAccess'
            Type = 'Policy'
            RequiresIncludeGroup = $false
            DefaultLaunchMode = 'ReportOnly'
            SupportedLaunchModes = @('ReportOnly', 'Enabled')
            Profiles = @('AppOnlyConfirmed', 'ArmorMeUpAppOnly')
            Notes = 'Tenant-wide Conditional Access MFA baseline with optional exclusion group.'
        }
        @{
            Sequence = 50
            TemplateKey = 'require-mfa-guest-access'
            DisplayName = 'Require MFA for guest access'
            Surface = 'ConditionalAccess'
            Type = 'Policy'
            RequiresIncludeGroup = $false
            DefaultLaunchMode = 'ReportOnly'
            SupportedLaunchModes = @('ReportOnly', 'Enabled')
            Profiles = @('AppOnlyConfirmed', 'ArmorMeUpAppOnly')
            Notes = 'Targets guest and external users.'
        }
        @{
            Sequence = 60
            TemplateKey = 'require-mfa-admin-portals'
            DisplayName = 'Require MFA for Microsoft admin portals'
            Surface = 'ConditionalAccess'
            Type = 'Policy'
            RequiresIncludeGroup = $false
            DefaultLaunchMode = 'ReportOnly'
            SupportedLaunchModes = @('ReportOnly', 'Enabled')
            Profiles = @('AppOnlyConfirmed', 'ArmorMeUpAppOnly')
            Notes = 'Admin portal Conditional Access protection.'
        }
        @{
            Sequence = 70
            TemplateKey = 'require-mfa-azure-management'
            DisplayName = 'Require MFA for Azure management'
            Surface = 'ConditionalAccess'
            Type = 'Policy'
            RequiresIncludeGroup = $false
            DefaultLaunchMode = 'ReportOnly'
            SupportedLaunchModes = @('ReportOnly', 'Enabled')
            Profiles = @('AppOnlyConfirmed', 'ArmorMeUpAppOnly')
            Notes = 'Application-scoped Conditional Access baseline for Azure management.'
        }
        @{
            Sequence = 80
            TemplateKey = 'secure-security-info-registration'
            DisplayName = 'Secure security info registration'
            Surface = 'ConditionalAccess'
            Type = 'Policy'
            RequiresIncludeGroup = $false
            DefaultLaunchMode = 'ReportOnly'
            SupportedLaunchModes = @('ReportOnly', 'Enabled')
            Profiles = @('AppOnlyConfirmed', 'ArmorMeUpAppOnly')
            Notes = 'Conditional Access protection around registration flows.'
        }
        @{
            Sequence = 90
            TemplateKey = 'require-phishing-resistant-mfa-admins'
            DisplayName = 'Require phishing-resistant MFA for privileged admins'
            Surface = 'ConditionalAccess'
            Type = 'Policy'
            RequiresIncludeGroup = $true
            DefaultLaunchMode = 'ReportOnly'
            SupportedLaunchModes = @('ReportOnly', 'Enabled')
            Profiles = @('AppOnlyConfirmed', 'ArmorMeUpAppOnly')
            Notes = 'Strengthens privileged-admin MFA beyond basic MFA.'
        }
        @{
            Sequence = 100
            TemplateKey = 'require-mfa-risky-sign-ins'
            DisplayName = 'Require MFA when risky sign-ins are detected'
            Surface = 'ConditionalAccess'
            Type = 'Policy'
            RequiresIncludeGroup = $false
            DefaultLaunchMode = 'ReportOnly'
            SupportedLaunchModes = @('ReportOnly', 'Enabled')
            Profiles = @('AppOnlyConfirmed', 'ArmorMeUpAppOnly')
            Notes = 'Sign-in risk policy path.'
        }
        @{
            Sequence = 110
            TemplateKey = 'require-password-change-high-risk-users'
            DisplayName = 'Require password change for high-risk users'
            Surface = 'ConditionalAccess'
            Type = 'Policy'
            RequiresIncludeGroup = $false
            DefaultLaunchMode = 'ReportOnly'
            SupportedLaunchModes = @('ReportOnly', 'Enabled')
            Profiles = @('AppOnlyConfirmed', 'ArmorMeUpAppOnly')
            Notes = 'User risk remediation path.'
        }
        @{
            Sequence = 120
            TemplateKey = 'defender-endpoint-core-protection'
            DisplayName = 'Defender endpoint core protection'
            Surface = 'Intune'
            Type = 'PilotBaseline'
            RequiresIncludeGroup = $true
            DefaultLaunchMode = 'DirectApply'
            SupportedLaunchModes = @('DirectApply')
            Profiles = @('AppOnlyConfirmed', 'ArmorMeUpAppOnly')
            Notes = 'Creates or updates the core protection and companion hardening profiles.'
        }
        @{
            Sequence = 130
            TemplateKey = 'defender-endpoint-firewall-and-smartscreen'
            DisplayName = 'Defender firewall and SmartScreen'
            Surface = 'Intune'
            Type = 'PilotBaseline'
            RequiresIncludeGroup = $true
            DefaultLaunchMode = 'DirectApply'
            SupportedLaunchModes = @('DirectApply')
            Profiles = @('AppOnlyConfirmed', 'ArmorMeUpAppOnly')
            Notes = 'Creates or updates Windows firewall/SmartScreen plus the companion Edge SmartScreen profile.'
        }
        @{
            Sequence = 140
            TemplateKey = 'defender-endpoint-browser-hardening'
            DisplayName = 'Defender browser hardening'
            Surface = 'Intune'
            Type = 'PilotBaseline'
            RequiresIncludeGroup = $true
            DefaultLaunchMode = 'DirectApply'
            SupportedLaunchModes = @('DirectApply')
            Profiles = @('AppOnlyConfirmed', 'ArmorMeUpAppOnly')
            Notes = 'Chrome hardening baseline through Intune group policy configuration.'
        }
        @{
            Sequence = 150
            TemplateKey = 'defender-endpoint-exploit-protection'
            DisplayName = 'Defender exploit protection'
            Surface = 'Intune'
            Type = 'PilotBaseline'
            RequiresIncludeGroup = $true
            DefaultLaunchMode = 'DirectApply'
            SupportedLaunchModes = @('DirectApply')
            Profiles = @('AppOnlyConfirmed', 'ArmorMeUpAppOnly')
            Notes = 'System-level exploit-protection baseline.'
        }
        @{
            Sequence = 160
            TemplateKey = 'defender-endpoint-attack-surface-reduction'
            DisplayName = 'Defender attack surface reduction'
            Surface = 'Intune'
            Type = 'PilotBaseline'
            RequiresIncludeGroup = $true
            DefaultLaunchMode = 'DirectApply'
            SupportedLaunchModes = @('DirectApply')
            Profiles = @('AppOnlyConfirmed', 'ArmorMeUpAppOnly')
            Notes = 'ASR baseline and controlled-folder-access coverage.'
        }
        @{
            Sequence = 170
            TemplateKey = 'defender-endpoint-credential-and-elevation-hardening'
            DisplayName = 'Defender credential and elevation hardening'
            Surface = 'Intune'
            Type = 'PilotBaseline'
            RequiresIncludeGroup = $true
            DefaultLaunchMode = 'DirectApply'
            SupportedLaunchModes = @('DirectApply')
            Profiles = @('AppOnlyConfirmed', 'ArmorMeUpAppOnly')
            Notes = 'Credential Guard, WDigest, UAC, and elevation hardening.'
        }
        @{
            Sequence = 180
            TemplateKey = 'defender-endpoint-remote-access-and-network-hardening'
            DisplayName = 'Defender remote access and network hardening'
            Surface = 'Intune'
            Type = 'PilotBaseline'
            RequiresIncludeGroup = $true
            DefaultLaunchMode = 'DirectApply'
            SupportedLaunchModes = @('DirectApply')
            Profiles = @('AppOnlyConfirmed', 'ArmorMeUpAppOnly')
            Notes = 'WinRM, RDP TLS, AutoPlay/AutoRun, SMBv1, and related host-network posture.'
        }
        @{
            Sequence = 190
            TemplateKey = 'defender-endpoint-os-security-baseline'
            DisplayName = 'Defender endpoint OS security baseline'
            Surface = 'Intune'
            Type = 'PilotBaseline'
            RequiresIncludeGroup = $true
            DefaultLaunchMode = 'DirectApply'
            SupportedLaunchModes = @('DirectApply')
            Profiles = @('AppOnlyConfirmed', 'ArmorMeUpAppOnly')
            Notes = 'Core local-security, SMB, and NTLMv2 posture.'
        }
        @{
            Sequence = 200
            TemplateKey = 'defender-endpoint-bitlocker-baseline'
            DisplayName = 'Defender BitLocker baseline'
            Surface = 'Intune'
            Type = 'PilotBaseline'
            RequiresIncludeGroup = $true
            DefaultLaunchMode = 'DirectApply'
            SupportedLaunchModes = @('DirectApply')
            Profiles = @('AppOnlyConfirmed', 'ArmorMeUpAppOnly')
            Notes = 'BitLocker startup baseline plus device encryption-state assessment.'
        }
        @{
            Sequence = 210
            TemplateKey = 'defender-endpoint-sensor-and-agent-health'
            DisplayName = 'Defender sensor and agent health assessment'
            Surface = 'Intune'
            Type = 'Assessment'
            RequiresIncludeGroup = $true
            DefaultLaunchMode = 'ReportOnly'
            SupportedLaunchModes = @('ReportOnly')
            Profiles = @('AssessmentOnly', 'AppOnlyConfirmed', 'ArmorMeUpAppOnly')
            Notes = 'Assessment-first validation of telemetry health and onboarding visibility in the pilot scope.'
        }
        @{
            Sequence = 220
            TemplateKey = 'defender-endpoint-browser-and-adobe-policy-surface-readiness'
            DisplayName = 'Defender browser and Adobe policy-surface readiness'
            Surface = 'Intune'
            Type = 'Assessment'
            RequiresIncludeGroup = $false
            DefaultLaunchMode = 'ReportOnly'
            SupportedLaunchModes = @('ReportOnly')
            Profiles = @('AssessmentOnly', 'AppOnlyConfirmed', 'ArmorMeUpAppOnly')
            Notes = 'Tenant readiness assessment for Chrome outdated-plugin and Adobe ADMX-backed controls.'
        }
    )
}
