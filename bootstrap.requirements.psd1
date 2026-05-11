@{
    Metadata = @{
        SourceMapPath     = 'graph.source-map.psd1'
        CanonicalDocsRepo = 'https://github.com/microsoftgraph/microsoft-graph-docs-contrib'
        MetadataRepo      = 'https://github.com/microsoftgraph/msgraph-metadata'
        PowerShellSdkRepo = 'https://github.com/microsoftgraph/msgraph-sdk-powershell'
        Notes             = @(
            'Treat this manifest as the curated bootstrap subset derived from graph.source-map.psd1.',
            'Use docs-contrib for permissions and endpoint contracts, metadata for schema permanence, and the PowerShell SDK repo for examples only.'
        )
    }

    Modules = @(
        @{
            Name    = 'ExchangeOnlineManagement'
            Feature = 'exchange'
        },
        @{
            Name    = 'MicrosoftTeams'
            Feature = 'teams'
        },
        @{
            Name    = 'Microsoft.Graph.Authentication'
            Feature = 'graph-bootstrap'
        }
    )

    Profiles = @{
        Current = @{
            AppPermissions = @(
                @{
                    ResourceAppId      = '00000003-0000-0000-c000-000000000000'
                    ResourceDisplayName = 'Microsoft Graph'
                    Value              = 'Application.Read.All'
                    Feature            = 'base'
                },
                @{
                    ResourceAppId      = '00000003-0000-0000-c000-000000000000'
                    ResourceDisplayName = 'Microsoft Graph'
                    Value              = 'DeviceManagementConfiguration.Read.All'
                    Feature            = 'base'
                },
                @{
                    ResourceAppId      = '00000003-0000-0000-c000-000000000000'
                    ResourceDisplayName = 'Microsoft Graph'
                    Value              = 'DeviceManagementConfiguration.ReadWrite.All'
                    Feature            = 'base'
                },
                @{
                    ResourceAppId      = '00000003-0000-0000-c000-000000000000'
                    ResourceDisplayName = 'Microsoft Graph'
                    Value              = 'DeviceManagementManagedDevices.Read.All'
                    Feature            = 'base'
                },
                @{
                    ResourceAppId      = '00000003-0000-0000-c000-000000000000'
                    ResourceDisplayName = 'Microsoft Graph'
                    Value              = 'Directory.Read.All'
                    Feature            = 'base'
                },
                @{
                    ResourceAppId      = '00000003-0000-0000-c000-000000000000'
                    ResourceDisplayName = 'Microsoft Graph'
                    Value              = 'Domain.ReadWrite.All'
                    Feature            = 'base'
                },
                @{
                    ResourceAppId      = '00000003-0000-0000-c000-000000000000'
                    ResourceDisplayName = 'Microsoft Graph'
                    Value              = 'Group.Read.All'
                    Feature            = 'base'
                },
                @{
                    ResourceAppId      = '00000003-0000-0000-c000-000000000000'
                    ResourceDisplayName = 'Microsoft Graph'
                    Value              = 'Organization.Read.All'
                    Feature            = 'teams'
                },
                @{
                    ResourceAppId      = '00000003-0000-0000-c000-000000000000'
                    ResourceDisplayName = 'Microsoft Graph'
                    Value              = 'Policy.Read.All'
                    Feature            = 'base'
                },
                @{
                    ResourceAppId      = '00000003-0000-0000-c000-000000000000'
                    ResourceDisplayName = 'Microsoft Graph'
                    Value              = 'Policy.ReadWrite.Authorization'
                    Feature            = 'base'
                },
                @{
                    ResourceAppId      = '00000003-0000-0000-c000-000000000000'
                    ResourceDisplayName = 'Microsoft Graph'
                    Value              = 'Policy.ReadWrite.ConsentRequest'
                    Feature            = 'base'
                },
                @{
                    ResourceAppId      = '00000003-0000-0000-c000-000000000000'
                    ResourceDisplayName = 'Microsoft Graph'
                    Value              = 'Policy.ReadWrite.ConditionalAccess'
                    Feature            = 'base'
                },
                @{
                    ResourceAppId      = '00000003-0000-0000-c000-000000000000'
                    ResourceDisplayName = 'Microsoft Graph'
                    Value              = 'SecurityEvents.Read.All'
                    Feature            = 'base'
                },
                @{
                    ResourceAppId      = '00000002-0000-0ff1-ce00-000000000000'
                    ResourceDisplayName = 'Office 365 Exchange Online'
                    Value              = 'Exchange.ManageAsApp'
                    Feature            = 'exchange'
                }
            )

            DirectoryRoles = @(
                @{
                    Value   = 'Exchange Administrator'
                    Feature = 'exchange'
                },
                @{
                    Value   = 'Teams Administrator'
                    Feature = 'teams'
                }
            )
        }

        Roadmap = @{
            AppPermissions = @(
                @{
                    ResourceAppId      = '00000003-0000-0000-c000-000000000000'
                    ResourceDisplayName = 'Microsoft Graph'
                    Value              = 'Application.Read.All'
                    Feature            = 'base'
                },
                @{
                    ResourceAppId      = '00000003-0000-0000-c000-000000000000'
                    ResourceDisplayName = 'Microsoft Graph'
                    Value              = 'Device.ReadWrite.All'
                    Feature            = 'base'
                },
                @{
                    ResourceAppId      = '00000003-0000-0000-c000-000000000000'
                    ResourceDisplayName = 'Microsoft Graph'
                    Value              = 'DeviceManagementConfiguration.Read.All'
                    Feature            = 'base'
                },
                @{
                    ResourceAppId      = '00000003-0000-0000-c000-000000000000'
                    ResourceDisplayName = 'Microsoft Graph'
                    Value              = 'DeviceManagementConfiguration.ReadWrite.All'
                    Feature            = 'base'
                },
                @{
                    ResourceAppId      = '00000003-0000-0000-c000-000000000000'
                    ResourceDisplayName = 'Microsoft Graph'
                    Value              = 'DeviceManagementManagedDevices.Read.All'
                    Feature            = 'base'
                },
                @{
                    ResourceAppId      = '00000003-0000-0000-c000-000000000000'
                    ResourceDisplayName = 'Microsoft Graph'
                    Value              = 'Directory.Read.All'
                    Feature            = 'base'
                },
                @{
                    ResourceAppId      = '00000003-0000-0000-c000-000000000000'
                    ResourceDisplayName = 'Microsoft Graph'
                    Value              = 'Directory.ReadWrite.All'
                    Feature            = 'base'
                },
                @{
                    ResourceAppId      = '00000003-0000-0000-c000-000000000000'
                    ResourceDisplayName = 'Microsoft Graph'
                    Value              = 'Group.Read.All'
                    Feature            = 'base'
                },
                @{
                    ResourceAppId      = '00000003-0000-0000-c000-000000000000'
                    ResourceDisplayName = 'Microsoft Graph'
                    Value              = 'Group.ReadWrite.All'
                    Feature            = 'base'
                },
                @{
                    ResourceAppId      = '00000003-0000-0000-c000-000000000000'
                    ResourceDisplayName = 'Microsoft Graph'
                    Value              = 'Organization.Read.All'
                    Feature            = 'teams'
                },
                @{
                    ResourceAppId      = '00000003-0000-0000-c000-000000000000'
                    ResourceDisplayName = 'Microsoft Graph'
                    Value              = 'Policy.Read.All'
                    Feature            = 'base'
                },
                @{
                    ResourceAppId      = '00000003-0000-0000-c000-000000000000'
                    ResourceDisplayName = 'Microsoft Graph'
                    Value              = 'Policy.ReadWrite.Authorization'
                    Feature            = 'base'
                },
                @{
                    ResourceAppId      = '00000003-0000-0000-c000-000000000000'
                    ResourceDisplayName = 'Microsoft Graph'
                    Value              = 'Policy.ReadWrite.ConsentRequest'
                    Feature            = 'base'
                },
                @{
                    ResourceAppId      = '00000003-0000-0000-c000-000000000000'
                    ResourceDisplayName = 'Microsoft Graph'
                    Value              = 'Policy.ReadWrite.ConditionalAccess'
                    Feature            = 'base'
                },
                @{
                    ResourceAppId      = '00000003-0000-0000-c000-000000000000'
                    ResourceDisplayName = 'Microsoft Graph'
                    Value              = 'Domain.ReadWrite.All'
                    Feature            = 'base'
                },
                @{
                    ResourceAppId      = '00000003-0000-0000-c000-000000000000'
                    ResourceDisplayName = 'Microsoft Graph'
                    Value              = 'SecurityAlert.ReadWrite.All'
                    Feature            = 'base'
                },
                @{
                    ResourceAppId      = '00000003-0000-0000-c000-000000000000'
                    ResourceDisplayName = 'Microsoft Graph'
                    Value              = 'SecurityEvents.Read.All'
                    Feature            = 'base'
                },
                @{
                    ResourceAppId      = '00000003-0000-0000-c000-000000000000'
                    ResourceDisplayName = 'Microsoft Graph'
                    Value              = 'User.ReadWrite.All'
                    Feature            = 'base'
                },
                @{
                    ResourceAppId      = '00000002-0000-0ff1-ce00-000000000000'
                    ResourceDisplayName = 'Office 365 Exchange Online'
                    Value              = 'Exchange.ManageAsApp'
                    Feature            = 'exchange'
                }
            )

            DirectoryRoles = @(
                @{
                    Value   = 'Exchange Administrator'
                    Feature = 'exchange'
                },
                @{
                    Value   = 'Teams Administrator'
                    Feature = 'teams'
                }
            )
        }
    }
}
