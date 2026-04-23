@{
    CanonicalSources = @{
        Organization = 'https://github.com/microsoftgraph'

        Documentation = @{
            Repository = 'https://github.com/microsoftgraph/microsoft-graph-docs-contrib'
            Purpose    = 'Canonical endpoint documentation, permissions guidance, and ongoing permissions-reference maintenance.'
            Notes      = @(
                'The docs repo root exposes update-permissions-reference.ps1 and correct-permissions-reference-errors.ps1.',
                'Use this repo as the primary source for endpoint-level permission and role guidance.'
            )
        }

        Metadata = @{
            Repository = 'https://github.com/microsoftgraph/msgraph-metadata'
            Purpose    = 'Canonical OpenAPI and metadata snapshots used to generate SDKs.'
            Notes      = @(
                'Use this repo to validate resource paths, schema drift, and stable endpoint existence.',
                'Prefer metadata and OpenAPI validation for long-lived Securityzator automation maps.'
            )
        }

        PowerShellSdk = @{
            Repository = 'https://github.com/microsoftgraph/msgraph-sdk-powershell'
            Purpose    = 'SDK implementation details, module packaging, and command examples.'
            Notes      = @(
                'Useful for operator ergonomics and examples.',
                'Not the canonical source for Securityzator bootstrap-critical behavior when REST and SDK diverge.'
            )
        }
    }

    PermanentMapRules = @(
        'Use microsoft-graph-docs-contrib as the source of truth for endpoint permissions and documented request/response contracts.',
        'Use msgraph-metadata as the source of truth for long-term schema and path validation.',
        'Keep local manifests such as bootstrap.requirements.psd1 aligned to those sources instead of hand-maintained one-off notes.',
        'Prefer direct REST for bootstrap-critical flows when the SDK has known behavioral or schema inconsistencies.'
    )

    Bootstrap = @{
        RequirementsManifest = 'bootstrap.requirements.psd1'
        RequirementsDocument = 'requirements.txt'

        AppPermissions = @{
            CanonicalRepo = 'https://github.com/microsoftgraph/microsoft-graph-docs-contrib'
            LocalManifest = 'bootstrap.requirements.psd1'
            SyncRule      = 'Treat the local manifest as a curated subset derived from docs-contrib, with Current and Roadmap profiles.'
        }

        ServicePrincipalAppRoleAssignments = @{
            ListAssignedToDocs = 'https://github.com/microsoftgraph/microsoft-graph-docs-contrib/blob/main/api-reference/v1.0/api/serviceprincipal-list-approleassignedto.md'
            CreateAssignmentDocs = 'https://github.com/microsoftgraph/microsoft-graph-docs-contrib/blob/main/api-reference/beta/api/serviceprincipal-post-approleassignments.md'
            LocalRule = 'Validate by resourceId and appRoleId; assign through REST and treat duplicate-assignment 400 responses as Present.'
        }

        DirectoryRoleAssignments = @{
            ListDocs   = 'https://github.com/microsoftgraph/microsoft-graph-docs-contrib/blob/main/api-reference/v1.0/api/rbacapplication-list-roleassignments.md'
            LocalRule  = 'Validate directory roles through roleManagement/directory/roleAssignments filtered by principalId and roleDefinitionId.'
        }

        ConditionalAccess = @{
            CreatePolicyDocs = 'https://github.com/microsoftgraph/microsoft-graph-docs-contrib/blob/main/api-reference/v1.0/api/conditionalaccessroot-post-policies.md'
            LocalRule        = 'Keep REST fallback available for Conditional Access bootstrapping and policy cloning.'
        }

        SecureScore = @{
            ControlProfilesDocs = 'https://github.com/microsoftgraph/microsoft-graph-docs-contrib/blob/main/api-reference/v1.0/api/security-list-securescorecontrolprofiles.md'
            MetadataRepo        = 'https://github.com/microsoftgraph/msgraph-metadata'
            LocalRule           = 'Use docs-contrib for permissions and endpoint behavior, and metadata/OpenAPI snapshots for schema permanence.'
        }

        ControlCatalog = @{
            ManifestPath = 'control-catalog.map.psd1'
            LocalRule    = 'Freeze the surfaced recommendation catalog and extended template families in a validator-backed manifest so routing drift is explicit.'
        }
    }

    BootstrapProfiles = @{
        Current = @{
            AppPermissions = @(
                @{
                    ResourceAppId = '00000003-0000-0000-c000-000000000000'
                    Value         = 'Application.Read.All'
                    Feature       = 'base'
                },
                @{
                    ResourceAppId = '00000003-0000-0000-c000-000000000000'
                    Value         = 'Group.Read.All'
                    Feature       = 'base'
                },
                @{
                    ResourceAppId = '00000003-0000-0000-c000-000000000000'
                    Value         = 'Organization.Read.All'
                    Feature       = 'teams'
                },
                @{
                    ResourceAppId = '00000003-0000-0000-c000-000000000000'
                    Value         = 'Policy.Read.All'
                    Feature       = 'base'
                },
                @{
                    ResourceAppId = '00000003-0000-0000-c000-000000000000'
                    Value         = 'Policy.ReadWrite.ConditionalAccess'
                    Feature       = 'base'
                },
                @{
                    ResourceAppId = '00000003-0000-0000-c000-000000000000'
                    Value         = 'SecurityEvents.Read.All'
                    Feature       = 'base'
                },
                @{
                    ResourceAppId = '00000002-0000-0ff1-ce00-000000000000'
                    Value         = 'Exchange.ManageAsApp'
                    Feature       = 'exchange'
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
                    ResourceAppId = '00000003-0000-0000-c000-000000000000'
                    Value         = 'Application.Read.All'
                    Feature       = 'base'
                },
                @{
                    ResourceAppId = '00000003-0000-0000-c000-000000000000'
                    Value         = 'Device.ReadWrite.All'
                    Feature       = 'base'
                },
                @{
                    ResourceAppId = '00000003-0000-0000-c000-000000000000'
                    Value         = 'Directory.Read.All'
                    Feature       = 'base'
                },
                @{
                    ResourceAppId = '00000003-0000-0000-c000-000000000000'
                    Value         = 'Directory.ReadWrite.All'
                    Feature       = 'base'
                },
                @{
                    ResourceAppId = '00000003-0000-0000-c000-000000000000'
                    Value         = 'Group.Read.All'
                    Feature       = 'base'
                },
                @{
                    ResourceAppId = '00000003-0000-0000-c000-000000000000'
                    Value         = 'Group.ReadWrite.All'
                    Feature       = 'base'
                },
                @{
                    ResourceAppId = '00000003-0000-0000-c000-000000000000'
                    Value         = 'Organization.Read.All'
                    Feature       = 'teams'
                },
                @{
                    ResourceAppId = '00000003-0000-0000-c000-000000000000'
                    Value         = 'Policy.Read.All'
                    Feature       = 'base'
                },
                @{
                    ResourceAppId = '00000003-0000-0000-c000-000000000000'
                    Value         = 'Policy.ReadWrite.ConditionalAccess'
                    Feature       = 'base'
                },
                @{
                    ResourceAppId = '00000003-0000-0000-c000-000000000000'
                    Value         = 'SecurityAlert.ReadWrite.All'
                    Feature       = 'base'
                },
                @{
                    ResourceAppId = '00000003-0000-0000-c000-000000000000'
                    Value         = 'SecurityEvents.Read.All'
                    Feature       = 'base'
                },
                @{
                    ResourceAppId = '00000003-0000-0000-c000-000000000000'
                    Value         = 'User.ReadWrite.All'
                    Feature       = 'base'
                },
                @{
                    ResourceAppId = '00000002-0000-0ff1-ce00-000000000000'
                    Value         = 'Exchange.ManageAsApp'
                    Feature       = 'exchange'
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

    SdkCaveats = @(
        @{
            Repository = 'https://github.com/microsoftgraph/msgraph-sdk-powershell/issues/3027'
            Note       = 'App role assignment values can be missing in SDK output even when the REST endpoint returns them.'
            LocalRule  = 'For bootstrap validation of app role assignments, prefer REST.'
        },
        @{
            Repository = 'https://github.com/microsoftgraph/msgraph-sdk-powershell/issues/3089'
            Note       = 'Conditional Access schema mismatches have been reported in SDK-driven create flows.'
            LocalRule  = 'Keep Conditional Access create/update flows REST-capable.'
        }
    )
}
