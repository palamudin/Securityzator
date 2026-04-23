using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Mvc.ModelBinding.Validation;
using Securityzator.Application.Blueprints;
using Securityzator.Application.Jobs;
using Securityzator.Application.Portal;
using Securityzator.Application.Recommendations;
using Securityzator.Application.Remediations;

namespace Securityzator.Web.Models.Remediations;

public sealed class RemediationsPageViewModel
{
    private const string GuidPattern = "^[0-9a-fA-F]{8}\\-[0-9a-fA-F]{4}\\-[0-9a-fA-F]{4}\\-[0-9a-fA-F]{4}\\-[0-9a-fA-F]{12}$";

    [ValidateNever]
    public required PortalBlueprint Blueprint { get; set; }

    [ValidateNever]
    public required string OperatorDisplayName { get; set; }

    [ValidateNever]
    public required string WorkspaceName { get; set; }

    [ValidateNever]
    public IReadOnlyList<RemediationConnectionOptionViewModel> Connections { get; set; } =
        Array.Empty<RemediationConnectionOptionViewModel>();

    [ValidateNever]
    public IReadOnlyList<DirectoryGroupEntry> AvailableGroups { get; set; } = Array.Empty<DirectoryGroupEntry>();

    [ValidateNever]
    public IReadOnlyList<RemediationJobRecord> RecentJobs { get; set; } = Array.Empty<RemediationJobRecord>();

    [ValidateNever]
    public IReadOnlyList<RemediationRunRecord> RecentRuns { get; set; } = Array.Empty<RemediationRunRecord>();

    [ValidateNever]
    public string? StatusMessage { get; set; }

    [ValidateNever]
    public string? ErrorMessage { get; set; }

    [ValidateNever]
    public required RemediationTemplate SelectedTemplate { get; set; }

    [ValidateNever]
    public RecommendationRecord? SourceRecommendation { get; set; }

    [ValidateNever]
    public string TemplateKey { get; set; } = "block-legacy-auth";

    [ValidateNever]
    public string? SourceControlId { get; set; }

    [Display(Name = "Azure connection")]
    [Required(ErrorMessage = "Select the Azure connection that should execute this quick win.")]
    public Guid? ConnectionId { get; set; }

    [Display(Name = "Include group")]
    public string IncludeGroupId { get; set; } = string.Empty;

    [Display(Name = "Exclude group")]
    [RegularExpression(GuidPattern, ErrorMessage = "Select a valid group object ID.")]
    public string? ExcludeGroupId { get; set; }

    [Display(Name = "Launch mode")]
    public RemediationLaunchMode LaunchMode { get; set; } = RemediationLaunchMode.ReportOnly;

    [Required]
    [StringLength(240, MinimumLength = 12)]
    [Display(Name = "Approval justification")]
    public string ApprovalJustification { get; set; } = string.Empty;

    [Display(Name = "Report-only confirmed")]
    public bool ConfirmReportOnly { get; set; }

    [Display(Name = "Group review confirmed")]
    public bool ConfirmGroupReview { get; set; }

    [Display(Name = "Enabled change confirmed")]
    public bool ConfirmEnabledChange { get; set; }

    [ValidateNever]
    public bool HasConnections => Connections.Count > 0;

    [ValidateNever]
    public bool HasSelectedConnection => ConnectionId.HasValue;

    [ValidateNever]
    public bool HasAvailableGroups => AvailableGroups.Count > 0;

    [ValidateNever]
    public bool HasSourceRecommendation => SourceRecommendation is not null;

    [ValidateNever]
    public bool RequiresIncludeGroup => SelectedTemplate.Targeting.SupportsIncludeGroupSelection;

    [ValidateNever]
    public bool SupportsExcludeGroup => SelectedTemplate.Targeting.SupportsExcludeGroupSelection;

    [ValidateNever]
    public bool SupportsLaunchModeSelection => SelectedTemplate.SupportsLaunchModeSelection;

    [ValidateNever]
    public bool RequiresReportOnlyConfirmation =>
        SupportsLaunchModeSelection && LaunchMode == RemediationLaunchMode.ReportOnly;

    [ValidateNever]
    public bool RequiresLiveChangeConfirmation =>
        !SupportsLaunchModeSelection && SelectedTemplate.DefaultLaunchMode == RemediationLaunchMode.DirectApply;

    [ValidateNever]
    public bool RequiresEnabledChangeConfirmation =>
        SupportsLaunchModeSelection && LaunchMode == RemediationLaunchMode.Enabled;

    [ValidateNever]
    public bool RequiresGroupReviewConfirmation =>
        RequiresIncludeGroup || SupportsExcludeGroup;

    [ValidateNever]
    public bool UsesTenantGroups => RequiresIncludeGroup || SupportsExcludeGroup;

    [ValidateNever]
    public bool CanQueueWithoutTenantGroups => !UsesTenantGroups;

    [ValidateNever]
    public RemediationLaunchMode EffectiveLaunchMode =>
        SupportsLaunchModeSelection
            ? LaunchMode
            : SelectedTemplate.DefaultLaunchMode;
}
