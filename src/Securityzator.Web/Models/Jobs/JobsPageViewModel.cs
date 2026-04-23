using Securityzator.Application.Blueprints;
using Securityzator.Application.Jobs;
using Securityzator.Application.Recommendations;
using Securityzator.Application.Remediations;
using Securityzator.Application.Workers;

namespace Securityzator.Web.Models.Jobs;

public sealed class JobsPageViewModel
{
    public required PortalBlueprint Blueprint { get; set; }

    public required string WorkspaceName { get; set; }

    public required IReadOnlyList<RemediationJobRecord> Jobs { get; set; }

    public required IReadOnlyList<RemediationRunRecord> Runs { get; set; }

    public required IReadOnlyList<WorkerAgentRecord> Workers { get; set; }

    public required IReadOnlyList<RecommendationCoverageSummary> RecommendationCoverageSummaries { get; set; }
}
