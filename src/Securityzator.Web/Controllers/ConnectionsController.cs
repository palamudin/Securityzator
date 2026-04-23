using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Securityzator.Application.Blueprints;
using Securityzator.Application.Connections;
using Securityzator.Web.Infrastructure;
using Securityzator.Web.Models.Connections;

namespace Securityzator.Web.Controllers;

[Authorize]
public class ConnectionsController : Controller
{
    private readonly IProductBlueprintService _blueprintService;
    private readonly IAzureConnectionService _connectionService;

    public ConnectionsController(
        IProductBlueprintService blueprintService,
        IAzureConnectionService connectionService)
    {
        _blueprintService = blueprintService;
        _connectionService = connectionService;
    }

    public async Task<IActionResult> Index(CancellationToken cancellationToken)
    {
        var model = await BuildPageModelAsync(new ConnectionsPageViewModel(), cancellationToken);
        return View(model);
    }

    [HttpGet]
    public async Task<IActionResult> Edit(Guid id, CancellationToken cancellationToken)
    {
        var connection = await _connectionService.GetForOperatorAsync(id, User.GetOperatorId(), cancellationToken);

        if (connection is null)
        {
            return NotFound();
        }

        var model = await BuildPageModelAsync(
            new ConnectionsPageViewModel
            {
                Id = connection.Id,
                DisplayName = connection.DisplayName,
                TenantId = connection.TenantId,
                ClientId = connection.ClientId,
                AutomationCertificateThumbprint = connection.AutomationCertificateThumbprint,
                AutomationCertificateStoreLocation = connection.AutomationCertificateStoreLocation,
                AutomationCertificateStoreName = connection.AutomationCertificateStoreName,
                RedirectUri = connection.RedirectUri,
                SelectedLicenseCapabilities = connection.DeclaredLicenseCapabilities.ToList()
            },
            cancellationToken);

        return View("Index", model);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Save(ConnectionsPageViewModel model, CancellationToken cancellationToken)
    {
        if (!model.IsEditMode && string.IsNullOrWhiteSpace(model.ClientSecret))
        {
            ModelState.AddModelError(nameof(model.ClientSecret), "Client secret is required when creating a connection.");
        }

        if (!string.IsNullOrWhiteSpace(model.AutomationCertificateThumbprint)
            && !IsValidCertificateThumbprint(model.AutomationCertificateThumbprint))
        {
            ModelState.AddModelError(
                nameof(model.AutomationCertificateThumbprint),
                "Enter a valid certificate thumbprint using hexadecimal characters only.");
        }

        if (!ModelState.IsValid)
        {
            var invalidModel = await BuildPageModelAsync(model, cancellationToken);
            return View("Index", invalidModel);
        }

        if (model.IsEditMode)
        {
            var updated = await _connectionService.UpdateAsync(
                new UpdateAzureConnectionRequest(
                    model.Id!.Value,
                    User.GetOperatorId(),
                    model.DisplayName,
                    model.TenantId,
                    model.ClientId,
                    model.ClientSecret,
                    model.RedirectUri,
                    model.AutomationCertificateThumbprint,
                    model.AutomationCertificateStoreLocation,
                    model.AutomationCertificateStoreName,
                    model.SelectedLicenseCapabilities),
                cancellationToken);

            if (updated is null)
            {
                return NotFound();
            }

            TempData["StatusMessage"] = $"Updated connection '{updated.DisplayName}'.";
        }
        else
        {
            var created = await _connectionService.CreateAsync(
                new CreateAzureConnectionRequest(
                    User.GetOperatorId(),
                    model.DisplayName,
                    model.TenantId,
                    model.ClientId,
                    model.ClientSecret!,
                    model.RedirectUri,
                    model.AutomationCertificateThumbprint,
                    model.AutomationCertificateStoreLocation,
                    model.AutomationCertificateStoreName,
                    model.SelectedLicenseCapabilities),
                cancellationToken);

            TempData["StatusMessage"] = $"Created connection '{created.DisplayName}'.";
        }

        return RedirectToAction(nameof(Index));
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Validate(Guid connectionId, CancellationToken cancellationToken)
    {
        var outcome = await _connectionService.ValidateAsync(connectionId, User.GetOperatorId(), cancellationToken);

        if (outcome.Succeeded)
        {
            TempData["StatusMessage"] = outcome.Message;
        }
        else
        {
            TempData["ErrorMessage"] = outcome.Message;
        }

        return RedirectToAction(nameof(Index));
    }

    private async Task<ConnectionsPageViewModel> BuildPageModelAsync(
        ConnectionsPageViewModel model,
        CancellationToken cancellationToken)
    {
        var blueprint = await _blueprintService.GetPortalBlueprintAsync(cancellationToken);
        var connections = await _connectionService.ListForOperatorAsync(User.GetOperatorId(), cancellationToken);

        model.Blueprint = blueprint;
        model.OperatorDisplayName = User.Identity?.Name ?? "Operator";
        model.WorkspaceName = User.GetWorkspaceName();
        model.StatusMessage = TempData["StatusMessage"] as string;
        model.ErrorMessage = TempData["ErrorMessage"] as string;
        model.AvailableLicenseCapabilities = TenantLicenseCapabilityCatalog.All;
        model.Connections = connections
            .Select(connection => new AzureConnectionListItemViewModel
            {
                Id = connection.Id,
                DisplayName = connection.DisplayName,
                TenantId = connection.TenantId,
                ClientId = connection.ClientId,
                RedirectUri = connection.RedirectUri,
                HasStoredSecret = connection.HasStoredSecret,
                AutomationCertificateThumbprint = connection.AutomationCertificateThumbprint,
                AutomationCertificateStoreLocation = connection.AutomationCertificateStoreLocation,
                AutomationCertificateStoreName = connection.AutomationCertificateStoreName,
                AutomationCertificateStatus = connection.AutomationCertificateStatus,
                AutomationCertificateSubject = connection.AutomationCertificateSubject,
                AutomationCertificateExpiresUtc = connection.AutomationCertificateExpiresUtc,
                AutomationCertificateMessage = connection.AutomationCertificateMessage,
                UpdatedUtc = connection.UpdatedUtc,
                SecretUpdatedUtc = connection.SecretUpdatedUtc,
                ValidationStatus = connection.ValidationStatus,
                LastValidationAttemptUtc = connection.LastValidationAttemptUtc,
                LastValidationSuccessUtc = connection.LastValidationSuccessUtc,
                LastValidationError = connection.LastValidationError,
                CanReadGroups = connection.CanReadGroups,
                CanReadConditionalAccess = connection.CanReadConditionalAccess,
                CanReadRecommendations = connection.CanReadRecommendations,
                CanReadManagedDevices = connection.CanReadManagedDevices,
                CanReadIntuneDeviceConfigurations = connection.CanReadIntuneDeviceConfigurations,
                CanReadIntuneCompliancePolicies = connection.CanReadIntuneCompliancePolicies,
                IntuneEnrolledDeviceCount = connection.IntuneEnrolledDeviceCount,
                HasIntuneDeviceConfigurations = connection.HasIntuneDeviceConfigurations,
                HasIntuneCompliancePolicies = connection.HasIntuneCompliancePolicies,
                IntuneAutomationMessage = connection.IntuneAutomationMessage,
                CanManageEntraDailyUseHardening = connection.CanManageEntraDailyUseHardening,
                EntraDailyUseAutomationMessage = connection.EntraDailyUseAutomationMessage,
                CanManageTeamsMeetingPolicy = connection.CanManageTeamsMeetingPolicy,
                TeamsAutomationMessage = connection.TeamsAutomationMessage,
                DeclaredLicenseCapabilities = connection.DeclaredLicenseCapabilities,
                DeclaredLicenseCapabilityLabels = TenantLicenseCapabilityCatalog.ResolveLabels(connection.DeclaredLicenseCapabilities)
            })
            .ToArray();

        return model;
    }

    private static bool IsValidCertificateThumbprint(string value)
    {
        var normalized = new string(value.Where(static character => !char.IsWhiteSpace(character)).ToArray());

        return normalized.Length is >= 40 and <= 128
               && normalized.All(Uri.IsHexDigit);
    }
}
