using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Securityzator.Application.Accounts;
using Securityzator.Web.Models.Account;

namespace Securityzator.Web.Controllers;

public class AccountController : Controller
{
    private readonly IOperatorAccountService _operatorAccountService;

    public AccountController(IOperatorAccountService operatorAccountService)
    {
        _operatorAccountService = operatorAccountService;
    }

    [AllowAnonymous]
    [HttpGet]
    public async Task<IActionResult> Login(string? returnUrl, CancellationToken cancellationToken)
    {
        if (User.Identity?.IsAuthenticated == true)
        {
            return RedirectToLocal(returnUrl);
        }

        var model = new LoginViewModel
        {
            ReturnUrl = returnUrl,
            RegistrationOpen = !await _operatorAccountService.HasOperatorsAsync(cancellationToken)
        };

        return View(model);
    }

    [AllowAnonymous]
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Login(LoginViewModel model, CancellationToken cancellationToken)
    {
        model.RegistrationOpen = !await _operatorAccountService.HasOperatorsAsync(cancellationToken);

        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var authenticatedOperator = await _operatorAccountService.AuthenticateAsync(
            model.Email,
            model.Password,
            cancellationToken);

        if (authenticatedOperator is null)
        {
            ModelState.AddModelError(
                string.Empty,
                model.RegistrationOpen
                    ? "We couldn't sign you in. If this is the first setup, create the initial operator account instead."
                    : "We couldn't sign you in with those credentials.");

            return View(model);
        }

        await SignInOperatorAsync(authenticatedOperator, model.RememberMe);
        return RedirectToLocal(model.ReturnUrl);
    }

    [AllowAnonymous]
    [HttpGet]
    public async Task<IActionResult> Register(CancellationToken cancellationToken)
    {
        if (User.Identity?.IsAuthenticated == true)
        {
            return RedirectToAction("Index", "Home");
        }

        var registrationOpen = !await _operatorAccountService.HasOperatorsAsync(cancellationToken);

        if (!registrationOpen)
        {
            return RedirectToAction(nameof(Login));
        }

        return View(new RegisterViewModel { RegistrationOpen = true });
    }

    [AllowAnonymous]
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Register(RegisterViewModel model, CancellationToken cancellationToken)
    {
        model.RegistrationOpen = !await _operatorAccountService.HasOperatorsAsync(cancellationToken);

        if (!model.RegistrationOpen)
        {
            ModelState.AddModelError(string.Empty, "Initial registration is already complete. Sign in instead.");
        }

        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var outcome = await _operatorAccountService.RegisterInitialOperatorAsync(
            new RegisterOperatorRequest(
                model.Email,
                model.DisplayName,
                model.WorkspaceName,
                model.Password),
            cancellationToken);

        if (!outcome.Succeeded || outcome.Operator is null)
        {
            ModelState.AddModelError(
                string.Empty,
                outcome.ErrorMessage ?? "We couldn't create the initial operator account.");
            return View(model);
        }

        await SignInOperatorAsync(outcome.Operator, rememberMe: true);
        return RedirectToAction("Index", "Home");
    }

    [Authorize]
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Logout()
    {
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        return RedirectToAction(nameof(Login));
    }

    private async Task SignInOperatorAsync(AuthenticatedOperator authenticatedOperator, bool rememberMe)
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, authenticatedOperator.Id.ToString()),
            new(ClaimTypes.Name, authenticatedOperator.DisplayName),
            new(ClaimTypes.Email, authenticatedOperator.Email),
            new(ClaimTypes.Role, authenticatedOperator.Role),
            new("workspace", authenticatedOperator.WorkspaceName)
        };

        var principal = new ClaimsPrincipal(
            new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme));

        await HttpContext.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            principal,
            new AuthenticationProperties
            {
                IsPersistent = rememberMe,
                AllowRefresh = true
            });
    }

    private IActionResult RedirectToLocal(string? returnUrl)
    {
        if (!string.IsNullOrWhiteSpace(returnUrl) && Url.IsLocalUrl(returnUrl))
        {
            return Redirect(returnUrl);
        }

        return RedirectToAction("Index", "Home");
    }
}
