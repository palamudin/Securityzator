using System.ComponentModel.DataAnnotations;

namespace Securityzator.Web.Models.Account;

public sealed class LoginViewModel
{
    [Required]
    [EmailAddress]
    [Display(Name = "Operator email")]
    public string Email { get; set; } = string.Empty;

    [Required]
    [DataType(DataType.Password)]
    public string Password { get; set; } = string.Empty;

    [Display(Name = "Remember me on this browser")]
    public bool RememberMe { get; set; }

    public string? ReturnUrl { get; set; }

    public bool RegistrationOpen { get; set; }
}
