using System.ComponentModel.DataAnnotations;

namespace Securityzator.Web.Models.Account;

public sealed class RegisterViewModel
{
    [Required]
    [EmailAddress]
    [Display(Name = "Operator email")]
    public string Email { get; set; } = string.Empty;

    [Required]
    [StringLength(80, MinimumLength = 2)]
    [Display(Name = "Display name")]
    public string DisplayName { get; set; } = string.Empty;

    [Required]
    [StringLength(80, MinimumLength = 2)]
    [Display(Name = "Workspace name")]
    public string WorkspaceName { get; set; } = string.Empty;

    [Required]
    [DataType(DataType.Password)]
    [StringLength(128, MinimumLength = 4)]
    public string Password { get; set; } = string.Empty;

    [Required]
    [DataType(DataType.Password)]
    [Compare(nameof(Password))]
    [Display(Name = "Confirm password")]
    public string ConfirmPassword { get; set; } = string.Empty;

    public bool RegistrationOpen { get; set; }
}
