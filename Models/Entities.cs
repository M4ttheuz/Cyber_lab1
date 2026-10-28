using System.ComponentModel.DataAnnotations;

namespace Cyber_lab1.Models;

public class User
{
    public int Id { get; set; }
    public string Username { get; set; } = string.Empty;
    public string PasswordHash { get; set; } = string.Empty;
    public string Role { get; set; } = "Czytelnik";
    public bool IsBlocked { get; set; } = false;
    public bool MustChangePassword { get; set; } = false;
    public DateTime PasswordSetAt { get; set; } = DateTime.UtcNow;

    public bool IsOtp { get; set; } = false;
    public DateTime? OtpExpiresAt { get; set; }
}

public class PasswordHistory
{
    public int Id { get; set; }
    public int UserId { get; set; }
    public string PasswordHash { get; set; } = string.Empty;
}

public class ForbiddenWord
{
    public int Id { get; set; }
    public string Word { get; set; } = string.Empty;
}

public class SystemSettings
{
    public int Id { get; set; }
    public int MinPasswordLength { get; set; } = 14;
    public bool EnforceForbiddenWords { get; set; } = true;
    public int PasswordValidityDays { get; set; } = 30;
    public int SessionTimeoutMinutes { get; set; } = 15;
}