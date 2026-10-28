using System.Security.Claims;
using Cyber_lab1.Data;
using Cyber_lab1.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace Cyber_lab1.Controllers;

public class AccountController : Controller
{
    private readonly AppDbContext _db;
    public AccountController(AppDbContext db) => _db = db;

    [HttpGet]
    public IActionResult Login() => View();

    [HttpPost]
    public async Task<IActionResult> Login(string username, string password)
    {
        var user = await _db.Users.FirstOrDefaultAsync(u => u.Username == username);

        if (user == null || !BCrypt.Net.BCrypt.Verify(password, user.PasswordHash))
        {
            ViewBag.Error = "Login lub hasło niepoprawne";
            return View();
        }

        if (user.IsBlocked)
        {
            ViewBag.Error = "Konto jest zablokowane.";
            return View();
        }

        if (user.IsOtp && user.OtpExpiresAt < DateTime.UtcNow)
        {
            ViewBag.Error = "Hasło jednorazowe wygasło (minęło 12h).";
            return View();
        }

        var settings = await _db.Settings.FirstAsync();

        if ((DateTime.UtcNow - user.PasswordSetAt).TotalDays > settings.PasswordValidityDays)
        {
            user.MustChangePassword = true;
            await _db.SaveChangesAsync();
        }

        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new(ClaimTypes.Name, user.Username),
            new(ClaimTypes.Role, user.Role)
        };

        var props = new AuthenticationProperties
        {
            IsPersistent = false,
            ExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(settings.SessionTimeoutMinutes),
            AllowRefresh = true
        };

        await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme,
            new ClaimsPrincipal(new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme)), props);

        if (user.MustChangePassword)
            return RedirectToAction("ChangePassword", new { firstLogin = true });

        return RedirectToAction("Index", "Home");
    }

    [Authorize]
    [HttpGet]
    public IActionResult ChangePassword(bool firstLogin = false)
    {
        ViewBag.FirstLogin = firstLogin;
        return View();
    }

    [Authorize]
    [HttpPost]
    public async Task<IActionResult> ChangePassword(string? oldPassword, string newPassword, string confirmPassword, bool firstLogin)
    {
        ViewBag.FirstLogin = firstLogin;
        int userId = int.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
        var user = await _db.Users.FindAsync(userId);

        if (!firstLogin && (string.IsNullOrEmpty(oldPassword) || !BCrypt.Net.BCrypt.Verify(oldPassword, user!.PasswordHash)))
        {
            ViewBag.Error = "Stare hasło jest niepoprawne.";
            return View();
        }

        if (newPassword != confirmPassword)
        {
            ViewBag.Error = "Nowe hasła nie są identyczne.";
            return View();
        }

        var settings = await _db.Settings.FirstAsync();
        if (newPassword.Length < settings.MinPasswordLength)
        {
            ViewBag.Error = $"Hasło musi mieć min. {settings.MinPasswordLength} znaków.";
            return View();
        }

        if (settings.EnforceForbiddenWords)
        {
            var words = await _db.ForbiddenWords.Select(w => w.Word).ToListAsync();
            foreach (var w in words)
            {
                if (newPassword.Contains(w, StringComparison.OrdinalIgnoreCase))
                {
                    ViewBag.Error = $"Hasło zawiera zakazane słowo: {w}";
                    return View();
                }
            }
        }

        var history = await _db.PasswordHistories.Where(h => h.UserId == userId).ToListAsync();
        if (history.Any(h => BCrypt.Net.BCrypt.Verify(newPassword, h.PasswordHash)))
        {
            ViewBag.Error = "Hasło było już wcześniej używane.";
            return View();
        }

        string newHash = BCrypt.Net.BCrypt.HashPassword(newPassword);
        user!.PasswordHash = newHash;
        user.MustChangePassword = false;
        user.IsOtp = false;
        user.PasswordSetAt = DateTime.UtcNow;

        _db.PasswordHistories.Add(new PasswordHistory { UserId = userId, PasswordHash = newHash });
        await _db.SaveChangesAsync();

        TempData["Msg"] = "Hasło zostało zmienione.";
        return RedirectToAction("Index", "Home");
    }

    public async Task<IActionResult> Logout()
    {
        await HttpContext.SignOutAsync();
        return RedirectToAction("Login");
    }

    public IActionResult AccessDenied()
    {
        Response.StatusCode = 403;
        return View();
    }
}