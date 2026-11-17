using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
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
    private readonly IHttpClientFactory _httpFactory;
    private readonly IConfiguration _config;

    private static readonly Dictionary<string, string[]> Categories = new()
    {
        ["Zwierzęta"] = new[] { "pies", "kot", "koń", "krowa", "wilk", "lis" },
        ["Owoce"] = new[] { "jabłko", "banan", "gruszka", "śliwka", "arbuz", "cytryna" },
        ["Pojazdy"] = new[] { "rower", "samochód", "pociąg", "autobus", "tramwaj", "motocykl" },
        ["Meble"] = new[] { "krzesło", "stół", "szafa", "łóżko", "biurko", "fotel" }
    };

    public AccountController(AppDbContext db, IHttpClientFactory httpFactory, IConfiguration config)
    {
        _db = db;
        _httpFactory = httpFactory;
        _config = config;
    }

    private void GenerateCaptcha()
    {
        var keys = Categories.Keys.ToList();
        int mainIdx = RandomNumberGenerator.GetInt32(keys.Count);
        int oddIdx;
        do
        {
            oddIdx = RandomNumberGenerator.GetInt32(keys.Count);
        } while (oddIdx == mainIdx);

        var mainWords = Categories[keys[mainIdx]]
            .OrderBy(_ => RandomNumberGenerator.GetInt32(1000))
            .Take(3)
            .ToList();

        var oddPool = Categories[keys[oddIdx]];
        string oddWord = oddPool[RandomNumberGenerator.GetInt32(oddPool.Length)];

        var allWords = new List<string>(mainWords) { oddWord }
            .OrderBy(_ => RandomNumberGenerator.GetInt32(1000))
            .ToList();

        HttpContext.Session.SetString("CaptchaAnswer", oddWord);
        HttpContext.Session.SetString("CaptchaExpires", DateTime.UtcNow.AddMinutes(2).ToString("O"));

        ViewBag.CaptchaWords = allWords;
    }

    [HttpGet]
    public IActionResult Login()
    {
        GenerateCaptcha();
        return View();
    }

    [HttpPost]
    public async Task<IActionResult> Login(string username, string password, string? captchaAnswer, string? website)
    {
        if (!string.IsNullOrEmpty(website))
        {
            GenerateCaptcha();
            ViewBag.Error = "Wykryto bota (wypełniono ukryte pole-pułapkę).";
            return View();
        }

        if (string.Equals(username?.Trim(), "backup_admin", StringComparison.OrdinalIgnoreCase))
        {
            string? canaryUrl = _config["Canarytokens:TrapAccountUrl"];
            if (!string.IsNullOrWhiteSpace(canaryUrl) && canaryUrl.StartsWith("http"))
            {
                try
                {
                    var client = _httpFactory.CreateClient();
                    await client.GetAsync(canaryUrl);
                }
                catch {}
            }
            GenerateCaptcha();
            ViewBag.Error = "Login lub hasło niepoprawne.";
            return View();
        }

        string? expectedAnswer = HttpContext.Session.GetString("CaptchaAnswer");
        string? expiresStr = HttpContext.Session.GetString("CaptchaExpires");

        HttpContext.Session.Remove("CaptchaAnswer");
        HttpContext.Session.Remove("CaptchaExpires");

        if (string.IsNullOrEmpty(expectedAnswer) ||
            string.IsNullOrEmpty(expiresStr) ||
            !DateTime.TryParse(expiresStr, null, System.Globalization.DateTimeStyles.RoundtripKind, out var expiresAt) ||
            DateTime.UtcNow > expiresAt ||
            !string.Equals(captchaAnswer?.Trim(), expectedAnswer, StringComparison.OrdinalIgnoreCase))
        {
            GenerateCaptcha();
            ViewBag.Error = "Błędna odpowiedź CAPTCHA lub zadanie wygasło (ważne 2 min).";
            return View();
        }

        var user = await _db.Users.FirstOrDefaultAsync(u => u.Username == username);
        var settings = await _db.Settings.FirstAsync();

        if (user != null && user.LockoutEnd.HasValue)
        {
            if (user.LockoutEnd.Value > DateTime.UtcNow)
            {
                var remaining = user.LockoutEnd.Value - DateTime.UtcNow;
                GenerateCaptcha();
                ViewBag.Error = $"Konto tymczasowo zablokowane. Pozostały czas: {(int)remaining.TotalMinutes} min {remaining.Seconds} sek.";
                return View();
            }
            else
            {
                user.LockoutEnd = null;
                user.FailedLoginAttempts = 0;
                await _db.SaveChangesAsync();
            }
        }

        if (user == null || !BCrypt.Net.BCrypt.Verify(password, user.PasswordHash))
        {
            if (user != null)
            {
                user.FailedLoginAttempts++;
                if (user.FailedLoginAttempts >= settings.MaxFailedAttempts)
                {
                    user.LockoutEnd = DateTime.UtcNow.AddMinutes(15);
                    user.FailedLoginAttempts = 0;
                    await _db.SaveChangesAsync();
                    GenerateCaptcha();
                    ViewBag.Error = "Przekroczono limit błędnych prób. Konto zablokowane na 15 min 0 sek.";
                    return View();
                }
                await _db.SaveChangesAsync();
            }

            GenerateCaptcha();
            ViewBag.Error = "Login lub hasło niepoprawne.";
            return View();
        }

        if (user.IsBlocked)
        {
            GenerateCaptcha();
            ViewBag.Error = "Konto jest zablokowane przez administratora.";
            return View();
        }

        if (user.IsOtp && user.OtpExpiresAt < DateTime.UtcNow)
        {
            GenerateCaptcha();
            ViewBag.Error = "Hasło jednorazowe wygasło (minęło 12h).";
            return View();
        }

        user.FailedLoginAttempts = 0;
        user.LockoutEnd = null;

        if ((DateTime.UtcNow - user.PasswordSetAt).TotalDays > settings.PasswordValidityDays)
        {
            user.MustChangePassword = true;
        }
        await _db.SaveChangesAsync();

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
        ViewBag.SiteKey = _config["Recaptcha:SiteKey"];
        return View();
    }

    [Authorize]
    [HttpPost]
    public async Task<IActionResult> ChangePassword(string? oldPassword, string newPassword, string confirmPassword, bool firstLogin)
    {
        ViewBag.FirstLogin = firstLogin;
        ViewBag.SiteKey = _config["Recaptcha:SiteKey"];

        string recaptchaToken = Request.Form["g-recaptcha-response"].ToString();
        if (string.IsNullOrWhiteSpace(recaptchaToken))
        {
            ViewBag.Error = "Odrzucono żądanie: brak tokenu reCAPTCHA.";
            return View();
        }

        var client = _httpFactory.CreateClient();
        var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["secret"] = _config["Recaptcha:SecretKey"] ?? "",
            ["response"] = recaptchaToken
        });

        var response = await client.PostAsync("https://www.google.com/recaptcha/api/siteverify", content);
        var json = await response.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);
        bool isSuccess = doc.RootElement.TryGetProperty("success", out var prop) && prop.GetBoolean();

        if (!isSuccess)
        {
            ViewBag.Error = "Odrzucono żądanie: niepoprawny token reCAPTCHA.";
            return View();
        }

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