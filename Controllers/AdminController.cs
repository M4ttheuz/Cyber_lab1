using System.Security.Cryptography;
using Cyber_lab1.Data;
using Cyber_lab1.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace Cyber_lab1.Controllers;

[Authorize(Roles = "Administrator")]
public class AdminController : Controller
{
    private readonly AppDbContext _db;
    private static readonly string[] OtpWords = { "rower", "szosa", "gory", "kawa", "las", "wiatr", "most", "rzeka", "slonce", "trasa" };

    public AdminController(AppDbContext db) => _db = db;

    private string GenerateOtp()
    {
        string w1 = OtpWords[RandomNumberGenerator.GetInt32(OtpWords.Length)];
        string w2 = OtpWords[RandomNumberGenerator.GetInt32(OtpWords.Length)];
        string w3 = OtpWords[RandomNumberGenerator.GetInt32(OtpWords.Length)];
        int digits = RandomNumberGenerator.GetInt32(10, 100);
        return $"{w1}-{w2}-{w3}-{digits}";
    }

    public async Task<IActionResult> Index()
    {
        ViewBag.Settings = await _db.Settings.FirstAsync();
        ViewBag.Words = await _db.ForbiddenWords.ToListAsync();
        var users = await _db.Users.ToListAsync();
        return View(users);
    }

    [HttpPost]
    public async Task<IActionResult> CreateUser(string username, string role)
    {
        string otp = GenerateOtp();
        var user = new User
        {
            Username = username,
            Role = role,
            PasswordHash = BCrypt.Net.BCrypt.HashPassword(otp),
            MustChangePassword = true,
            IsOtp = true,
            OtpExpiresAt = DateTime.UtcNow.AddHours(12)
        };
        _db.Users.Add(user);
        await _db.SaveChangesAsync();

        TempData["OtpMsg"] = $"Utworzono konto {username}. Hasło jednorazowe (ważne 12h): {otp}";
        return RedirectToAction("Index");
    }

    [HttpPost]
    public async Task<IActionResult> ResetPassword(int id)
    {
        var user = await _db.Users.FindAsync(id);
        if (user != null)
        {
            string otp = GenerateOtp();
            user.PasswordHash = BCrypt.Net.BCrypt.HashPassword(otp);
            user.MustChangePassword = true;
            user.IsOtp = true;
            user.OtpExpiresAt = DateTime.UtcNow.AddHours(12);
            await _db.SaveChangesAsync();
            TempData["OtpMsg"] = $"Zresetowano hasło dla {user.Username}. Nowe OTP (ważne 12h): {otp}";
        }
        return RedirectToAction("Index");
    }

    [HttpPost]
    public async Task<IActionResult> ChangeRole(int id, string role)
    {
        var user = await _db.Users.FindAsync(id);
        if (user != null && user.Username != "ADMIN") { user.Role = role; await _db.SaveChangesAsync(); }
        return RedirectToAction("Index");
    }

    [HttpPost]
    public async Task<IActionResult> ToggleBlock(int id)
    {
        var user = await _db.Users.FindAsync(id);
        if (user != null && user.Username != "ADMIN") { user.IsBlocked = !user.IsBlocked; await _db.SaveChangesAsync(); }
        return RedirectToAction("Index");
    }

    [HttpPost]
    public async Task<IActionResult> DeleteUser(int id)
    {
        var user = await _db.Users.FindAsync(id);
        if (user != null && user.Username != "ADMIN") { _db.Users.Remove(user); await _db.SaveChangesAsync(); }
        return RedirectToAction("Index");
    }

    [HttpPost]
    public async Task<IActionResult> UpdateSettings(int minLen, bool enforceWords, int validityDays, int sessionMinutes)
    {
        var s = await _db.Settings.FirstAsync();
        s.MinPasswordLength = minLen;
        s.EnforceForbiddenWords = enforceWords;
        s.PasswordValidityDays = validityDays;
        s.SessionTimeoutMinutes = sessionMinutes;
        await _db.SaveChangesAsync();
        return RedirectToAction("Index");
    }

    [HttpPost]
    public async Task<IActionResult> AddWord(string word)
    {
        if (!string.IsNullOrWhiteSpace(word))
        {
            _db.ForbiddenWords.Add(new ForbiddenWord { Word = word.Trim().ToLower() });
            await _db.SaveChangesAsync();
        }
        return RedirectToAction("Index");
    }

    [HttpPost]
    public async Task<IActionResult> DeleteWord(int id)
    {
        var w = await _db.ForbiddenWords.FindAsync(id);
        if (w != null) { _db.ForbiddenWords.Remove(w); await _db.SaveChangesAsync(); }
        return RedirectToAction("Index");
    }
}