using Cyber_lab1.Models;
using Microsoft.EntityFrameworkCore;

namespace Cyber_lab1.Data;

public class AppDbContext : DbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

    public DbSet<User> Users => Set<User>();
    public DbSet<PasswordHistory> PasswordHistories => Set<PasswordHistory>();
    public DbSet<ForbiddenWord> ForbiddenWords => Set<ForbiddenWord>();
    public DbSet<SystemSettings> Settings => Set<SystemSettings>();

    public static void Seed(AppDbContext db)
    {
        db.Database.EnsureCreated();
        if (db.Users.Any()) return;

        db.Settings.Add(new SystemSettings());

        string[] words = { "ubb", "bielsko", "mod1", "wiosna", "lato", "jesien", "zima", "styczen", "luty", "marzec", "kwiecien", "maj", "czerwiec", "lipiec", "sierpien", "wrzesien", "pazdziernik", "listopad", "grudzien" };
        foreach (var w in words) db.ForbiddenWords.Add(new ForbiddenWord { Word = w });

        string defaultHash = BCrypt.Net.BCrypt.HashPassword("DlugieHasloStartowe123!");
        var users = new List<User>
        {
            new() { Username = "ADMIN", Role = "Administrator", PasswordHash = defaultHash },
            new() { Username = "kierownik1", Role = "Kierownik", PasswordHash = defaultHash },
            new() { Username = "redaktor1", Role = "Redaktor", PasswordHash = defaultHash },
            new() { Username = "redaktor2", Role = "Redaktor", PasswordHash = defaultHash },
            new() { Username = "pracownik1", Role = "Pracownik", PasswordHash = defaultHash },
            new() { Username = "pracownik2", Role = "Pracownik", PasswordHash = defaultHash },
            new() { Username = "czytelnik1", Role = "Czytelnik", PasswordHash = defaultHash },
            new() { Username = "czytelnik2", Role = "Czytelnik", PasswordHash = defaultHash }
        };

        db.Users.AddRange(users);
        db.SaveChanges();

        foreach (var u in db.Users)
            db.PasswordHistories.Add(new PasswordHistory { UserId = u.Id, PasswordHash = u.PasswordHash });

        db.SaveChanges();
    }
}