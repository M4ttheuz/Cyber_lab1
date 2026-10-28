using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Cyber_lab1.Controllers;

[Authorize]
public class HomeController : Controller
{
    public IActionResult Index() => View();

    [Authorize(Roles = "Kierownik")]
    public IActionResult ZatwierdzRaport() => Content("Strefa kierownika: raport zatwierdzony.");

    [Authorize(Roles = "Kierownik,Redaktor")]
    public IActionResult EdytujArtykul() => Content("Strefa redaktora/kierownika: artykuł zapisany.");

    [Authorize(Roles = "Kierownik,Redaktor,Pracownik")]
    public IActionResult DodajNotatke() => Content("Strefa pracownika: notatka dodana.");

    [Authorize(Roles = "Administrator,Kierownik,Redaktor,Pracownik,Czytelnik")]
    public IActionResult CzytajArtykuly() => Content("Strefa ogólna: lista opublikowanych artykułów.");
}