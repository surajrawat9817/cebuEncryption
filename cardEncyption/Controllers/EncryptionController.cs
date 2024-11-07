using Microsoft.AspNetCore.Mvc;
using WebApplication3.Helper;

namespace WebApplication3.Controllers;

public class EncryptionController : Controller
{
    private const string DefaultSecretKey = "d15be270a756e84bae09ea88b12e80af6596541e6a5266f73a6980f1669bd718"; // Replace with your actual 16-byte default secret key

    [HttpGet]
    public IActionResult Index()
    {
        return View();
    }

    [HttpPost]
    public IActionResult EncryptText(string encryptedText, string secretKey)
    {
        try
        {
            var keyToUse = string.IsNullOrWhiteSpace(secretKey) ? DefaultSecretKey : secretKey;
            
            var encyptedText = CryptoHelper.AesEncryption(encryptedText, keyToUse);
            ViewData["EncryptedText"] = encyptedText;
        }
        catch (Exception ex)
        {
            ViewData["EncryptedText"] = $"Error during Encryption: {ex.Message}";
        }

        return View("Index");
    }
}