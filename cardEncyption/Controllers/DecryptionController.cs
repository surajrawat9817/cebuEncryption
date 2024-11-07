using Microsoft.AspNetCore.Mvc;
using WebApplication3.Helper;

public class DecryptionController : Controller
{
    private const string DefaultSecretKey = "d15be270a756e84bae09ea88b12e80af6596541e6a5266f73a6980f1669bd718"; // Replace with your actual 16-byte default secret key

    [HttpGet]
    public IActionResult Index()
    {
        return View();
    }

    [HttpPost]
    public IActionResult DecryptText(string encryptedText, string secretKey)
    {
        try
        {
            // Use the provided secret key if available; otherwise, use the default key
            var keyToUse = string.IsNullOrWhiteSpace(secretKey) ? DefaultSecretKey : secretKey;
            
            var decryptedText = CryptoHelper.AesDecryption(encryptedText, keyToUse);
            ViewData["DecryptedText"] = decryptedText;
        }
        catch (Exception ex)
        {
            ViewData["DecryptedText"] = $"Error during decryption: {ex.Message}";
        }

        return View("Index");
    }
}