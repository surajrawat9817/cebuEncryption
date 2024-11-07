using System.Security.Cryptography;
using System.Text;

namespace WebApplication3.Helper;

public class CryptoHelper
{
        public static string AesEncryption(string plainText, string secret)
    {
        byte[] salt = RandomNumberGenerator.GetBytes(8);
        byte[] password = Encoding.ASCII.GetBytes(secret);
        byte[] passwordWithSalt = new byte[password.Length + salt.Length];
        Array.Copy(password, 0, passwordWithSalt, 0, password.Length);
        Array.Copy(salt, 0, passwordWithSalt, password.Length, salt.Length);

        List<byte[]> hash = new List<byte[]>();
        byte[] digest = passwordWithSalt;
        for (int i = 0; i < 3; i++)
        {
            using (var md5 = MD5.Create())
            {
                hash.Add(md5.ComputeHash(digest));
                digest = new byte[hash[i].Length + passwordWithSalt.Length];
                Array.Copy(hash[i], 0, digest, 0, hash[i].Length);
                Array.Copy(passwordWithSalt, 0, digest, hash[i].Length, passwordWithSalt.Length);
            }
        }

        byte[] keyDerivation = new byte[hash.Count * hash[0].Length];
        int offset = 0;
        foreach (var item in hash)
        {
            Array.Copy(item, 0, keyDerivation, offset, item.Length);
            offset += item.Length;
        }

        byte[] key = new byte[32];
        byte[] iv = new byte[16];
        Array.Copy(keyDerivation, 0, key, 0, 32);
        Array.Copy(keyDerivation, 32, iv, 0, 16);

        using (var aes = Aes.Create())
        {
            aes.Key = key;
            aes.IV = iv;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            byte[] cipherText;
            using (var encryptor = aes.CreateEncryptor())
            {
                cipherText = encryptor.TransformFinalBlock(Encoding.UTF8.GetBytes(plainText), 0,
                    Encoding.UTF8.GetBytes(plainText).Length);
            }

            byte[] result = new byte[Encoding.UTF8.GetBytes("Salted__").Length + salt.Length + cipherText.Length];
            Array.Copy(Encoding.UTF8.GetBytes("Salted__"), 0, result, 0, Encoding.UTF8.GetBytes("Salted__").Length);
            Array.Copy(salt, 0, result, Encoding.UTF8.GetBytes("Salted__").Length, salt.Length);
            Array.Copy(cipherText, 0, result, Encoding.UTF8.GetBytes("Salted__").Length + salt.Length,
                cipherText.Length);
            return Convert.ToBase64String(result);
        }
    }

    public static string AesDecryption(string cipherTextBase64, string secret)
    {
        var cipherTextBytes = Convert.FromBase64String(cipherTextBase64);
        var saltMarker = Encoding.UTF8.GetBytes("Salted__");

        // Extract the salt from the input cipher text
        var salt = new byte[8];
        Array.Copy(cipherTextBytes, saltMarker.Length, salt, 0, salt.Length);

        // Derive the key and IV using the same process as encryption
        var password = Encoding.ASCII.GetBytes(secret);
        var passwordWithSalt = new byte[password.Length + salt.Length];
        Array.Copy(password, 0, passwordWithSalt, 0, password.Length);
        Array.Copy(salt, 0, passwordWithSalt, password.Length, salt.Length);

        var hash = new List<byte[]>();
        var digest = passwordWithSalt;

        // Generate the required key and IV (48 bytes total)
        for (var index = 0; index < 3; index++)
        {
            hash.Add(MD5.HashData(digest));
            digest = new byte[hash[index].Length + passwordWithSalt.Length];
            Array.Copy(hash[index], 0, digest, 0, hash[index].Length);
            Array.Copy(passwordWithSalt, 0, digest, hash[index].Length, passwordWithSalt.Length);
        }

        var key = new byte[32];
        var iv = new byte[16];
        Array.Copy(hash[0], 0, key, 0, 16);
        Array.Copy(hash[1], 0, key, 16, 16);
        Array.Copy(hash[2], 0, iv, 0, 16);

        using var aes = Aes.Create();
        aes.Key = key;
        aes.IV = iv;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;

        // Decrypt the cipher text
        var encryptedDataOffset = saltMarker.Length + salt.Length;
        var encryptedDataLength = cipherTextBytes.Length - encryptedDataOffset;
        var encryptedData = new byte[encryptedDataLength];
        Array.Copy(cipherTextBytes, encryptedDataOffset, encryptedData, 0, encryptedDataLength);

        using var decryptor = aes.CreateDecryptor();
        var plainTextBytes = decryptor.TransformFinalBlock(encryptedData, 0, encryptedData.Length);

        return Encoding.UTF8.GetString(plainTextBytes);
    }

}