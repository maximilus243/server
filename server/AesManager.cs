using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Server
{
    /// <summary>
    /// מחלקה האחראית על הצפנה ופענוח של הודעות בתקשורת באמצעות מפתח AES ו-IV.
    /// </summary>
    public class AesManager
    {
        public byte[] Key { get; set; }
        public byte[] IV { get; set; }

        public AesManager(byte[] key = null, byte[] iv = null)
        {
            Key = key;
            IV = iv;
        }

        /// <summary>
        /// מפענחת מערך בייטים מוצפן ב-AES למחרוזת טקסט קריאה.
        /// </summary>
        public string Decrypt(byte[] cipherData)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = Key;
                aes.IV = IV;

                using (MemoryStream ms = new MemoryStream(cipherData))
                using (CryptoStream cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Read))
                using (StreamReader sr = new StreamReader(cs))
                {
                    return sr.ReadToEnd();
                }
            }
        }

        /// <summary>
        /// מצפינה מחרוזת טקסט למערך בייטים מוצפן ב-AES.
        /// </summary>
        public byte[] Encrypt(string plainText)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = Key;
                aes.IV = IV;

                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        byte[] inputBytes = Encoding.UTF8.GetBytes(plainText);
                        cs.Write(inputBytes, 0, inputBytes.Length);
                        cs.FlushFinalBlock();
                    }
                    return ms.ToArray();
                }
            }
        }
    }
}