using System;
using System.Security.Cryptography;

namespace Server
{
    /// <summary>
    /// מחלקה האחראית על ניהול הצפנת RSA, יצירת מפתחות ופענוח מפתחות סשן.
    /// </summary>
    public class RsaManager : IDisposable
    {
        private readonly RSA _rsa;

        public RsaManager(int keySize = 2048)
        {
            _rsa = RSA.Create(keySize);
        }

        /// <summary>
        /// מחזירה את המפתח הציבורי בפורמט XML לשליחה ללקוח.
        /// </summary>
        public string GetPublicKeyXml()
        {
            return _rsa.ToXmlString(false);
        }

        /// <summary>
        /// מפענחת נתונים שהוצפנו באמצעות המפתח הציבורי (כגון מפתח ה-AES שנשלח מהלקוח).
        /// </summary>
        public byte[] Decrypt(byte[] encryptedData)
        {
            return _rsa.Decrypt(encryptedData, RSAEncryptionPadding.OaepSHA256);
        }

        public void Dispose()
        {
            _rsa?.Dispose();
        }
    }
}