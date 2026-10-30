using System;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;

namespace Server
{
    /// <summary>
    /// מחלקה המכילה את תוצאת יצירת ה-CAPTCHA (הקוד והתמונה ב-Base64).
    /// </summary>
    public class CaptchaResult
    {
        public string Code { get; set; }
        public string Base64Image { get; set; }
    }

    /// <summary>
    /// מחלקה האחראית על יצירת אתגרי CAPTCHA ויצירת תמונות מטושטשות הגנה מבוטים.
    /// </summary>
    public static class CaptchaManager
    {
        /// <summary>
        /// מייצרת קוד CAPTCHA אקראי ותמונה בפורמט Base64.
        /// </summary>
        /// <param name="length">אורך קוד ה-CAPTCHA (ברירת מחדל: 5).</param>
        public static CaptchaResult GenerateCaptcha(int length = 5)
        {
            string captchaCode = DataHandle.GenerateOTPCode(length);
            string base64Image;

            using (Bitmap bmp = new Bitmap(180, 60))
            using (Graphics g = Graphics.FromImage(bmp))
            {
                g.Clear(Color.LightGray);
                Random rnd = new Random();

                // הוספת קווי רעש
                for (int i = 0; i < 8; i++)
                {
                    int x1 = rnd.Next(bmp.Width);
                    int y1 = rnd.Next(bmp.Height);
                    int x2 = rnd.Next(bmp.Width);
                    int y2 = rnd.Next(bmp.Height);
                    g.DrawLine(new Pen(Color.DimGray, 2), x1, y1, x2, y2);
                }

                // ציור הטקסט
                using (Font font = new Font("Arial", 22, FontStyle.Bold | FontStyle.Italic))
                using (SolidBrush brush = new SolidBrush(Color.DarkBlue))
                {
                    g.DrawString(captchaCode, font, brush, 15, 12);
                }

                using (MemoryStream ms = new MemoryStream())
                {
                    bmp.Save(ms, ImageFormat.Png);
                    base64Image = Convert.ToBase64String(ms.ToArray());
                }
            }

            return new CaptchaResult
            {
                Code = captchaCode,
                Base64Image = base64Image
            };
        }
    }
}