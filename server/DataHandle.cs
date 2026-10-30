using System;
using System.Data.SqlClient;
using System.IO;
using System.Net.Mail;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Server
{
    /// <summary>
    /// מחלקה לניהול נתונים, עבודה מול מסד הנתונים, הצפנת סיסמאות ושליחת קודי אימות במייל.
    /// </summary>
    public class DataHandle
    {
        private string connectionString;

        // הגדרת פרטי ה-SMTP (שרת המייל) במקום מרכזי
        private const string SmtpEmail = "cyberprojformax@gmail.com";
        private const string SmtpPassword = "kpwlnwepezbxguwe";

        /// <summary>
        /// בנאי המחלקה - מאתחל את מחרוזת התקשורת למסד הנתונים ומוודא שהסכמה מעודכנת.
        /// </summary>
        public DataHandle()
        {
            string dbPath = GetDatabasePath("Database1.mdf");
            connectionString = $@"Data Source=(LocalDB)\MSSQLLocalDB;AttachDbFilename={dbPath};Integrated Security=True;";

            EnsureSchemaUpdated();
        }

        /// <summary>
        /// בודקת ומעדכנת את מבנה הטבלה במסד הנתונים במידת הצורך (הגדלת עמודת הסיסמה והוספת עמודת OTP).
        /// </summary>
        private void EnsureSchemaUpdated()
        {
            try
            {
                using (SqlConnection conn = new SqlConnection(connectionString))
                {
                    conn.Open();

                    // הרחבת אורך עמודת הסיסמה כדי לאפשר אחסון Hash ו-Salt
                    using (SqlCommand cmd = new SqlCommand("ALTER TABLE UserDetails ALTER COLUMN password NVARCHAR(100) NOT NULL;", conn))
                    {
                        cmd.ExecuteNonQuery();
                    }

                    // וידוא קיומה של עמודת otp_code, ואם אינה קיימת - הוספתה
                    using (SqlCommand cmd = new SqlCommand("IF NOT EXISTS (SELECT * FROM sys.columns WHERE object_id = OBJECT_ID('UserDetails') AND name = 'otp_code') ALTER TABLE UserDetails ADD otp_code NVARCHAR(10) NULL;", conn))
                    {
                        cmd.ExecuteNonQuery();
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Schema auto-update log: {ex.Message}");
            }
        }

        /// <summary>
        /// מייצר מחרוזת Salt אקראית ומאובטחת בגודל 16 בייטים (בפורמט Base64).
        /// </summary>
        /// <returns>מחרוזת Salt ייחודית.</returns>
        public static string GenerateSalt()
        {
            byte[] saltBytes = new byte[16];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(saltBytes);
            }
            return Convert.ToBase64String(saltBytes);
        }

        /// <summary>
        /// מחשב ערך Hash מסוג SHA-256 עבור המחרוזת וה-Salt שניתנו.
        /// </summary>
        /// <param name="rawData">המידע המקורי (למשל הסיסמה).</param>
        /// <param name="salt">ה-Salt המתווסף לסיסמה.</param>
        /// <returns>ערך ה-Hash כמחרוזת הפסדצימלית.</returns>
        public static string ComputeSha256(string rawData, string salt)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(rawData + salt));
                StringBuilder builder = new StringBuilder(bytes.Length * 2);
                foreach (byte b in bytes)
                {
                    builder.Append(b.ToString("x2"));
                }
                return builder.ToString();
            }
        }

        /// <summary>
        /// מייצר קוד אימות חד-פעמי (OTP) אקראי ומאובטח המורכב מאותיות באנגלית ומספרים.
        /// </summary>
        /// <param name="length">אורך הקוד (ברירת מחדל: 6 תווים).</param>
        /// <returns>מחרוזת קוד ה-OTP.</returns>
        public static string GenerateOTPCode(int length = 6)
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            byte[] randomBytes = new byte[length];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomBytes);
            }

            char[] result = new char[length];
            for (int i = 0; i < length; i++)
            {
                result[i] = chars[randomBytes[i] % chars.Length];
            }
            return new string(result);
        }

        /// <summary>
        /// שומר או מעדכן את קוד ה-OTP של משתמש מסוים במסד הנתונים.
        /// </summary>
        /// <param name="username">שם המשתמש.</param>
        /// <param name="code">קוד ה-OTP לשמירה (או מחרוזת ריקה לאיפוס).</param>
        /// <returns>True אם העדכון הצליח, אחרת False.</returns>
        public bool SaveOTP(string username, string code)
        {
            using (SqlConnection connection = new SqlConnection(connectionString))
            {
                string query = "UPDATE UserDetails SET otp_code = @Code WHERE username = @Username";
                using (SqlCommand cmd = new SqlCommand(query, connection))
                {
                    cmd.Parameters.AddWithValue("@Code", code);
                    cmd.Parameters.AddWithValue("@Username", username.Trim());
                    connection.Open();
                    return cmd.ExecuteNonQuery() > 0;
                }
            }
        }

        /// <summary>
        /// מאמת את קוד ה-OTP שהזין המשתמש מול הקוד השמור במסד הנתונים.
        /// במידה והאימות מצליח, הקוד מאופס במסד הנתונים.
        /// </summary>
        /// <param name="username">שם המשתמש.</param>
        /// <param name="code">הקוד שהזין המשתמש.</param>
        /// <returns>True אם הקוד תואם, אחרת False.</returns>
        public bool VerifyOTP(string username, string code)
        {
            using (SqlConnection connection = new SqlConnection(connectionString))
            {
                string query = "SELECT otp_code FROM UserDetails WHERE username = @Username";
                using (SqlCommand cmd = new SqlCommand(query, connection))
                {
                    cmd.Parameters.AddWithValue("@Username", username.Trim());
                    connection.Open();
                    object result = cmd.ExecuteScalar();

                    if (result != null && result.ToString().Trim() == code.Trim() && !string.IsNullOrEmpty(code))
                    {
                        SaveOTP(username, ""); // איפוס הקוד לאחר אימות מוצלח למניעת שימוש חוזר
                        return true;
                    }
                    return false;
                }
            }
        }

        /// <summary>
        /// שולח הודעת דוא"ל עם קוד האימות לכתובת המייל המבוקשת.
        /// </summary>
        /// <param name="toEmail">כתובת הדוא"ל של הנמען.</param>
        /// <param name="code">קוד האימות לשליחה.</param>
        /// <returns>True אם השליחה הצליחה, אחרת False.</returns>
        public bool SendVerificationCode(string toEmail, string code)
        {
            try
            {
                using (var smtp = new SmtpClient("smtp.gmail.com", 587))
                {
                    smtp.Credentials = new System.Net.NetworkCredential(SmtpEmail, SmtpPassword);
                    smtp.EnableSsl = true;

                    var mail = new MailMessage(SmtpEmail, toEmail)
                    {
                        Subject = "קוד אימות למערכת",
                        Body = $"Your verification code is: {code}"
                    };
                    smtp.Send(mail);
                    return true;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Email error: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// מאתר את הנתיב המלא של קובץ מסד הנתונים (mdf.) בתיקיית הפרויקט.
        /// </summary>
        /// <param name="dbFileName">שם קובץ מסד הנתונים.</param>
        /// <returns>הנתיב המלא לקובץ.</returns>
        public static string GetDatabasePath(string dbFileName)
        {
            DirectoryInfo dir = new DirectoryInfo(AppDomain.CurrentDomain.BaseDirectory);
            while (dir != null)
            {
                if (dir.GetFiles("*.csproj").Length > 0 || dir.GetFiles("*.sln").Length > 0)
                {
                    return Path.Combine(dir.FullName, dbFileName);
                }
                dir = dir.Parent;
            }
            return Path.Combine(AppDomain.CurrentDomain.BaseDirectory, dbFileName);
        }

        /// <summary>
        /// בודק האם כתובת המייל היא בפורמט תקין.
        /// </summary>
        /// <param name="email">כתובת המייל לבדיקה.</param>
        /// <returns>True אם הפורמט תקין, אחרת False.</returns>
        public bool IsValidEmail(string email)
        {
            if (string.IsNullOrWhiteSpace(email)) return false;
            try
            {
                var mailAddress = new MailAddress(email.Trim());
                return true;
            }
            catch (FormatException)
            {
                return false;
            }
        }

        /// <summary>
        /// בודק האם הסיסמה עומדת בדרישות החוזק:
        /// לפחות 10 תווים, כולל אות קטנה, אות גדולה, ספרה ותו מיוחד.
        /// </summary>
        /// <param name="password">הסיסמה לבדיקה.</param>
        /// <returns>True אם הסיסמה חזקה מספיק, אחרת False.</returns>
        public bool IsStrongPassword(string password)
        {
            if (string.IsNullOrWhiteSpace(password)) return false;
            string pattern = @"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^a-zA-Z0-9]).{10,}$";
            return Regex.IsMatch(password.Trim(), pattern);
        }

        /// <summary>
        /// בודק האם משתמש קיים במערכת והאם הסיסמה שהזין תואמת (על פי בדיקת Salt ו-Hash).
        /// </summary>
        /// <param name="username">שם המשתמש.</param>
        /// <param name="password">הסיסמה לבדיקה.</param>
        /// <returns>True אם שם המשתמש והסיסמה נכונים, אחרת False.</returns>
        public bool isExist(string username, string password)
        {
            if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password)) return false;

            using (SqlConnection connection = new SqlConnection(connectionString))
            {
                string query = "SELECT password FROM UserDetails WHERE username = @Username";
                using (SqlCommand cmd = new SqlCommand(query, connection))
                {
                    cmd.Parameters.AddWithValue("@Username", username.Trim());
                    connection.Open();
                    object result = cmd.ExecuteScalar();

                    if (result == null || result == DBNull.Value) return false;

                    // הפרדת ה-Salt מה-Hash המקורי (שמורים בפורמט salt:hash)
                    string[] parts = result.ToString().Split(':');
                    if (parts.Length < 2) return false;

                    string salt = parts[0];
                    string originalHash = parts[1];
                    string computedHash = ComputeSha256(password.Trim(), salt);

                    return computedHash == originalHash;
                }
            }
        }
        public bool ResetPassword(string username, string newPassword)
        {
            if (!IsStrongPassword(newPassword)) return false;

            string salt = GenerateSalt();
            string storedPassword = salt + ":" + ComputeSha256(newPassword, salt);

            using (SqlConnection connection = new SqlConnection(connectionString))
            {
                string query = "UPDATE UserDetails SET password = @Password WHERE username = @Username";
                using (SqlCommand cmd = new SqlCommand(query, connection))
                {
                    cmd.Parameters.AddWithValue("@Password", storedPassword);
                    cmd.Parameters.AddWithValue("@Username", username.Trim());
                    connection.Open();
                    return cmd.ExecuteNonQuery() > 0;
                }
            }
        }
        /// <summary>
        /// מעדכנת את הסיסמה של המשתמש (קוראת מתודת ResetPassword).
        /// </summary>
        public bool UpdatePassword(string username, string newPassword)
        {
            return ResetPassword(username, newPassword);
        }

        /// <summary>
        /// מקבל את כתובת הדוא"ל של משתמש לפי שם המשתמש שלו.
        /// </summary>
        /// <param name="username">שם המשתמש.</param>
        /// <returns>כתובת הדוא"ל או מחרוזת ריקה אם המשתמש לא נמצא.</returns>
        public string GetUserEmail(string username)
        {
            using (SqlConnection connection = new SqlConnection(connectionString))
            {
                string query = "SELECT email FROM UserDetails WHERE username = @Username";
                using (SqlCommand cmd = new SqlCommand(query, connection))
                {
                    cmd.Parameters.AddWithValue("@Username", username.Trim());
                    connection.Open();
                    object result = cmd.ExecuteScalar();
                    return result != null ? result.ToString() : string.Empty;
                }
            }
        }

        /// <summary>
        /// מוסיף משתמש חדש למסד הנתונים לאחר ביצוע תקינות קלטים (תקינות מייל, חוזק סיסמה, ייחודיות משתמש ומייל).
        /// </summary>
        /// <param name="username">שם משתמש.</param>
        /// <param name="password">סיסמה.</param>
        /// <param name="fname">שם פרטי.</param>
        /// <param name="lname">שם משפחה.</param>
        /// <param name="email">כתובת דוא"ל.</param>
        /// <param name="city">עיר מגורים.</param>
        /// <returns>הודעת טקסט המסכמת את תוצאת הפעולה (הצלחה או שגיאה ספציפית).</returns>
        public string AddUser(string username, string password, string fname, string lname, string email, string city)
        {
            username = username.Trim();
            password = password.Trim();
            fname = fname.Trim();
            lname = lname.Trim();
            email = email.Trim();
            city = city.Trim();

            // בדיקות תקינות קלט
            if (username.Length < 4) return "The username isn't long enough. Minimum is 4 characters.";
            if (!IsValidEmail(email)) return "The email format is invalid.";
            if (!IsStrongPassword(password)) return "Password is not strong enough!";

            using (SqlConnection connection = new SqlConnection(connectionString))
            {
                connection.Open();

                // בדיקה אם הדוא"ל כבר קיים במערכת
                using (SqlCommand cmd = new SqlCommand("SELECT COUNT(*) FROM UserDetails WHERE email = @Email", connection))
                {
                    cmd.Parameters.AddWithValue("@Email", email);
                    if ((int)cmd.ExecuteScalar() > 0) return "Email already exists";
                }

                // בדיקה אם שם המשתמש כבר תפוס
                using (SqlCommand cmd = new SqlCommand("SELECT COUNT(*) FROM UserDetails WHERE username = @Username", connection))
                {
                    cmd.Parameters.AddWithValue("@Username", username);
                    if ((int)cmd.ExecuteScalar() > 0) return "Username already exists";
                }

                // יצירת Salt והצפנת הסיסמה
                string salt = GenerateSalt();
                string storedPassword = salt + ":" + ComputeSha256(password, salt);

                // הכנסת המשתמש החדש לטבלה
                string insertQuery = "INSERT INTO UserDetails (username, password, fname, lname, email, city) " +
                                     "VALUES (@Username, @Password, @Fname, @Lname, @Email, @City)";

                using (SqlCommand cmd = new SqlCommand(insertQuery, connection))
                {
                    cmd.Parameters.AddWithValue("@Username", username);
                    cmd.Parameters.AddWithValue("@Password", storedPassword);
                    cmd.Parameters.AddWithValue("@Fname", fname);
                    cmd.Parameters.AddWithValue("@Lname", lname);
                    cmd.Parameters.AddWithValue("@Email", email);
                    cmd.Parameters.AddWithValue("@City", city);

                    int x = cmd.ExecuteNonQuery();
                    return x > 0 ? "User created successfully" : "Couldn't create the account";
                }
            }
        }
    }
}