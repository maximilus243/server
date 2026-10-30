using System;
using System.IO;

namespace Server
{
    /// <summary>
    /// מחלקה לניהול תיעוד אירועים (Logs) של השרת.
    /// מספקת מנגנון כתיבה בטוח ברמת תהליכונים (Thread-Safe) לקובץ טקסט ולמסך הקונסול.
    /// </summary>
    public static class Logger
    {
        /// <summary>
        /// הנתיב לקובץ ה-Log של השרת בתיקיית הריצה.
        /// </summary>
        private static readonly string LogFilePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "server_log.txt");

        /// <summary>
        /// אובייקט נעילה להבטחת סנכרון כתיבה לקובץ בין תהליכונים שונים (Thread Safety).
        /// </summary>
        private static readonly object LockObj = new object();

        /// <summary>
        /// רושם אירוע או פעולה לקובץ ה-Log ולמסך הקונסול בצירוף חותמת זמן.
        /// </summary>
        /// <param name="clientIP">כתובת ה-IP של הלקוח שביצע את הפעולה.</param>
        /// <param name="action">שם הפעולה או סוג האירוע (למשל: LOGIN_SUCCESS, RATE_LIMIT_EXCEEDED).</param>
        /// <param name="details">פירוט או מידע נוסף לגבי הפעולה (אופציונלי).</param>
        public static void Log(string clientIP, string action, string details = "")
        {
            lock (LockObj)
            {
                try
                {
                    string logLine = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] [IP: {clientIP}] [Action: {action}] {details}";
                    File.AppendAllText(LogFilePath, logLine + Environment.NewLine);
                    Console.WriteLine(logLine);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Failed to write to log file: " + ex.Message);
                }
            }
        }
    }
}