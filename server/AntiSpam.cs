using System;
using System.Collections.Generic;

namespace Server
{
    public static class AntiSpam
    {
        private static readonly Dictionary<string, List<DateTime>> RequestHistory = new Dictionary<string, List<DateTime>>();
        private static readonly object LockObj = new object();

        private const int MaxRequests = 10; // מקסימום 10 בקשות
        private static readonly TimeSpan TimeWindow = TimeSpan.FromSeconds(5); // בחלון זמן של 5 שניות

        public static bool IsAllowed(string clientIP)
        {
            lock (LockObj)
            {
                DateTime now = DateTime.Now;

                if (!RequestHistory.ContainsKey(clientIP))
                    RequestHistory[clientIP] = new List<DateTime>();

                // ניקוי בקשות ישנות מחוץ לחלון הזמן
                RequestHistory[clientIP].RemoveAll(t => now - t > TimeWindow);

                if (RequestHistory[clientIP].Count >= MaxRequests)
                {
                    Logger.Log(clientIP, "RATE_LIMIT_EXCEEDED", "Blocked excess requests.");
                    return false;
                }

                RequestHistory[clientIP].Add(now);
                return true;
            }
        }
    }
}