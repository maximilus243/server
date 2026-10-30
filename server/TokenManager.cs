using System;
using System.Collections.Generic;

namespace Server
{
    public static class TokenManager
    {
        private static readonly Dictionary<string, string> ActiveTokens = new Dictionary<string, string>();
        private static readonly object LockObj = new object();

        public static string IssueToken(string username)
        {
            lock (LockObj)
            {
                string token = Guid.NewGuid().ToString("N");
                ActiveTokens[username] = token;
                return token;
            }
        }

        public static bool ValidateToken(string username, string token)
        {
            lock (LockObj)
            {
                return ActiveTokens.TryGetValue(username, out string validToken) && validToken == token;
            }
        }

        public static void RevokeToken(string username)
        {
            lock (LockObj)
            {
                ActiveTokens.Remove(username);
            }
        }
    }
}