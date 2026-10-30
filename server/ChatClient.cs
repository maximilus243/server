using server;
using System;
using System.IO;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace Server
{
    class ChatClient
    {
        private TcpClient _client;
        private string _clientIP;
        private byte[] data;
        private DataHandle DH = new DataHandle();

        private string _expectedCaptchaCode = "";
        private bool _isCaptchaSolved = false;
        private string _pendingRegisterMessage = "";

        // --- שימוש במחלקות המוצפנות החדשות ---
        private RsaManager _rsaManager;
        private AesManager _aesManager;
        private bool _isHandshakeComplete = false;
        private Timer _sessionTimer;

        public ChatClient(TcpClient client)
        {
            _client = client;
            _clientIP = client.Client.RemoteEndPoint.ToString();
            data = new byte[_client.ReceiveBufferSize];

            _rsaManager = new RsaManager(2048);
            _aesManager = new AesManager();

            _sessionTimer = new Timer(OnSessionExpired, null, TimeSpan.FromSeconds(300), Timeout.InfiniteTimeSpan);
            _client.GetStream().BeginRead(data, 0, data.Length, ReceiveMessage, null);

            SendRsaPublicKey();
        }

        private void SendRsaPublicKey()
        {
            string publicKeyXml = _rsaManager.GetPublicKeyXml();
            SendMessage($"#RSA_KEY {publicKeyXml}");
        }

        public void SendMessage(string message)
        {
            try
            {
                NetworkStream ns = _client.GetStream();
                string messageToSend;

                if (!_isHandshakeComplete || message.StartsWith("#RSA_KEY") || message.StartsWith("#HANDSHAKE_OK"))
                {
                    messageToSend = message;
                }
                else
                {
                    byte[] encryptedBytes = _aesManager.Encrypt(message);
                    messageToSend = Convert.ToBase64String(encryptedBytes);
                }

                byte[] bytesToSend = Encoding.UTF8.GetBytes(messageToSend + "\n");
                ns.Write(bytesToSend, 0, bytesToSend.Length);
                ns.Flush();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error sending to {_clientIP}: {ex.Message}");
            }
        }

        public void ReceiveMessage(IAsyncResult ar)
        {
            try
            {
                int bytesRead = _client.GetStream().EndRead(ar);
                if (bytesRead < 1)
                {
                    HandleDisconnect();
                    return;
                }

                if (!AntiSpam.IsAllowed(_clientIP))
                {
                    SendMessage("RATE_LIMIT_EXCEEDED");
                    _client.GetStream().BeginRead(data, 0, data.Length, ReceiveMessage, null);
                    return;
                }

                string rawMessage = Encoding.UTF8.GetString(data, 0, bytesRead).Trim();

                if (_isHandshakeComplete && !rawMessage.StartsWith("#AES_KEY", StringComparison.OrdinalIgnoreCase))
                {
                    byte[] cipherBytes = Convert.FromBase64String(rawMessage);
                    rawMessage = _aesManager.Decrypt(cipherBytes);
                }

                Logger.Log(_clientIP, "INCOMING_MSG", MaskSensitiveData(rawMessage));

                if (rawMessage.StartsWith("#AES_KEY", StringComparison.OrdinalIgnoreCase))
                {
                    HandleAesKeyExchange(rawMessage);
                }
                else if (rawMessage.StartsWith("#Regist", StringComparison.OrdinalIgnoreCase))
                {
                    HandleRegister(rawMessage);
                }
                else if (rawMessage.StartsWith("#Login", StringComparison.OrdinalIgnoreCase))
                {
                    HandleLogin(rawMessage);
                }
                else if (rawMessage.StartsWith("#ForgotPassword", StringComparison.OrdinalIgnoreCase))
                {
                    HandleForgotPassword(rawMessage);
                }
                else if (rawMessage.StartsWith("#ResetPassword", StringComparison.OrdinalIgnoreCase))
                {
                    HandleResetPassword(rawMessage);
                }
                else if (rawMessage.StartsWith("#GetCaptcha", StringComparison.OrdinalIgnoreCase))
                {
                    SendCaptchaChallenge();
                }
                else if (rawMessage.StartsWith("#VerifyCode", StringComparison.OrdinalIgnoreCase))
                {
                    string clientCode = ExtractValue(rawMessage, "#VerifyCode");
                    string username = ExtractValue(rawMessage, "#Username");

                    if (DH.VerifyOTP(username, clientCode))
                    {
                        string sessionToken = TokenManager.IssueToken(username);
                        SendMessage($"LOGIN OK #TOKEN {sessionToken}");
                        Logger.Log(_clientIP, "LOGIN_SUCCESS", $"User: {username}, Token: {sessionToken}");

                        if (!Program.ConnectedPlayers.Contains(this))
                        {
                            Program.ConnectedPlayers.Add(this);
                            Program.CheckGameStart();
                        }
                    }
                    else
                    {
                        SendMessage("INVALID_VERIFICATION_CODE");
                    }
                }
                else if (rawMessage.StartsWith("#VerifyCaptcha", StringComparison.OrdinalIgnoreCase))
                {
                    HandleVerifyCaptcha(rawMessage);
                }
                else
                {
                    SendMessage("ERROR_UNKNOWN_COMMAND");
                }

                _client.GetStream().BeginRead(data, 0, data.Length, ReceiveMessage, null);
            }
            catch (Exception ex)
            {
                Logger.Log(_clientIP, "DISCONNECT_OR_ERROR", ex.Message);
                HandleDisconnect();
            }
        }

        private void HandleAesKeyExchange(string rawMessage)
        {
            try
            {
                string[] parts = rawMessage.Split(' ');
                if (parts.Length >= 3)
                {
                    byte[] encryptedKey = Convert.FromBase64String(parts[1]);
                    byte[] encryptedIV = Convert.FromBase64String(parts[2]);

                    _aesManager.Key = _rsaManager.Decrypt(encryptedKey);
                    _aesManager.IV = _rsaManager.Decrypt(encryptedIV);

                    SendMessage("#HANDSHAKE_OK");
                    _isHandshakeComplete = true;

                    Console.WriteLine($"AES Key updated/refreshed for {_clientIP}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to process AES Key from {_clientIP}: {ex.Message}");
            }
        }

        private void SendCaptchaChallenge()
        {
            CaptchaResult captcha = CaptchaManager.GenerateCaptcha();
            _expectedCaptchaCode = captcha.Code;
            SendMessage($"#CAPTCHA_IMAGE {captcha.Base64Image}");
        }

        private void HandleVerifyCaptcha(string msg)
        {
            string userCaptcha = ExtractValue(msg, "#VerifyCaptcha");

            if (!string.IsNullOrEmpty(userCaptcha) && userCaptcha.Equals(_expectedCaptchaCode, StringComparison.OrdinalIgnoreCase))
            {
                _isCaptchaSolved = true;
                SendMessage("CAPTCHA_OK");

                if (!string.IsNullOrEmpty(_pendingRegisterMessage))
                {
                    string pendingMsg = _pendingRegisterMessage;
                    _pendingRegisterMessage = "";
                    HandleRegister(pendingMsg);
                }
            }
            else
            {
                SendMessage("CAPTCHA_FAILED");
                SendCaptchaChallenge();
            }
        }

        private string MaskSensitiveData(string message)
        {
            if (string.IsNullOrEmpty(message)) return message;
            return System.Text.RegularExpressions.Regex.Replace(
                message,
                @"(#(?:password|Password|NewPassword))\s+\S+",
                "$1 ********",
                System.Text.RegularExpressions.RegexOptions.IgnoreCase
            );
        }

        private string ExtractValue(string message, string tag)
        {
            try
            {
                int tagIndex = message.IndexOf(tag, StringComparison.OrdinalIgnoreCase);
                if (tagIndex == -1) return "";

                string sub = message.Substring(tagIndex + tag.Length).Trim();
                string[] parts = sub.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                return parts.Length > 0 ? parts[0] : "";
            }
            catch { return ""; }
        }

        private void OnSessionExpired(object state)
        {
            Console.WriteLine($"Session timeout reached for {_clientIP}. Disconnecting...");
            SendMessage("SESSION_EXPIRED");
            HandleDisconnect();
        }

        private void HandleDisconnect()
        {
            Console.WriteLine($"The client disconnected {_clientIP}");

            if (Program.ConnectedPlayers.Contains(this))
            {
                Program.ConnectedPlayers.Remove(this);
                foreach (var remainingPlayer in Program.ConnectedPlayers)
                {
                    remainingPlayer.SendMessage("OpponentLeft#");
                }
            }

            _sessionTimer?.Dispose();
            _rsaManager?.Dispose();

            try { _client.Close(); } catch { }
        }

        private void HandleRegister(string msg)
        {
            if (!_isCaptchaSolved)
            {
                _pendingRegisterMessage = msg;
                SendCaptchaChallenge();
                return;
            }

            _isCaptchaSolved = false;

            string username = ExtractValue(msg, "#Username");
            string password = ExtractValue(msg, "#password");
            string fname = ExtractValue(msg, "#fname");
            string lname = ExtractValue(msg, "#lname");
            string email = ExtractValue(msg, "#email");
            string city = ExtractValue(msg, "#city");

            string resultMessage = DH.AddUser(username, password, fname, lname, email, city);

            if (resultMessage == "User created successfully")
            {
                string code = DataHandle.GenerateOTPCode();
                DH.SaveOTP(username, code);

                if (DH.SendVerificationCode(email, code))
                {
                    SendMessage("VERIFY_REGIST_CODE_SENT");
                }
                else
                {
                    SendMessage("FAILED_TO_SEND_EMAIL");
                }
            }
            else
            {
                SendMessage(resultMessage);
            }
        }

        private void HandleLogin(string msg)
        {
            string username = ExtractValue(msg, "#Username");
            string password = ExtractValue(msg, "#Password");

            if (DH.isExist(username, password))
            {
                string email = DH.GetUserEmail(username);

                string code = DataHandle.GenerateOTPCode();
                DH.SaveOTP(username, code);

                if (DH.SendVerificationCode(email, code))
                {
                    SendMessage("VERIFY_LOGIN_CODE_SENT");
                }
                else
                {
                    SendMessage("FAILED_TO_SEND_EMAIL");
                }
            }
            else
            {
                SendMessage("LOGIN FAILED");
            }
        }

        private void HandleForgotPassword(string msg)
        {
            string username = ExtractValue(msg, "#Username");
            string email = DH.GetUserEmail(username);

            if (!string.IsNullOrEmpty(email))
            {
                string code = DataHandle.GenerateOTPCode();
                DH.SaveOTP(username, code);

                if (DH.SendVerificationCode(email, code))
                {
                    SendMessage("RESET_CODE_SENT");
                }
                else
                {
                    SendMessage("FAILED_TO_SEND_EMAIL");
                }
            }
            else
            {
                SendMessage("USER_NOT_FOUND");
            }
        }

        private void HandleResetPassword(string msg)
        {
            string username = ExtractValue(msg, "#Username");
            string code = ExtractValue(msg, "#Code");
            string newPassword = ExtractValue(msg, "#NewPassword");

            if (DH.VerifyOTP(username, code))
            {
                bool isUpdated = DH.ResetPassword(username, newPassword);
                if (isUpdated)
                {
                    SendMessage("PASSWORD_RESET_SUCCESS");
                }
                else
                {
                    SendMessage("FAILED_TO_RESET_PASSWORD");
                }
            }
            else
            {
                SendMessage("INVALID_VERIFICATION_CODE");
            }
        }
    }
}