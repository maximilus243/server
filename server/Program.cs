using Server;
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;

namespace server
{
    /// <summary>
    /// The entry point for the Connect Four Server application.
    /// This class manages the listener and coordinates the two players.
    /// </summary>
    internal class Program
    {
        // Server configuration constants
        private const string ipAddress = "127.0.0.1"; // Localhost IP
        const int portNo = 1500;                      // Communication port

        // Static list to keep track of the two players in the game session
        // This is shared across the server so moves can be relayed between instances
        public static List<ChatClient> ConnectedPlayers = new List<ChatClient>();

        /// <summary>
        /// The main execution thread of the server. 
        /// Initializes the TCP listener and continuously waits for incoming client connections.
        /// </summary>
        static void Main(string[] args)
        {
            // Set up the listener on the specified IP and Port
            IPAddress localAdd = IPAddress.Parse(ipAddress);
            TcpListener listener = new TcpListener(localAdd, portNo);
            listener.Start();

            Console.WriteLine("Connect Four Server Started...");
            Console.WriteLine("Waiting for players to connect and login...");

            // Infinite loop to continuously accept incoming client connections
            while (true)
            {
                TcpClient tcp = listener.AcceptTcpClient();
                Console.WriteLine("A client connected.");

                // Pass the connection to the ChatClient class to handle asynchronously
                ChatClient clientHandler = new ChatClient(tcp);
            }
        }

        /// <summary>
        /// Checks the number of currently authenticated players.
        /// Once exactly two players are logged in, it assigns their IDs and starts the match.
        /// </summary>
        public static void CheckGameStart()
        {
            Console.WriteLine($"Player logged in. Total connected players: {ConnectedPlayers.Count}");

            // שיוך מזהה ייחודי לכל שחקן המחובר כעת
            for (int i = 0; i < ConnectedPlayers.Count; i++)
            {
                ConnectedPlayers[i].SendMessage($"AssignPlayer#{i + 1}");
            }
        }
    }
}