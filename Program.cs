
using System;
using System.Collections;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using System.Security.Cryptography.X509Certificates;
using System.IO;
using System.Threading;

namespace AutoSSLToUCE
{
    public class SslTcpClient
    {
        private static Hashtable certificateErrors = new Hashtable();

        // The following method is invoked by the RemoteCertificateValidationDelegate.
        public static bool ValidateServerCertificate(
              object sender,
              X509Certificate certificate,
              X509Chain chain,
              SslPolicyErrors sslPolicyErrors)
        {
            if (sslPolicyErrors == SslPolicyErrors.None)
                return true;

            Console.WriteLine("Certificate error: {0}", sslPolicyErrors);

            // Do not allow this client to communicate with unauthenticated servers.
            return false;
        }
        public static void RunClient(string machineName, string serverName, string username, string password, string command)
        {
            TcpClient client = new TcpClient(machineName, 41797);
            Console.WriteLine("Client connected.");
            SslStream sslStream = new SslStream(
                client.GetStream(),
                false,
                new RemoteCertificateValidationCallback(ValidateServerCertificate),
                null
                );
            // The server name must match the name on the server certificate (UC-ENGINE).
            try
            {
                sslStream.AuthenticateAsClient(serverName);
            }
            catch (AuthenticationException e)
            {
                Console.WriteLine("Exception: {0}", e.Message);
                if (e.InnerException != null)
                {
                    Console.WriteLine("Inner exception: {0}", e.InnerException.Message);
                }
                Console.WriteLine("Authentication failed - closing the connection.");
                client.Close();
                return;
            }
            byte[] messsage = Encoding.UTF8.GetBytes("\r\n");
            sslStream.Write(messsage);
            sslStream.Flush();
            int count = 3;
            bool loginEntered = false;
            bool passwordEntered = false;
            while (sslStream.IsAuthenticated && count > 0)
            {
                string serverMessage = ReadMessage(sslStream);
                if (serverMessage.Trim() == "Login:")
                {
                    Console.WriteLine("entering username");
                    sslStream.Write(Encoding.UTF8.GetBytes($"{username}\r\n"));
                    sslStream.Flush();
                    loginEntered = true;
                    count--;
                }
                else if (serverMessage.Trim() == "Password:")
                {
                    Console.WriteLine("entering password");
                    sslStream.Write(Encoding.UTF8.GetBytes($"{password}\r\n"));
                    sslStream.Flush();
                    passwordEntered = true;
                }
                if (loginEntered && passwordEntered)
                {
                    Console.Write("entering command: ");
                    sslStream.Write(Encoding.UTF8.GetBytes($"{command}\r\n"));
                    sslStream.Flush();
                    ReadCommandResponse(sslStream); //The first prompt is empty (ignore).
                    serverMessage = ReadCommandResponse(sslStream);
                    Console.WriteLine(serverMessage);
                    break;
                }
            }
            client.Close();
            Console.WriteLine("Client closed.");
        }
        static string ReadMessage(SslStream sslStream)
        {

            byte[] buffer = new byte[2048];
            StringBuilder messageData = new StringBuilder();
            int bytes = -1;
            //Timeout after 5 seconds
            using (CancellationTokenSource cts = new CancellationTokenSource(5000))
            {
                while (!cts.IsCancellationRequested)
                {
                    bytes = sslStream.Read(buffer, 0, buffer.Length);
                    Decoder decoder = Encoding.UTF8.GetDecoder();
                    char[] chars = new char[decoder.GetCharCount(buffer, 0, bytes)];
                    decoder.GetChars(buffer, 0, bytes, chars, 0);
                    messageData.Append(chars);

                    if (messageData.ToString().Contains("\r\n"))
                    {
                        break;
                    }
                }
            }
            return messageData.ToString();
        }

        static string ReadCommandResponse(SslStream sslStream)
        {
            byte[] buffer = new byte[2048];
            StringBuilder messageData = new StringBuilder();
            int bytes = -1;
            //Timeout after 5 seconds
            using (CancellationTokenSource cts = new CancellationTokenSource(5000))
            {
                cts.Token.Register(() => { throw new TimeoutException(); });
                while (!cts.IsCancellationRequested)
                {
                    bytes = sslStream.Read(buffer, 0, buffer.Length);
                    Decoder decoder = Encoding.UTF8.GetDecoder();
                    char[] chars = new char[decoder.GetCharCount(buffer, 0, bytes)];
                    decoder.GetChars(buffer, 0, bytes, chars, 0);
                    messageData.Append(chars);

                    //Break when finding a prompt.
                    if (messageData.ToString().Contains("UC-ENGINE") && messageData.ToString().Contains(">"))
                    {
                        break;
                    }
                }
            }
            return messageData.ToString();
        }
        private static void DisplayUsage()
        {
            Console.WriteLine("hostname/IP, username, password, command");
            Environment.Exit(1);
        }
        public static int Main(string[] args)
        {
            if (args == null || args.Length < 4)
            {
                DisplayUsage();
            }
            SslTcpClient.RunClient(args[0], "UC-ENGINE", args[1], args[2], args[3]);
            return 0;
        }
    }
}
