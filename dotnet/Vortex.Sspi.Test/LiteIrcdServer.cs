using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using System.Collections.Generic;

namespace Vortex.Sspi.Test
{
    public class LiteIrcdServer
    {
        private readonly int port;
        private const int BufferSize = 1024;
        private CancellationTokenSource _cts = new CancellationTokenSource();
        private NetworkStream? _stream;
        private string _nickname = "Guest";

        public LiteIrcdServer(int port = 6667)
        {
            this.port = port;
        }

        public void RequestShutdown()
        {
            _cts.Cancel();
        }

        public async Task RunAsync()
        {
            var listenerIPv4 = new TcpListener(IPAddress.Loopback, port);
            listenerIPv4.Start();
            Console.WriteLine($"[IRCd-lite] Listening on 127.0.0.1:{port} (IPv4)");

            TcpListener? listenerIPv6 = null;
            try {
                listenerIPv6 = new TcpListener(IPAddress.IPv6Loopback, port);
                listenerIPv6.Server.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.IPv6Only, true);
                listenerIPv6.Start();
                Console.WriteLine($"[IRCd-lite] Listening on ::1:{port} (IPv6)");
            } catch (Exception) {
                Console.WriteLine("[IRCd-lite] IPv6 not available.");
            }

            Console.WriteLine("[IRCd-lite] Waiting for connections...");

            var acceptTasks = new List<Task<TcpClient>>();
            acceptTasks.Add(listenerIPv4.AcceptTcpClientAsync());
            if (listenerIPv6 != null) acceptTasks.Add(listenerIPv6.AcceptTcpClientAsync());

            while (!_cts.IsCancellationRequested)
            {
                var clientTask = Task.WhenAny(acceptTasks);
                var completedTask = await Task.WhenAny(clientTask, Task.Delay(-1, _cts.Token));
                if (_cts.IsCancellationRequested)
                    break;
                
                var finishedAcceptTask = clientTask.Result;
                var client = finishedAcceptTask.Result;
                Console.WriteLine("[IRCd-lite] Client connected.");

                // Replace the completed task with a new one for the next client
                if (finishedAcceptTask == acceptTasks[0])
                    acceptTasks[0] = listenerIPv4.AcceptTcpClientAsync();
                else if (acceptTasks.Count > 1)
                    acceptTasks[1] = listenerIPv6!.AcceptTcpClientAsync();

                _stream = client.GetStream();
                byte[] buffer = new byte[BufferSize];
                int cursor = 0;

                while (!_cts.IsCancellationRequested)
                {
                    var readTask = _stream.ReadAsync(buffer, cursor, BufferSize - cursor, _cts.Token);
                    var finishedTask = await Task.WhenAny(readTask, Task.Delay(-1, _cts.Token));
                    if (_cts.IsCancellationRequested)
                        break;
                    int read = await readTask;
                    if (read == 0) break; // Client disconnected
                    cursor += read;
                    bool foundLine = false;

                    // Search for \r\n in buffer
                    for (int i = 1; i < cursor; i++)
                    {
                        if (buffer[i - 1] == (byte)'\r' && buffer[i] == (byte)'\n')
                        {
                            // Found IRC command
                            string rawLine = Encoding.Latin1.GetString(buffer, 0, i - 1);
                            Console.WriteLine($"<-- {rawLine}");

                            var match = System.Text.RegularExpressions.Regex.Match(rawLine, @"^ *(?::(?<prefix>[^ ]+)\s+)?(?<command>[^ ]+)(?: +(?<param>(?!:)[^ ]+))*(?: +:(?<trailing>.*)| *)$");
                            if (match.Success)
                            {
                                string? prefix = match.Groups["prefix"].Success ? match.Groups["prefix"].Value : null;
                                string command = match.Groups["command"].Value;
                                
                                var paramsList = new List<string>();
                                
                                foreach (System.Text.RegularExpressions.Capture capture in match.Groups["param"].Captures)
                                {
                                    paramsList.Add(capture.Value);
                                }
                                
                                if (match.Groups["trailing"].Success)
                                {
                                    paramsList.Add(match.Groups["trailing"].Value);
                                }
                                
                                HandleIrcCommand(command.ToUpper(), paramsList.ToArray(), prefix);
                            }

                            // Reset cursor for next command
                            int remaining = cursor - (i + 1);
                            if (remaining > 0)
                                Array.Copy(buffer, i + 1, buffer, 0, remaining);
                            cursor = remaining;
                            foundLine = true;
                            break;
                        }
                    }

                    if (!foundLine && cursor >= BufferSize)
                    {
                        Console.WriteLine("[IRCd-lite] Buffer full without CRLF. Resetting cursor.");
                        cursor = 0;
                    }
                }
                
                Console.WriteLine("[IRCd-lite] Client disconnected.");
                _stream?.Dispose();
                client.Dispose();
                _stream = null;
                _session?.Dispose();
                _session = null;
            }

            listenerIPv4.Stop();
            listenerIPv6?.Stop();
            Console.WriteLine("[IRCd-lite] Server shut down.");
        }

        private Vortex.Sspi.SspiSession? _session;

        private static string UnescapeIrcxAuth(string input)
        {
            var sb = new StringBuilder(input.Length);
            for (int i = 0; i < input.Length; i++)
            {
                if (input[i] == '\\' && i + 1 < input.Length)
                {
                    i++;
                    switch (input[i])
                    {
                        case '0': sb.Append('\0'); break;
                        case 'b': sb.Append(' '); break;
                        case 'c': sb.Append(','); break;
                        case '\\': sb.Append('\\'); break;
                        case 'r': sb.Append('\r'); break;
                        case 'n': sb.Append('\n'); break;
                        case 't': sb.Append('\t'); break;
                        default:
                            sb.Append('\\');
                            sb.Append(input[i]);
                            break;
                    }
                }
                else
                {
                    sb.Append(input[i]);
                }
            }
            return sb.ToString();
        }

        private static string EscapeIrcxAuth(string input)
        {
            var sb = new StringBuilder(input.Length + 16);
            foreach (char c in input)
            {
                switch (c)
                {
                    case '\0': sb.Append("\\0"); break;
                    case ' ': sb.Append("\\b"); break;
                    case ',': sb.Append("\\c"); break;
                    case '\\': sb.Append("\\\\"); break;
                    case '\r': sb.Append("\\r"); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\t': sb.Append("\\t"); break;
                    default: sb.Append(c); break;
                }
            }
            return sb.ToString();
        }

        private void HandleIrcCommand(string command, string[] args, string? prefix)
        {
            switch (command.ToUpper())
            {
                case "AUTH":
                    if (args.Length >= 3 && args[0].Equals("NTLM", StringComparison.OrdinalIgnoreCase))
                    {
                        string phase = args[1].ToUpper(); // I or S
                        string tokenStr = UnescapeIrcxAuth(args[2]);
                        byte[] inputToken = Encoding.Latin1.GetBytes(tokenStr);
                        
                        if (_session == null) _session = new Vortex.Sspi.SspiSession();

                        try
                        {
                            byte[]? challenge = _session.ParseToken(inputToken, out int status);
                            if (status == 0x00090312) // SEC_I_CONTINUE_NEEDED
                            {
                                if (challenge != null)
                                {
                                    string challengeStr = Encoding.Latin1.GetString(challenge);
                                    string escapedChallenge = EscapeIrcxAuth(challengeStr);
                                    SendResponse($"AUTH NTLM S :{escapedChallenge}");
                                }
                            }
                            else if (status == 0) // SEC_E_OK
                            {
                                var id = _session.GetIdentity();
                                
                                // This is where we should get the username (and optionally domain) from _session and verify it against our user database.
                                // For this test, we will just verify against a hardcoded hash of the expected NTLMv2 response for the test credentials (password "password").
                                var hash = new byte[] { 0x88, 0x46, 0xF7, 0xEA, 0xEE, 0x8F, 0xB1, 0x17, 0xAD, 0x06, 0xBD, 0xD8, 0x30, 0xB7, 0x58, 0x6C };

                                var result = _session.Verify(hash);
                                if (result == 0) // SEC_E_OK
                                {
                                    Console.WriteLine($"[IRCd-lite] SSPI Login Success! User: {id.Username}, Domain: {id.Domain}");
                                    SendResponse($"AUTH NTLM * {id.Username}@{id.Domain} 0");   
                                }
                                else
                                {
                                    Console.WriteLine($"[IRCd-lite] SSPI Login Failed: Invalid credentials");
                                    SendResponse($":Vortex.Sspi.Test 910 {_nickname} :Login failed (invalid credentials)");
                                }
                                
                                // Dispose session since authentication completed
                                _session.Dispose();
                                _session = null;
                            }
                            else
                            {
                                Console.WriteLine($"[IRCd-lite] SSPI Error: 0x{status:X8}");
                                SendResponse($":Vortex.Sspi.Test 910 {_nickname} :Login failed (0x{status:X8})");
                                _session.Dispose();
                                _session = null;
                            }
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"[IRCd-lite] NTLM parse exception: {ex.Message}");
                            SendResponse($":Vortex.Sspi.Test 910 {_nickname} :Internal authentication error");
                            _session?.Dispose();
                            _session = null;
                        }
                    }
                    else
                    {
                        Console.WriteLine($"[IRCd-lite] Unhandled AUTH format");
                    }
                    break;
                case "IRCVERS":
                    SendResponse($":Vortex.Sspi.Test 800 {_nickname} :1 0 GateKeeper,NTLM 512 *");
                    break;
                default:
                    SendResponse($":Vortex.Sspi.Test NOTICE {_nickname} :This is an AUTH only service.");
                    Console.WriteLine($"[IRCd-lite] Unhandled command: {command}");
                    break;
            }
        }

        private void SendResponse(string message)
        {
            if (_stream == null) return;
            try
            {
                Console.WriteLine($"--> {message}");
                byte[] data = Encoding.Latin1.GetBytes(message + "\r\n");
                _stream.Write(data, 0, data.Length);
            }
            catch (Exception ex) { Console.WriteLine($"[IRCd-lite] Send Error: {ex.Message}"); }
        }
    }
}
